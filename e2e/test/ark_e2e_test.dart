import 'dart:io';
import 'dart:convert';
import 'dart:async';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:app_core/ark_wallet.dart';
import 'package:app_core/client.dart';
import 'package:app_core/passkey/seed_source.dart';
import 'package:app_core/passkey/session_token_source.dart';
import 'package:cryptography/cryptography.dart';
import 'package:e2e/boarding_poll.dart';
import 'package:e2e/mock_fcm_server.dart';
import 'package:e2e/regtest_helper.dart';
import 'package:hive/hive.dart';
import 'package:http/http.dart' as http;

/// 32-byte seed for the cosigner's Ed25519 session-token keypair (env `WEBAUTH_TOKEN_SECRET`).
/// The gated test mints Bearer tokens with the same seed so `SessionAuthority::verify` accepts them.
final List<int> webauthTokenSecret = List<int>.generate(32, (i) => i + 1);
final String webauthTokenSecretHex =
    webauthTokenSecret.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Mint a session token in the cosigner's compact-EdDSA-JWT shape: `b64u(header).b64u(payload).
/// b64u(Ed25519_sig over "header.payload")`. The cosigner verifies the signature over the received
/// bytes (it doesn't re-serialize), so no JSON canonicalization is required — only a matching key.
Future<String> mintSessionToken(String subHex, List<int> seed) async {
  final algo = Ed25519();
  final keyPair = await algo.newKeyPairFromSeed(seed);
  String b64u(List<int> b) => base64Url.encode(b).replaceAll('=', '');
  final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  final header = b64u(utf8.encode('{"alg":"EdDSA","typ":"JWT"}'));
  final payload = b64u(utf8.encode(jsonEncode({
    'sub': subHex,
    'exp': now + 900,
    'iat': now,
    'jti': 'e2e-gated',
  })));
  final signingInput = '$header.$payload';
  final sig = await algo.sign(utf8.encode(signingInput), keyPair: keyPair);
  return '$signingInput.${b64u(sig.bytes)}';
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// Helper to call the arkd admin REST API.
class ArkdAdmin {
  final String adminUrl;
  final String publicUrl;

  ArkdAdmin({
    this.adminUrl = 'http://127.0.0.1:7071',
    this.publicUrl = 'http://127.0.0.1:7070',
  });

  Future<Map<String, dynamic>> getInfo() async {
    final resp = await http.get(Uri.parse('$publicUrl/v1/info'));
    if (resp.statusCode != 200)
      throw Exception('arkd info failed: ${resp.body}');
    return jsonDecode(resp.body) as Map<String, dynamic>;
  }

  Future<bool> isReady() async {
    try {
      await getInfo();
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<void> initWallet() async {
    // Get seed
    final seedResp =
        await http.get(Uri.parse('$adminUrl/v1/admin/wallet/seed'));
    if (seedResp.statusCode != 200)
      throw Exception('seed failed: ${seedResp.body}');
    final seed = jsonDecode(seedResp.body)['seed'] as String;

    // Create wallet
    await http.post(
      Uri.parse('$adminUrl/v1/admin/wallet/create'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'seed': seed, 'password': 'password'}),
    );

    await Future.delayed(Duration(seconds: 1));

    // Unlock wallet
    await http.post(
      Uri.parse('$adminUrl/v1/admin/wallet/unlock'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'password': 'password'}),
    );

    await Future.delayed(Duration(seconds: 1));
  }

  Future<String> getWalletAddress() async {
    final resp = await http.get(Uri.parse('$adminUrl/v1/admin/wallet/address'));
    if (resp.statusCode != 200)
      throw Exception('wallet address failed: ${resp.body}');
    return jsonDecode(resp.body)['address'] as String;
  }
}

/// Spawn the cosigner binary against the shared regtest fixtures.
/// Same `serverTempDir` across calls reuses the same sled `data_dir`, so
/// killing + restarting exercises persistence rehydration paths.
/// `extraEnv` lets the caller layer additional env vars on top (used by
/// setUpAll to point FCM at the local `MockFcmServer`). Returns the spawned
/// Process; throws if it doesn't report "listening on" within 30s or exits
/// before becoming ready.
Future<Process> startCosignerRuntime(
  int port,
  Directory dataDir, {
  Map<String, String> extraEnv = const {},
}) async {
  final serverReady = Completer<void>();
  final serverFailed = Completer<void>();
  final env = {
    'BITCOIN_RPC_USER': 'admin1',
    'BITCOIN_RPC_PASSWORD': '123',
    'ASP_URL': 'http://127.0.0.1:7070',
    // Boarding watcher: poll the local electrs esplora; sweep fast for tests.
    'ESPLORA_URL': 'http://127.0.0.1:30000',
    'BOARDING_WATCH_INTERVAL_SECS': '3',
    // Asserted by the GetServerInfo test — set explicitly so the
    // expectation isn't dependent on the cosigner default.
    'BITCOIN_NETWORK': 'regtest',
    // Force the auto-settle threshold to be "always crossed" for any
    // VTXO_TREE_EXPIRY. The tick task fires when
    // `now > expires_at - safety_margin`; the margin must therefore exceed
    // the VTXO's remaining lifetime. docker-compose sets ARKD_VTXO_TREE_EXPIRY
    // to ~4.3h, so a margin this large drives `expires_at - margin` below 0
    // (clamped to 0) -> always crossed -> the next 60-second tick after the
    // intent is stored drives the batch.
    'AUTO_SETTLE_SAFETY_MARGIN_SECS': '9999999999',
    'HOME': dataDir.path,
    // Per-run SQLite KV file. Same dir across restarts, so state survives a runtime
    // bounce the way the shared Redis instance used to.
    'SQLITE_PATH': '${dataDir.path}/cosigner.db',
    ...extraEnv,
  };
  final proc = await Process.start(
    '../cosigner/target/release/cosigner',
    [
      '--port',
      port.toString(),
    ],
    mode: ProcessStartMode.normal,
    environment: env,
  );
  final stdoutBuffer = StringBuffer();
  final stderrBuffer = StringBuffer();
  proc.stdout.transform(utf8.decoder).listen((data) {
    stdoutBuffer.write(data);
    print('[Server]: $data');
    if (!serverReady.isCompleted &&
        stdoutBuffer.toString().contains('MPC Wallet Server listening on')) {
      serverReady.complete();
    }
  }, onDone: () {
    if (!serverReady.isCompleted && !serverFailed.isCompleted) {
      serverFailed.complete();
    }
  });
  proc.stderr.transform(utf8.decoder).listen((data) {
    stderrBuffer.write(data);
    print('[Server]: $data');
    if (!serverReady.isCompleted &&
        stderrBuffer.toString().contains('MPC Wallet Server listening on')) {
      serverReady.complete();
    }
  }, onDone: () {
    if (!serverReady.isCompleted && !serverFailed.isCompleted) {
      serverFailed.complete();
    }
  });

  try {
    await Future.any([
      serverReady.future,
      serverFailed.future.then((_) {
        throw Exception('MPC Server failed to start');
      }),
    ]).timeout(Duration(seconds: 30), onTimeout: () {
      throw Exception('MPC Server did not become ready in time');
    });
  } catch (e) {
    proc.kill();
    rethrow;
  }
  return proc;
}

void main() {
  Process? serverProcess;
  late RegtestHelper btc;
  late ArkdAdmin arkd;
  late Directory tempDir;
  late Directory serverTempDir;
  late int serverPort;
  late MockFcmServer mockFcm;
  late String fcmTestProjectId;
  late Map<String, String> cosignerExtraEnv;

  // Real 2-of-2 {wallet, cosigner}: no signer. Distinct storageId per wallet.
  MpcClient createClient({String? storageId}) {
    return MpcClient.rest('http://127.0.0.1:$serverPort', storageId: storageId);
  }

  setUpAll(() async {
    print('--- Ark E2E Setup ---');

    // 0. Hive Init
    tempDir = await Directory.systemTemp.createTemp('mpc_ark_e2e_');
    Hive.init(tempDir.path);

    // 1. Docker: bitcoind + electrs + arkd should already be running
    // (via `make arkd-up && make bitcoin-init && make arkd-init`)
    print('Checking Docker services...');

    btc = RegtestHelper();
    try {
      try {
        await btc.createWallet("default");
      } catch (e) {
        if (!e.toString().contains("already loaded")) rethrow;
      }
      btc = RegtestHelper(rpcUrl: "http://127.0.0.1:18443/wallet/default");
      await btc.getNewAddress();
      print("  Bitcoind: OK");
    } catch (e) {
      throw Exception(
          "Bitcoind not reachable. Run: make arkd-up && make bitcoin-init\nError: $e");
    }

    // 2. Check arkd
    arkd = ArkdAdmin();
    print('Checking arkd...');
    bool arkdReady = false;
    for (int i = 0; i < 10; i++) {
      if (await arkd.isReady()) {
        arkdReady = true;
        break;
      }
      print('  Waiting for arkd... (${i + 1}/10)');
      await Future.delayed(Duration(seconds: 3));
    }

    if (!arkdReady) {
      // Try to initialize arkd wallet
      print('  arkd not ready, attempting wallet init...');
      try {
        await arkd.initWallet();
        await Future.delayed(Duration(seconds: 2));
        final info = await arkd.getInfo();
        print('  arkd initialized: $info');
      } catch (e) {
        throw Exception(
            "arkd not reachable. Run: make arkd-up && make arkd-init\nError: $e");
      }
    }

    final info = await arkd.getInfo();
    print(
        '  arkd info: pubkey=${(info['pubkey'] as String?)?.substring(0, 16)}...');

    // 3. Fund ASP wallet if needed
    try {
      final aspAddr = await arkd.getWalletAddress();
      print('  Funding ASP wallet at $aspAddr');
      final minerAddr = await btc.getNewAddress();
      // Ensure enough blocks for spending
      await btc.generateToAddress(101, minerAddr);
      await btc.sendToAddress(aspAddr, 10.0);
      await btc.generateToAddress(1, minerAddr);
      print('  ASP funded with 10 BTC');
      await Future.delayed(Duration(seconds: 5));
    } catch (e) {
      print('  Warning: Could not fund ASP: $e');
    }

    // 4. Mock Firebase Cloud Messaging
    //
    // Stand up a local HTTP server that impersonates both endpoints the
    // cosigner hits during a push: the OAuth2 token endpoint and
    // the `messages:send` endpoint. The cosigner signs an OAuth JWT with
    // the fixture private key — the mock doesn't verify the signature,
    // since real Firebase isn't in the loop.
    //
    // Pushes only fire when a user has registered a device token AND a
    // new VTXO arrives. Existing tests don't register tokens, so the
    // mock sits idle for them. The dedicated FCM test below is the only
    // consumer.
    print('Starting MockFcmServer...');
    mockFcm = MockFcmServer();
    await mockFcm.start();
    print('  MockFcmServer listening on ${mockFcm.baseUrl}');

    fcmTestProjectId = 'mpc-wallet-e2e-test';
    final keyPemPath = '../e2e/fixtures/fcm_test_key.pem';
    final keyPem = await File(keyPemPath).readAsString();
    final fcmServiceAccountJson = jsonEncode({
      'type': 'service_account',
      'project_id': fcmTestProjectId,
      'private_key_id': 'e2e-mock',
      'private_key': keyPem,
      'client_email': 'fcm-e2e@$fcmTestProjectId.iam.gserviceaccount.com',
      // Both `aud` claim in the JWT and the POST destination are derived
      // from this — see fcm_client.rs::mint_token.
      'token_uri': mockFcm.tokenUri,
    });
    cosignerExtraEnv = {
      'FCM_SERVICE_ACCOUNT_JSON': fcmServiceAccountJson,
      'FCM_BASE_URL': mockFcm.baseUrl,
      // Enable session-token auth so the gated-wallet test can present a minted
      // Bearer token. Harmless for the other tests: verify_auth falls back to
      // Schnorr when no token is presented.
      'WEBAUTH_TOKEN_SECRET': webauthTokenSecretHex,
    };

    // 5. Start MPC Server with ASP_URL
    print('Starting MPC Server with ASP...');
    final portSocket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    serverPort = portSocket.port;
    await portSocket.close();
    serverTempDir = await Directory.systemTemp.createTemp('mpc_ark_server_');
    serverProcess = await startCosignerRuntime(
      serverPort,
      serverTempDir,
      extraEnv: cosignerExtraEnv,
    );
    print('--- Ark E2E Setup Complete ---');
  });

  tearDownAll(() async {
    serverProcess?.kill();
    try {
      await mockFcm.stop();
    } catch (_) {}
    try {
      await serverTempDir.delete(recursive: true);
    } catch (_) {}
    try {
      await tempDir.delete(recursive: true);
    } catch (_) {}
  });

  // Server is the source of truth for `bitcoin_network`; the client fetches
  // it via this RPC at the moment a wallet is constructed (see
  // `MpcService.restoreSession` / `doDkg`). Verifies the wire
  // shape: unauthenticated, no DKG required, returns whatever the runtime
  // was started with.
  test('GetServerInfo returns the configured bitcoin_network', () async {
    final client = createClient();

    final info = await client.getServerInfo();
    print('   bitcoin_network=${info.bitcoinNetwork}');
    expect(info.bitcoinNetwork, equals('regtest'),
        reason:
            'Server should echo back BITCOIN_NETWORK env var (set to "regtest" '
            'in the test harness). If this fails, either the env wiring or the '
            'GetServerInfo handler is broken.');
  }, timeout: Timeout(Duration(minutes: 1)));

  test('Ark: DKG + GetArkInfo + GetArkAddress + GetBoardingAddress', () async {
    // 1. DKG Setup
    print('1. DKG Setup');
    final client = createClient();

    await client.doDkg();
    print('   DKG Complete. userId=${client.userId?.substring(0, 16)}...');

    // 2. GetArkInfo
    print('2. GetArkInfo');
    final arkInfo = await client.getArkInfo();
    print('   network=${arkInfo.network}');
    print('   signerPubkey=${arkInfo.signerPubkey.substring(0, 16)}...');
    print('   sessionDuration=${arkInfo.sessionDuration}');
    print('   unilateralExitDelay=${arkInfo.unilateralExitDelay}');
    print('   boardingExitDelay=${arkInfo.boardingExitDelay}');

    expect(arkInfo.signerPubkey, isNotEmpty);
    expect(arkInfo.network, isNotEmpty);
    expect(arkInfo.unilateralExitDelay, greaterThan(0));

    // 3. GetArkAddress
    print('3. GetArkAddress');
    final arkAddress = await client.getArkAddress();
    print('   Ark Address: $arkAddress');
    expect(arkAddress, isNotEmpty);
    // Ark addresses start with "ark1" on mainnet or "tark1" on testnet/regtest
    expect(
      arkAddress.startsWith('ark1') || arkAddress.startsWith('tark1'),
      isTrue,
      reason: "Ark address should start with ark1 or tark1, got: $arkAddress",
    );

    // 4. GetBoardingAddress
    print('4. GetBoardingAddress');
    final boardingAddress = await client.getBoardingAddress();
    print('   Boarding Address: $boardingAddress');
    expect(boardingAddress, isNotEmpty);
    // Boarding address is a P2TR address (bcrt1p... on regtest, tb1p... on signet/testnet)
    expect(
        boardingAddress.startsWith('bcrt1p') ||
            boardingAddress.startsWith('tb1p'),
        isTrue,
        reason: "Boarding address should be P2TR, got: $boardingAddress");

    // 5. ListVtxos (should be empty for new wallet)
    print('5. ListVtxos');
    final vtxosResp = await client.listVtxos();
    print(
        '   VTXOs: ${vtxosResp.vtxos.length}, balance: ${vtxosResp.totalBalance}');
    expect(vtxosResp.vtxos, isEmpty);
    expect(vtxosResp.totalBalance.toInt(), equals(0));

    // 6. Verify addresses are deterministic
    print('6. Verifying address determinism');
    final arkAddress2 = await client.getArkAddress();
    final boardingAddress2 = await client.getBoardingAddress();
    expect(arkAddress2, equals(arkAddress));
    expect(boardingAddress2, equals(boardingAddress));
    print('   Addresses are deterministic');

    print('Ark E2E Test Complete!');
  }, timeout: Timeout(Duration(minutes: 5)));

  // Balance and VTXO assertions below caught two production bugs:
  // 1. get_boarding_address() not registering scripts → VTXOs invisible after settle
  // 2. exit_delay stored as 0 → VTXO reconstruction used wrong taproot tree → VTXO_NOT_FOUND on send
  // Without these, the test only verified txid non-empty, which passed even with broken VTXOs.
  test('Ark: Full flow - fund boarding, settle, send Alice→Bob', () async {
    // 1. Alice DKG
    print('1. Alice DKG');
    final alice = createClient(storageId: "alice");
    await alice.doDkg();
    print('   Alice userId=${alice.userId?.substring(0, 16)}...');

    // 2. Get Alice's boarding address
    print('2. Get boarding address');
    final boardingAddress = await alice.getBoardingAddress();
    print('   Boarding: $boardingAddress');

    // 3. Fund boarding address with 0.01 BTC (1,000,000 sats)
    print('3. Fund boarding address');
    final minerAddr = await btc.getNewAddress();
    final fundTxid = await btc.sendToAddress(boardingAddress, 0.01);
    print('   Fund txid: $fundTxid');
    // Confirm the funding tx
    await btc.generateToAddress(1, minerAddr);
    print('   Funding confirmed');

    // Wait for electrum/nbxplorer to index the new block
    await Future.delayed(Duration(seconds: 5));

    // Verify UTXO exists at boarding address
    final utxos = await btc.scanUtxos(boardingAddress);
    print('   UTXOs at boarding address: ${utxos.length}');
    expect(utxos, isNotEmpty, reason: 'Should have UTXO at boarding address');
    print('   UTXO amount: ${utxos[0]['amount']} BTC');

    // 4. Settle (board on-chain UTXO into Ark VTXO)
    print('4. Settle (board)');
    // We need to mine blocks to trigger ASP batches (ARKD_SCHEDULER_TYPE=block).
    bool settling = true;
    int blocksMined = 0;
    final miningTimer = Timer.periodic(Duration(seconds: 3), (timer) async {
      if (!settling) {
        timer.cancel();
        return;
      }
      try {
        final addr = await btc.getNewAddress();
        await btc.generateToAddress(1, addr);
        blocksMined++;
        print('   Mined block #$blocksMined for batch trigger');
      } catch (e) {
        print('   Mining error (non-fatal): $e');
      }
    });

    final boardingUtxos = await pollBoardingUtxos(boardingAddress, 1);
    expect(boardingUtxos, isNotEmpty);
    try {
      final commitmentTxid = await settleBoarding(alice, boardingUtxos);
      settling = false;
      miningTimer.cancel();
      print('   Settled! commitment_txid=$commitmentTxid');
      expect(commitmentTxid, isNotEmpty);
    } catch (e) {
      settling = false;
      miningTimer.cancel();
      rethrow;
    }

    // 5. Verify Alice has a VTXO with correct balance and exit_delay
    print('5. List VTXOs');
    final vtxosResp = await alice.listVtxos();
    final aliceBalanceAfterSettle = vtxosResp.totalBalance.toInt();
    print(
        '   VTXOs: ${vtxosResp.vtxos.length}, balance: $aliceBalanceAfterSettle');
    expect(vtxosResp.vtxos.length, equals(1),
        reason: 'Alice should have exactly 1 VTXO after settle');
    expect(aliceBalanceAfterSettle, greaterThan(900000),
        reason: 'Alice should have ~1M sats (0.01 BTC minus fees)');
    expect(vtxosResp.vtxos.first.exitDelay, greaterThan(0),
        reason:
            'exit_delay must not be 0 — would produce wrong taproot tree on spend');
    // expires_at lands asynchronously: the boarding settle handler pushes
    // the VTXO without it (the ASP doesn't return it from the settle call),
    // and the vtxo_stream subscription backfills it when the matching
    // event arrives. Poll for it.
    int expiresAt = vtxosResp.vtxos.first.expiresAt.toInt();
    for (int i = 0; i < 20 && expiresAt == 0; i++) {
      await Future.delayed(Duration(seconds: 1));
      final r = await alice.listVtxos();
      if (r.vtxos.isNotEmpty) {
        expiresAt = r.vtxos.first.expiresAt.toInt();
      }
    }
    expect(expiresAt, greaterThan(0),
        reason:
            'expires_at must be populated end-to-end so auto-settle can decide when to fire');
    final aliceScript = vtxosResp.vtxos.first.script;
    expect(aliceScript, isNotEmpty, reason: 'VTXO script must be populated');
    print('   Alice script: ${aliceScript.substring(0, 16)}...');

    // 5b. Store-only delegate: signed intent stored on the cosigner without
    // joining a batch. listVtxos should report the delegate as active and
    // VTXOs unchanged.
    print('5b. settleDelegate(storeOnly: true)');
    final delegatedTxid = await alice.settleDelegate(storeOnly: true);
    expect(delegatedTxid, isEmpty,
        reason: 'DELEGATED status returns no commitment_txid');
    final afterDelegate = await alice.listVtxos();
    expect(afterDelegate.hasActiveDelegate, isTrue,
        reason: 'cosigner should report delegate as active');
    expect(afterDelegate.vtxos.length, equals(1),
        reason: 'store-only must not consume VTXOs');
    expect(afterDelegate.totalBalance.toInt(), equals(aliceBalanceAfterSettle),
        reason: 'store-only must not change balance');

    // 6. Bob DKG
    print('6. Bob DKG');
    final bob = createClient(storageId: "bob");
    await bob.doDkg();
    print('   Bob userId=${bob.userId?.substring(0, 16)}...');

    // 7. Get Bob's Ark address
    print('7. Bob Ark address');
    final bobArkAddress = await bob.getArkAddress();
    print('   Bob Ark: $bobArkAddress');

    // 8. Alice sends VTXO to Bob via MpcArkWallet
    print('8. Alice sends to Bob');
    final sendAmount = 100000; // 100k sats
    final aliceArkWallet = MpcArkWallet(alice);
    final unsigned = await aliceArkWallet.createTransaction(
      destination: bobArkAddress,
      amountSats: sendAmount,
    );
    print('   Built tx: ${unsigned.sighashes.length} sighashes');
    final signed = await aliceArkWallet.signTransaction(unsigned);
    print('   Signed tx');
    final arkTxid = await aliceArkWallet.submit(signed);
    print('   Send ark_txid: $arkTxid');
    expect(arkTxid, isNotEmpty);

    // 8b. Verify balances after first send.
    // Wait for Bob's indexer subscription to deliver the received VTXO.
    final aliceAfterSend1 = await alice.listVtxos();
    print(
        '   Alice: ${aliceAfterSend1.vtxos.length} VTXOs, balance=${aliceAfterSend1.totalBalance}');
    expect(
        aliceAfterSend1.totalBalance.toInt(), lessThan(aliceBalanceAfterSettle),
        reason: 'Alice balance should decrease after send');
    // The off-chain send consumed VTXOs covered by Alice's stored delegate,
    // so the cosigner must have invalidated it. Without invalidation the
    // auto-settle tick task would later submit signatures referencing
    // already-spent VTXOs.
    expect(aliceAfterSend1.hasActiveDelegate, isFalse,
        reason:
            'sending should invalidate any stored delegate covering the spent VTXOs');
    // Verify all Alice VTXOs have a non-empty script.
    // Note: boarding VTXOs use boarding_exit_delay, change VTXOs use
    // unilateral_exit_delay — so scripts may differ. Both must be non-empty.
    for (final vtxo in aliceAfterSend1.vtxos) {
      expect(vtxo.script, isNotEmpty,
          reason: 'Every VTXO must have a non-empty scriptPubKey');
    }

    // Poll Bob's balance — subscription event may take a moment to arrive.
    int bobBalance1 = 0;
    for (int i = 0; i < 10; i++) {
      final resp = await bob.listVtxos();
      bobBalance1 = resp.totalBalance.toInt();
      if (bobBalance1 > 0) break;
      print('   Waiting for Bob VTXO... (${i + 1}/10)');
      await Future.delayed(Duration(seconds: 1));
    }
    print('   Bob: balance=$bobBalance1');
    expect(bobBalance1, equals(sendAmount),
        reason: 'Bob should have received exactly $sendAmount sats');

    // PORT NOTE: the receive-history assertions that stood here are gone. They guarded
    // `vtxo_stream::apply_stream_update` against dropping "receive" rows — a stream the cosigner
    // no longer runs. It is called rather than running, so it never observes a receive and cannot
    // record one; `ListArkTransactions` was removed with the log. Balances above still prove the
    // receive landed. Rebuilding history from the ASP indexer is its own piece of work.

    // 9. Alice sends again to Bob (uses change VTXO from first send)
    print('9. Alice sends to Bob again');
    final sendAmount2 = 50000; // 50k sats
    final unsigned2 = await aliceArkWallet.createTransaction(
      destination: bobArkAddress,
      amountSats: sendAmount2,
    );
    print('   Built tx: ${unsigned2.sighashes.length} sighashes');
    final signed2 = await aliceArkWallet.signTransaction(unsigned2);
    print('   Signed tx');
    final arkTxid2 = await aliceArkWallet.submit(signed2);
    print('   Send ark_txid: $arkTxid2');
    expect(arkTxid2, isNotEmpty);

    // 9b. Verify balances after second send
    final aliceAfterSend2 = await alice.listVtxos();
    print(
        '   Alice: ${aliceAfterSend2.vtxos.length} VTXOs, balance=${aliceAfterSend2.totalBalance}');
    expect(aliceAfterSend2.totalBalance.toInt(),
        lessThan(aliceAfterSend1.totalBalance.toInt()),
        reason: 'Alice balance should decrease after second send');
    int bobBalance2 = 0;
    for (int i = 0; i < 10; i++) {
      final resp = await bob.listVtxos();
      bobBalance2 = resp.totalBalance.toInt();
      if (bobBalance2 >= sendAmount + sendAmount2) break;
      await Future.delayed(Duration(seconds: 1));
    }
    print('   Bob: balance=$bobBalance2');
    expect(bobBalance2, equals(sendAmount + sendAmount2),
        reason: 'Bob should have ${sendAmount + sendAmount2} sats total');


    // 10. Third send (20k sats) — exercises spending down the change VTXO
    print('10. Alice sends 20k to Bob');
    final sendAmount3 = 20000;
    final unsigned4 = await aliceArkWallet.createTransaction(
      destination: bobArkAddress,
      amountSats: sendAmount3,
    );
    final signed4 = await aliceArkWallet.signTransaction(unsigned4);
    final arkTxid4 = await aliceArkWallet.submit(signed4);
    print('   Send ark_txid: $arkTxid4');
    expect(arkTxid4, isNotEmpty);

    // 10b. Verify final balances
    final aliceFinal = await alice.listVtxos();
    final totalSent = sendAmount + sendAmount2 + sendAmount3;
    print(
        '   Alice final: ${aliceFinal.vtxos.length} VTXOs, balance=${aliceFinal.totalBalance}');
    expect(aliceFinal.totalBalance.toInt(),
        equals(aliceBalanceAfterSettle - totalSent),
        reason:
            'Alice should have original balance minus $totalSent sats sent');
    int bobFinalBalance = 0;
    for (int i = 0; i < 10; i++) {
      final resp = await bob.listVtxos();
      bobFinalBalance = resp.totalBalance.toInt();
      if (bobFinalBalance >= totalSent) break;
      await Future.delayed(Duration(seconds: 1));
    }
    print('   Bob final: balance=$bobFinalBalance');
    expect(bobFinalBalance, equals(totalSent),
        reason: 'Bob should have received $totalSent sats total');

    // ---------------------------------------------------------------------
    // 11. Request-to-pay, end to end: Bob bills Alice and Alice pays it.
    //
    // Runs here rather than standalone because it needs a FUNDED payer, which
    // this test already has. Covers the half a mocked test cannot: the payment
    // actually settles and the cosigner marks the request fulfilled.
    //
    // Absorbed the former standalone `payment_request_e2e_test.dart`, which was
    // wired into neither the Makefile nor CI and so never ran. Its unique
    // coverage — group-key canonicalisation of the allowlist and of the intent's
    // requester, the memo, the decline path, and the post-revoke gate — is folded
    // in below; the rest it asserted was already covered here.
    // ---------------------------------------------------------------------
    print('11. Request-to-pay: Bob bills Alice, Alice pays');

    // These endpoints authenticate against the id in the URL, so both sides need
    // a token bound to the id they address the API by.
    alice.setSessionTokenSource(
        StaticSessionToken(await mintSessionToken(alice.userId!, webauthTokenSecret)));
    bob.setSessionTokenSource(
        StaticSessionToken(await mintSessionToken(bob.userId!, webauthTokenSecret)));

    // A stranger cannot bill Alice: the allowlist is the only authorization, since
    // auth proves key possession but does not bind a signer to the actor addressed.
    await expectLater(
      bob.requestPayment(alice.userId!, 1000, memo: 'not yet allowed'),
      throwsA(isA<Exception>()),
      reason: 'a non-contact must not be able to bill Alice',
    );
    print('   Un-allowlisted request refused');

    // Bob is added by the id he addresses the API with, but the cosigner canonicalises
    // it to his GROUP key before storing. Pinning that keeps the allowlist comparable
    // no matter which of a wallet's ids a caller happens to use.
    final bobGroupKey = bob.groupKeyHex!;
    await alice.contactAdd(bob.userId!, 'Bob');
    final aliceContacts = await alice.contactList();
    expect(aliceContacts, hasLength(1));
    expect(aliceContacts.map((c) => _hex(c.verifyingKey)), contains(bobGroupKey),
        reason: 'the contact must be stored as the group key, not the id passed in');
    print('   Alice allowlisted Bob (stored canonically as his group key)');

    final requestAmount = 15000;
    final intent =
        await bob.requestPayment(alice.userId!, requestAmount, memo: 'invoice 1');
    expect(intent.status, 'pending');
    expect(intent.amountSats.toInt(), requestAmount);
    expect(intent.memo, 'invoice 1');
    expect(_hex(intent.fromVerifyingKey), bobGroupKey,
        reason: 'the requester must be recorded by group key, not by share key');
    // The payee address is derived by Alice's cosigner from Bob's group key — never
    // supplied by Bob. A wrongly-derived one would send funds Bob cannot spend.
    expect(intent.toArkAddress, bobArkAddress,
        reason: "payee address must be Bob's own Ark address");
    print('   Request created, payee address == Bob\'s own address');

    final inbox = await alice.paymentRequests();
    expect(inbox.map((i) => i.id), contains(intent.id));

    // Pay it: amount + payee come from the STORED intent, never from the caller.
    final aliceBeforePay = (await alice.listVtxos()).totalBalance.toInt();
    final payWallet = MpcArkWallet(alice);
    final payUnsigned = await payWallet.createTransaction(
      destination: intent.toArkAddress,
      amountSats: intent.amountSats.toInt(),
    );
    final payTxid = await payWallet.submit(await payWallet.signTransaction(payUnsigned));
    expect(payTxid, isNotEmpty);
    print('   Paid: ark_txid=$payTxid');

    // The cosigner recognises the settled send as satisfying the request.
    final afterPay = await alice.paymentRequests();
    final paid = afterPay.firstWhere((i) => i.id == intent.id);
    expect(paid.status, 'fulfilled',
        reason: 'the settled send must mark the request fulfilled');
    expect(paid.arkTxid, payTxid);
    print('   Request marked fulfilled with the settling txid');

    // And the money actually moved.
    final aliceAfterPay = (await alice.listVtxos()).totalBalance.toInt();
    expect(aliceAfterPay, lessThan(aliceBeforePay),
        reason: "Alice's balance must drop by the paid amount");
    int bobAfterPay = 0;
    for (var i = 0; i < 20; i++) {
      bobAfterPay = (await bob.listVtxos()).totalBalance.toInt();
      if (bobAfterPay >= totalSent + requestAmount) break;
      await Future.delayed(Duration(seconds: 1));
    }
    expect(bobAfterPay, equals(totalSent + requestAmount),
        reason: 'Bob must receive the requested amount');
    print('   Bob received it: balance=$bobAfterPay');

    // Declining is the other terminal state. Unlike a revoked request it must STAY in
    // the inbox, marked declined — the payer refused it, they didn't un-know about it.
    final unwanted =
        await bob.requestPayment(alice.userId!, 777, memo: 'not today');
    await alice.declinePaymentRequest(unwanted.id);
    final afterDecline = await alice.paymentRequests();
    expect(afterDecline.firstWhere((i) => i.id == unwanted.id).status, 'declined',
        reason: 'a declined request must remain visible with declined status');
    print('   Alice declined a request');

    // Revoking must also drop that contact's pending requests — otherwise revocation
    // would stop new requests but leave the old ones sitting in the inbox.
    final second =
        await bob.requestPayment(alice.userId!, 500, memo: 'will be revoked');
    await alice.contactRemove(bob.userId!);
    final afterRevoke = await alice.paymentRequests();
    expect(afterRevoke.where((i) => i.id == second.id), isEmpty,
        reason: 'revoking a contact must discard their pending requests');
    // ...and the gate is shut for new ones too, not just the queued one.
    await expectLater(
      bob.requestPayment(alice.userId!, 100, memo: 'after revoke'),
      throwsA(isA<Exception>()),
      reason: 'a revoked contact must not be able to create a request',
    );
    print('   Revoke closed the gate and dropped the pending request');

    print('Full Ark E2E flow complete!');
  }, timeout: Timeout(Duration(minutes: 10)));

  // Phase 5 — gated wallet. The FROST share is PIN/PRF-blinded (δ); auth rides a minted session
  // token; the raw share is reconstructed transiently ONLY to FROST-sign an ARK op. Proves the
  // whole "PIN only for ARK" design headlessly (FixedSeedSource stands in for the passkey PRF):
  //  - reads authenticate token-only, with NO seed reconstructed;
  //  - a right-seed settle FROST-signs validly (reconstruction integrates end-to-end);
  //  - a WRONG seed cannot sign — the cosigner rejects the bad signature share.
  test('Ark gated: PIN/PRF-blinded share — token auth + reconstructed FROST sign',
      () async {
    final seed =
        Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 3) & 0xff));
    final wrongSeed =
        Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 4) & 0xff));

    // 1. Gated DKG: the seed is wired BEFORE DKG, so the share is stored blinded and no Schnorr
    //    auth helper is built. DKG itself is unauthenticated, so no token is needed yet.
    print('1. Gated DKG');
    final alice = createClient(storageId: "gated_alice");
    alice.setSeedSource(FixedSeedSource(seed));
    await alice.doDkg();
    expect(alice.userId, isNotNull);
    print('   userId=${alice.userId!.substring(0, 16)}...');

    // 2. Mint an upstream-style session token bound to this user (sub = group key) and wire it.
    //    Every authenticated RPC now rides the Bearer token; the share is never used for auth.
    final token = await mintSessionToken(alice.userId!, webauthTokenSecret);
    alice.setSessionTokenSource(StaticSessionToken(token));

    // 3. Reads work token-only — no seed reconstructed. Proves auth is off the share.
    print('2. Reads via token (no seed)');
    final arkInfo = await alice.getArkInfo();
    expect(arkInfo.signerPubkey, isNotEmpty);
    final boardingAddress = await alice.getBoardingAddress();
    expect(boardingAddress, isNotEmpty);

    // 4. Fund + settle — the first FROST sign. The share is reconstructed from δ + the seed
    //    transiently; a valid commitment proves the gating integrates end-to-end.
    print('3. Fund + settle (gated FROST sign)');
    final minerAddr = await btc.getNewAddress();
    await btc.sendToAddress(boardingAddress, 0.01);
    await btc.generateToAddress(1, minerAddr);
    await Future.delayed(Duration(seconds: 5));

    bool settling = true;
    final miningTimer = Timer.periodic(Duration(seconds: 3), (t) async {
      if (!settling) {
        t.cancel();
        return;
      }
      try {
        await btc.generateToAddress(1, await btc.getNewAddress());
      } catch (_) {}
    });
    final boardingUtxos = await pollBoardingUtxos(boardingAddress, 1);
    expect(boardingUtxos, isNotEmpty);
    String commitmentTxid;
    try {
      commitmentTxid = await settleBoarding(alice, boardingUtxos);
    } finally {
      settling = false;
      miningTimer.cancel();
    }
    expect(commitmentTxid, isNotEmpty,
        reason: 'gated settle must FROST-sign validly with the reconstructed share');
    final vtxos = await alice.listVtxos();
    expect(vtxos.vtxos.length, equals(1),
        reason: 'a VTXO ⇒ the gated signature was accepted on-chain');
    print('   Settled — reconstructed share signed validly');

    // 5. WRONG seed ⇒ reconstruction yields the wrong share ⇒ the cosigner rejects the FROST
    //    signature share. The gate holds: a wrong PIN/PRF cannot spend.
    print('4. Wrong seed must fail to sign');
    alice.setSeedSource(FixedSeedSource(wrongSeed));
    final aliceArk = MpcArkWallet(alice);
    final selfAddr = await alice.getArkAddress();
    final unsigned = await aliceArk.createTransaction(
      destination: selfAddr,
      amountSats: 1000,
    );
    await expectLater(
      aliceArk.signTransaction(unsigned),
      throwsA(anything),
      reason: 'a wrong PIN/PRF seed must not produce a valid FROST signature',
    );
    print('   Wrong seed correctly rejected — gate holds');
  }, timeout: Timeout(Duration(minutes: 10)));

  // Auto-settle round-trip: register a delegate intent with store_only=true,
  // then verify the cosigner's tick task drives it to completion on its own.
  //
  // Setup forces `AUTO_SETTLE_SAFETY_MARGIN_SECS` far larger than
  // `ARKD_VTXO_TREE_EXPIRY`, so the tick threshold clamps to 0 (always
  // crossed) and any stored intent fires on the next 60-second tick,
  // independent of the arkd expiry configuration.
  test('Ark: auto-settle drives stored delegate intent without client', () async {
    print('1. Alice DKG');
    final alice = createClient(storageId: "alice");
    await alice.doDkg();

    print('2. Fund boarding + settle');
    final boardingAddress = await alice.getBoardingAddress();
    final minerAddr = await btc.getNewAddress();
    await btc.sendToAddress(boardingAddress, 0.005);
    await btc.generateToAddress(1, minerAddr);

    // The wallet polls the boarding address via electrum (bitcoind sees the
    // deposit immediately; electrs needs a few seconds to index) and supplies
    // the UTXO to settle().
    final boardingUtxos = await pollBoardingUtxos(boardingAddress, 500000);
    expect(boardingUtxos, isNotEmpty,
        reason: 'Electrum should index the boarding UTXO within 30s');

    bool stillMining = true;
    final miningTimer = Timer.periodic(Duration(seconds: 3), (timer) async {
      if (!stillMining) {
        timer.cancel();
        return;
      }
      try {
        await btc.generateToAddress(1, await btc.getNewAddress());
      } catch (_) {}
    });
    try {
      final commitment = await settleBoarding(alice, boardingUtxos);
      expect(commitment, isNotEmpty);
      print('   Settled commitment=$commitment');
    } finally {
      // Keep mining through the rest of the test — the cosigner's auto-settle
      // submission still needs the ASP scheduler firing batches.
    }

    print('3. Snapshot original VTXO (poll until expires_at populates)');
    String originalTxid = '';
    int originalBalance = 0;
    int expiresAt = 0;
    for (int i = 0; i < 20; i++) {
      final r = await alice.listVtxos();
      if (r.vtxos.isNotEmpty) {
        originalTxid = r.vtxos.first.txid;
        originalBalance = r.totalBalance.toInt();
        expiresAt = r.vtxos.first.expiresAt.toInt();
      }
      if (expiresAt > 0) break;
      await Future.delayed(Duration(seconds: 1));
    }
    expect(expiresAt, greaterThan(0),
        reason:
            'expires_at must be populated by the vtxo_stream backfill before the tick can act');
    print('   txid=$originalTxid balance=$originalBalance expires_at=$expiresAt');

    print('4. settleDelegate(storeOnly: true) — store signed intent');
    final delegated = await alice.settleDelegate(storeOnly: true);
    expect(delegated, isEmpty, reason: 'DELEGATED returns no commitment_txid');
    final afterDelegate = await alice.listVtxos();
    expect(afterDelegate.hasActiveDelegate, isTrue);
    expect(afterDelegate.vtxos.first.txid, equals(originalTxid),
        reason: 'storing the intent must NOT consume the VTXO');

    print(
        '5. Wait up to 2 minutes for the cosigner tick task to drive the intent');
    // Setup forces a huge AUTO_SETTLE_SAFETY_MARGIN_SECS, so the tick threshold
    // is "always crossed" regardless of VTXO_TREE_EXPIRY. Tick interval is
    // 60s with the first tick skipped on boot, so worst-case ~60s before
    // submission + ASP batch latency. Mining keeps the scheduler moving.
    String? newTxid;
    int newBalance = 0;
    bool stillActive = true;
    final deadline = DateTime.now().add(Duration(minutes: 2));
    while (DateTime.now().isBefore(deadline)) {
      await Future.delayed(Duration(seconds: 5));
      try {
        final resp = await alice.listVtxos();
        stillActive = resp.hasActiveDelegate;
        if (resp.vtxos.isNotEmpty) {
          newTxid = resp.vtxos.first.txid;
          newBalance = resp.totalBalance.toInt();
        }
        // Auto-settle complete: VTXO refreshed (txid changed) AND delegate
        // cleared (the handler clears it after a successful settle).
        if (newTxid != null && newTxid != originalTxid && !stillActive) {
          break;
        }
      } catch (e) {
        print('   listVtxos error (will retry): $e');
      }
    }
    stillMining = false;
    miningTimer.cancel();

    expect(newTxid, isNotNull,
        reason: 'auto-settle did not produce any VTXO update before timeout');
    expect(newTxid, isNot(equals(originalTxid)),
        reason:
            'auto-settle must replace the original VTXO with a fresh one');
    expect(newBalance, equals(originalBalance),
        reason: 'auto-settle must preserve the balance');
    expect(stillActive, isFalse,
        reason: 'cosigner must clear the delegate after a successful settle');
    print(
        '6. Auto-settle complete: new txid=$newTxid (was $originalTxid), balance preserved');
  }, timeout: Timeout(Duration(minutes: 4)));

  // Cosigner-runtime restart: kill the process, restart against the same
  // data_dir, and prove that persisted state survives. Specifically:
  //   * VTXOs reload (`load_user_vtxos`) before the vtxo_stream catches up
  //   * Ark transaction history reloads (`load_user_ark_history`) — the
  //     previously-gone-on-restart entries we just wired up
  //   * Per-user RPCs (getArkAddress) work again after rehydration
  test('Ark: cosigner restart preserves rehydrated state', () async {
    print('1. Alice DKG');
    final alice = createClient(storageId: "alice");
    await alice.doDkg();

    print('2. Fund boarding + settle');
    final boardingAddress = await alice.getBoardingAddress();
    final minerAddr = await btc.getNewAddress();
    await btc.sendToAddress(boardingAddress, 0.003);
    await btc.generateToAddress(1, minerAddr);

    final boardingUtxos = await pollBoardingUtxos(boardingAddress, 300000);
    expect(boardingUtxos, isNotEmpty,
        reason: 'Electrum should index the boarding UTXO within 30s');

    bool stillMining = true;
    final miningTimer = Timer.periodic(Duration(seconds: 3), (timer) async {
      if (!stillMining) {
        timer.cancel();
        return;
      }
      try {
        await btc.generateToAddress(1, await btc.getNewAddress());
      } catch (_) {}
    });
    final commitment = await settleBoarding(alice, boardingUtxos);
    expect(commitment, isNotEmpty);
    stillMining = false;
    miningTimer.cancel();

    print('3. Capture pre-restart state');
    final preVtxos = await alice.listVtxos();
    expect(preVtxos.vtxos, isNotEmpty,
        reason: 'pre-restart should have at least one VTXO');
    final preVtxoOutpoints =
        preVtxos.vtxos.map((v) => '${v.txid}:${v.vout}').toSet();
    print('   pre-restart: ${preVtxos.vtxos.length} VTXOs');

    print('4. Kill cosigner');
    final oldProcess = serverProcess!;
    serverProcess = null;
    oldProcess.kill(ProcessSignal.sigterm);
    // Wait for actual exit so the sled lock releases before we restart.
    await oldProcess.exitCode;
    print('   cosigner exited; sled lock should be released');

    print('5. Restart cosigner against the same data_dir');
    serverProcess = await startCosignerRuntime(
      serverPort,
      serverTempDir,
      extraEnv: cosignerExtraEnv,
    );

    print('6. Recapture post-restart state');
    // First listVtxos call spawns a fresh actor; `get_or_spawn` rehydrates
    // vtxos / ark_tx_history / device_tokens from sled. The vtxo_stream
    // subscription will also reconnect and reconcile, but the rehydration
    // load means the first listVtxos call already returns valid state.
    final postVtxos = await alice.listVtxos();

    print(
        '   post-restart: ${postVtxos.vtxos.length} VTXOs');

    final postVtxoOutpoints =
        postVtxos.vtxos.map((v) => '${v.txid}:${v.vout}').toSet();

    expect(postVtxoOutpoints, equals(preVtxoOutpoints),
        reason:
            'VTXOs should be rehydrated from vtxo_store after restart (pre-restart set must match post-restart set)');

    print('7. Sanity: post-restart per-user RPCs work');
    final addr = await alice.getArkAddress();
    expect(addr, isNotEmpty,
        reason:
            'getArkAddress should succeed once the user actor is rehydrated post-restart');

    print('Restart-survival test complete!');
  }, timeout: Timeout(Duration(minutes: 4)));

  // Plan A 1B gate — absorbed from the former `restore_from_seal_e2e_test.dart`.
  //
  // The restart test above proves DATA rehydrates (VTXOs, history) and that a
  // derivation like getArkAddress still works — but it never signs, and neither
  // does the stale-VTXO restart test. The delegate-survives-restart test does
  // settle post-restart, which exercises the restored `ark_cosigner_secret`, not
  // the FROST share. So nothing here covered the specific claim below.
  //
  // That claim: with the plaintext FROST key gone from `policies`, the cosigner's
  // signing share exists ONLY inside the sealed snapshot. A cold-spawned actor
  // must reconstruct it from the seal alone. Because the persisted key field is
  // blank, a broken restore cannot be masked by a plaintext fallback — the sign
  // simply fails.
  //
  // Moving it here also fixes it: standalone it ran under a `make e2e-restore` target,
  // which starts no arkd and sets no ASP_URL, so the runtime exited at boot with
  // "ASP_URL is required" and the test could never have passed. Here the shared
  // runtime from setUpAll is already pointed at arkd.
  test('Ark: cosigner FROST-signs from the sealed snapshot after a restart',
      () async {
    print('1. DKG a fresh wallet');
    final sealed = createClient(storageId: 'seal_restore');
    await sealed.doDkg();
    print('   user=${sealed.userId?.substring(0, 12)}');

    // Baseline while the actor is warm: proves the happy path and that the guest
    // actually sealed its state before we kill anything.
    final warmMsg = Uint8List.fromList(List.generate(32, (i) => i + 1));
    await sealed.sign(warmMsg, applyTweak: false); // throws on an invalid aggregate
    print('2. Warm sign OK');

    print('3. Kill cosigner');
    final oldProcess = serverProcess!;
    serverProcess = null;
    oldProcess.kill(ProcessSignal.sigterm);
    // Wait for real exit so the SQLite file is released before the restart.
    await oldProcess.exitCode;

    print('4. Restart against the same data dir — every actor is now cold');
    serverProcess = await startCosignerRuntime(
      serverPort,
      serverTempDir,
      extraEnv: cosignerExtraEnv,
    );

    // The cold-spawned actor has to restore its share from the seal to produce a
    // valid signature share here. A different message than the warm one, so a
    // cached/replayed signature cannot make this pass.
    final coldMsg = Uint8List.fromList(List.generate(32, (i) => 0xA0 + i));
    await sealed.sign(coldMsg, applyTweak: false);
    print('5. COLD sign OK — share restored from the seal alone');
  }, timeout: Timeout(Duration(minutes: 4)));

  // FCM push delivery: the cosigner is configured (via setUpAll) to
  // direct all FCM traffic at `MockFcmServer`. This test:
  //   1. Registers a fake device token for the recipient (Bob)
  //   2. Triggers a receive (Alice → Bob via off-chain send)
  //   3. Asserts the mock recorded a `messages:send` POST with the right
  //      bearer token, project id, target token, and data payload shape
  //
  // Pre-conditions covered:
  //   * OAuth round-trip happens (cosigner sets Authorization: Bearer <mock>)
  //   * payload is a visible notification ("Funds received") + `type=vtxo_received` data
  //   * Android `priority: HIGH` + APNS alert headers present
  //   * `user_id` field in data matches the recipient
  // REMOVED: 'FCM push fires on VTXO receive with correct payload shape' and
  // 'Ark: boarding watcher pushes tap-to-board on a confirmed deposit'.
  //
  // Both drove a push the cosigner cannot send. It is called rather than running, so it has no
  // outbound socket and no FCM client; the notification used to go out on a detached task that a
  // per-request runtime would drop. `RegisterDeviceToken` went with it — the host owns the push
  // channel now, and the registry that feeds it. These come back as host tests, not cosigner ones.

  test('Ark: delegate intent survives cosigner restart + auto-settles',
      () async {
    print('1. Alice DKG');
    final alice = createClient(storageId: "alice");
    await alice.doDkg();

    print('2. Fund boarding + settle');
    final boardingAddress = await alice.getBoardingAddress();
    final minerAddr = await btc.getNewAddress();
    await btc.sendToAddress(boardingAddress, 0.003);
    await btc.generateToAddress(1, minerAddr);

    final boardingUtxos = await pollBoardingUtxos(boardingAddress, 300000);
    expect(boardingUtxos, isNotEmpty);

    bool stillMining = true;
    final miningTimer = Timer.periodic(Duration(seconds: 3), (timer) async {
      if (!stillMining) {
        timer.cancel();
        return;
      }
      try {
        await btc.generateToAddress(1, await btc.getNewAddress());
      } catch (_) {}
    });
    final commitment = await settleBoarding(alice, boardingUtxos);
    expect(commitment, isNotEmpty);

    print('3. Wait for expires_at backfill');
    int originalExpiresAt = 0;
    String originalTxid = '';
    int originalBalance = 0;
    for (int i = 0; i < 20; i++) {
      final r = await alice.listVtxos();
      if (r.vtxos.isNotEmpty) {
        originalExpiresAt = r.vtxos.first.expiresAt.toInt();
        originalTxid = r.vtxos.first.txid;
        originalBalance = r.totalBalance.toInt();
      }
      if (originalExpiresAt > 0) break;
      await Future.delayed(Duration(seconds: 1));
    }
    expect(originalExpiresAt, greaterThan(0));

    print('4. settleDelegate(storeOnly: true) — persist signed intent to sled');
    final delegatedTxid = await alice.settleDelegate(storeOnly: true);
    expect(delegatedTxid, isEmpty);
    final beforeRestart = await alice.listVtxos();
    expect(beforeRestart.hasActiveDelegate, isTrue,
        reason: 'pre-restart: cosigner should report delegate as active');

    print('5. Kill cosigner');
    final oldProcess = serverProcess!;
    serverProcess = null;
    oldProcess.kill(ProcessSignal.sigterm);
    await oldProcess.exitCode;
    print('   cosigner exited; sled lock should be released');

    print('6. Restart against same data_dir — must rehydrate delegate');
    serverProcess = await startCosignerRuntime(
      serverPort,
      serverTempDir,
      extraEnv: cosignerExtraEnv,
    );

    print('7. listVtxos confirms delegate rehydrated from sled');
    final afterRestart = await alice.listVtxos();
    expect(afterRestart.hasActiveDelegate, isTrue,
        reason:
            'POST-RESTART: cosigner must rehydrate the signed delegate intent from sled. '
            'If false, either (a) delegate_sessions sled row missing, '
            '(b) SecretStore dkg-secret lookup failed, or '
            '(c) DelegateSettleSession::from_persisted rejected the record.');
    expect(afterRestart.vtxos.length, equals(1),
        reason: 'pre-restart VTXO must still be present post-restart');
    expect(afterRestart.vtxos.first.txid, equals(originalTxid),
        reason: 'rehydrated VTXO outpoint must match pre-restart');

    print(
        '8. Wait up to 4 minutes for tick to drive the rehydrated intent through a batch');
    String? newTxid;
    int newBalance = 0;
    bool stillActive = true;
    final deadline = DateTime.now().add(Duration(minutes: 4));
    while (DateTime.now().isBefore(deadline)) {
      await Future.delayed(Duration(seconds: 5));
      try {
        final resp = await alice.listVtxos();
        stillActive = resp.hasActiveDelegate;
        if (resp.vtxos.isNotEmpty) {
          newTxid = resp.vtxos.first.txid;
          newBalance = resp.totalBalance.toInt();
        }
        if (newTxid != null && newTxid != originalTxid && !stillActive) {
          break;
        }
      } catch (e) {
        print('   listVtxos error (will retry): $e');
      }
    }
    stillMining = false;
    miningTimer.cancel();

    expect(newTxid, isNotNull,
        reason: 'rehydrated auto-settle did not produce a VTXO update');
    expect(newTxid, isNot(equals(originalTxid)),
        reason:
            'rehydrated auto-settle must replace the original VTXO with a fresh one');
    expect(newBalance, equals(originalBalance),
        reason: 'rehydrated auto-settle must preserve the balance');
    expect(stillActive, isFalse,
        reason:
            'cosigner must clear the rehydrated delegate (sled + in-memory) after settle completes');

    print(
        '9. Delegate-persistence + rehydrated auto-settle complete: txid=$originalTxid → $newTxid');
  }, timeout: Timeout(Duration(minutes: 7)));

  // Cold-spawn auto-settle: prove the tick task itself spawns the actor
  // from sled, not by reading the in-memory DashMap.
  //
  // The previous test ('delegate intent survives cosigner restart')
  // calls `listVtxos` immediately after restart, which warms Alice's actor.
  // The tick would find her in the DashMap and fire — even if the sled-
  // iteration code were broken. This test instead waits for the tick to
  // happen WITHOUT any prior RPC against Alice. The first `listVtxos`
  // happens AFTER the wait; if it shows the new VTXO, the only thing
  // that could have driven the settle is the tick task spawning Alice
  // cold via the sled `delegate_sessions` iteration.
  //
  // Failure mode this guards against: a regression that switches the
  // tick back to `snapshot_handles()` (in-memory only). With that change,
  // a restarted Alice whose client hasn't reopened the app would still
  // have her delegate intent in sled but the tick would never find her
  // and her VTXO would eventually expire.
  test(
      'Ark: auto-settle tick cold-spawns user from sled after restart, no prior RPC',
      () async {
    print('1. Alice DKG');
    final alice = createClient(storageId: "alice");
    await alice.doDkg();

    print('2. Fund boarding + settle');
    final boardingAddress = await alice.getBoardingAddress();
    final minerAddr = await btc.getNewAddress();
    await btc.sendToAddress(boardingAddress, 0.003);
    await btc.generateToAddress(1, minerAddr);

    final boardingUtxos = await pollBoardingUtxos(boardingAddress, 300000);
    expect(boardingUtxos, isNotEmpty);

    bool stillMining = true;
    final miningTimer = Timer.periodic(Duration(seconds: 3), (timer) async {
      if (!stillMining) {
        timer.cancel();
        return;
      }
      try {
        await btc.generateToAddress(1, await btc.getNewAddress());
      } catch (_) {}
    });
    final commitment = await settleBoarding(alice, boardingUtxos);
    expect(commitment, isNotEmpty);

    print('3. Wait for expires_at backfill, then store delegate intent');
    int expiresAt = 0;
    String originalTxid = '';
    int originalBalance = 0;
    for (int i = 0; i < 20; i++) {
      final r = await alice.listVtxos();
      if (r.vtxos.isNotEmpty) {
        expiresAt = r.vtxos.first.expiresAt.toInt();
        originalTxid = r.vtxos.first.txid;
        originalBalance = r.totalBalance.toInt();
      }
      if (expiresAt > 0) break;
      await Future.delayed(Duration(seconds: 1));
    }
    expect(expiresAt, greaterThan(0));

    await alice.settleDelegate(storeOnly: true);
    final pre = await alice.listVtxos();
    expect(pre.hasActiveDelegate, isTrue);

    print('4. Kill cosigner');
    final oldProcess = serverProcess!;
    serverProcess = null;
    oldProcess.kill(ProcessSignal.sigterm);
    await oldProcess.exitCode;

    print('5. Restart cosigner');
    serverProcess = await startCosignerRuntime(
      serverPort,
      serverTempDir,
      extraEnv: cosignerExtraEnv,
    );

    // Critical: the next ~3 minutes must pass with NO RPC against Alice.
    // The only legitimate way her actor can spawn is via the sled-iterating
    // tick task we're testing. We keep mining so the ASP scheduler can
    // form batches once the cosigner-driven settle starts.
    //
    // Timing: the tick task skips its immediate fire, then ticks every
    // 60s, so the first tick lands ~60s after restart. If the sled
    // iteration finds Alice, it cold-spawns her and sends TickAutoSettle.
    // The handler then drives the batch (10-30s with active mining).
    // Total expected wall-clock: ~90-120s. We wait up to 3 minutes for
    // slack.
    print('6. Wait 3 minutes for cold-spawn tick to drive the settle');
    print('   (NOT calling any RPC against Alice during this window)');
    await Future.delayed(Duration(minutes: 3));

    print('7. First post-restart RPC against Alice — assert tick did the work');
    final post = await alice.listVtxos();
    stillMining = false;
    miningTimer.cancel();

    expect(post.vtxos, isNotEmpty,
        reason: 'Alice should still have a VTXO after the tick drove the settle');
    expect(post.vtxos.first.txid, isNot(equals(originalTxid)),
        reason:
            'COLD-SPAWN PROOF: if the tick task only iterated the in-memory '
            'DashMap, Alice would never have been spawned (no prior RPC), '
            'her delegate would never have fired, and the VTXO txid would '
            'still match the pre-restart original.');
    expect(post.totalBalance.toInt(), equals(originalBalance),
        reason: 'cold-spawn auto-settle must preserve balance');
    expect(post.hasActiveDelegate, isFalse,
        reason:
            'cold-spawn auto-settle must clear the delegate (sled + in-memory) on success');

    print(
        '8. Cold-spawn auto-settle proven: ${originalTxid.substring(0, 12)}…');
    print('   → ${post.vtxos.first.txid.substring(0, 12)}…');
  }, timeout: Timeout(Duration(minutes: 6)));

  // Delegate/auto-settle stress + regression. Ping-pongs Ark VTXOs between two
  // BOARDED wallets for N cycles (DELEGATE_STRESS_CYCLES, default 10): each half a
  // wallet sends (FROST-signs), the receiver delegates (FROST-signs), and the
  // cosigner auto-settles it server-side to one VTXO; the next half spends that
  // just-auto-settled VTXO. Asserts 4*N client signatures, 2*N server-side
  // auto-settles, and per-cycle balance conservation.
  //
  // Regression: boarding gives each wallet a boarding-delay VTXO, so the first
  // consolidated VTXO mixes boarding + unilateral delays. Spending it used to fail
  // (INVALID_PSBT_INPUT) because route_tick_auto_settle guessed the consolidated
  // VTXO's exit_delay from the first input; fixed by recording the settle's real
  // unilateral_exit_delay. Spends auto-settled VTXOs every cycle → fails pre-fix.
  test('Ark: delegate/auto-settle stress — many send/receive cycles', () async {
    final cycles =
        int.tryParse(Platform.environment['DELEGATE_STRESS_CYCLES'] ?? '') ?? 10;
    final sendSats =
        int.tryParse(Platform.environment['DELEGATE_STRESS_SEND_SATS'] ?? '') ??
            50000;
    print('=== delegate stress: $cycles cycles, send=$sendSats sats/leg ===');

    // Two boarded wallets (sequential DKG — mirrors the other Ark tests).
    final alice = createClient(storageId: 'stress_alice');
    await alice.doDkg();
    final bob = createClient(storageId: 'stress_bob');
    await bob.doDkg();
    final aliceArk = await alice.getArkAddress();
    final bobArk = await bob.getArkAddress();

    // Client-signing counters (the whole point of the test).
    int totalSends = 0;
    int totalDelegates = 0;
    int totalAutoSettles = 0;

    // One mining timer for the WHOLE test, GATED by `mineNow`. ASP batches are
    // block-driven, so settle + auto-settle need blocks flowing — but an
    // off-chain SEND must reference a stable VTXO checkpoint, and background
    // re-batching mid-send makes arkd reject the PSBT (INVALID_PSBT_INPUT). So we
    // mine only during settle/auto-settle and hold the chain quiet during sends.
    final minerAddr = await btc.getNewAddress();
    bool stillMining = true;
    bool mineNow = false;
    final miningTimer = Timer.periodic(Duration(seconds: 3), (t) async {
      if (!stillMining) {
        t.cancel();
        return;
      }
      if (!mineNow) return;
      try {
        await btc.generateToAddress(1, minerAddr);
      } catch (_) {}
    });

    try {
      // ── Fund BOTH wallets by boarding 0.005 BTC then settling. Boarding is
      // essential to the regression: it gives each wallet a boarding-delay VTXO,
      // so the first consolidated VTXO mixes boarding + unilateral delays. ──
      Future<int> fund(MpcClient c, String label) async {
        final addr = await c.getBoardingAddress();
        await btc.sendToAddress(addr, 0.005);
        await btc.generateToAddress(1, minerAddr);
        final utxos = await pollBoardingUtxos(addr, 500000);
        expect(utxos, isNotEmpty,
            reason: '$label boarding UTXO should index within 30s');
        mineNow = true; // settle needs the ASP scheduler forming batches
        final commitment = await settleBoarding(c, utxos);
        mineNow = false;
        expect(commitment, isNotEmpty,
            reason: '$label settle should return a commitment txid');
        int bal = 0;
        for (int i = 0; i < 15; i++) {
          bal = (await c.listVtxos()).totalBalance.toInt();
          if (bal > 0) break;
          await Future.delayed(Duration(seconds: 1));
        }
        expect(bal, greaterThan(0), reason: '$label should hold a settled VTXO');
        print('   funded $label: balance=$bal');
        return bal;
      }

      final a0 = await fund(alice, 'alice');
      final b0 = await fund(bob, 'bob');
      // Ping-pong is conservative: end of each cycle alice==a0, bob==b0. Both must
      // stay solvent for `sendSats` every leg for any N.
      expect(a0, greaterThan(sendSats * 2));
      expect(b0, greaterThan(sendSats));

      // Poll until every VTXO of `c` is confirmed (expires_at>0). Caller owns the
      // mining gate (OFF before a send, ON before a delegate). Soft-warns on timeout.
      Future<void> confirmVtxos(MpcClient c, String label) async {
        for (int i = 0; i < 60; i++) {
          final r = await c.listVtxos();
          if (r.vtxos.isNotEmpty &&
              r.vtxos.every((v) => v.expiresAt.toInt() > 0)) return;
          await Future.delayed(Duration(seconds: 1));
        }
        print('   [$label] warning: not all VTXOs confirmed (expires_at) after 60s');
      }

      // Sender FROST-signs an off-chain send of `sendSats` to `recvAddr` (non-empty
      // ark_txid only if the sig verified), asserts funds moved, polls the receiver.
      Future<void> sendAndReceive(MpcClient sender, String senderLabel,
          MpcClient receiver, String receiverLabel, String recvAddr) async {
        // Hold the chain quiet: a send must reference a stable VTXO checkpoint,
        // and background mining would move it out from under the built PSBT.
        mineNow = false;
        await confirmVtxos(sender, senderLabel);
        await Future.delayed(Duration(seconds: 2)); // let any in-flight block land
        final senderPre = (await sender.listVtxos()).totalBalance.toInt();
        final recvPre = (await receiver.listVtxos()).totalBalance.toInt();

        // Build → FROST-sign → submit, with retry: mining elsewhere can leave the
        // ASP's checkpoint briefly ahead of listVtxos; re-reading + rebuilding
        // converges now that the chain is quiet.
        String arkTxid = '';
        for (int attempt = 1; attempt <= 6; attempt++) {
          final w = MpcArkWallet(sender);
          final unsigned = await w.createTransaction(
              destination: recvAddr, amountSats: sendSats);
          expect(unsigned.sighashes, isNotEmpty,
              reason: 'a send must produce sighashes for the client to FROST-sign');
          final signedTx = await w.signTransaction(unsigned); // client FROST-signs
          try {
            arkTxid = await w.submit(signedTx);
            break;
          } catch (e) {
            if (attempt < 6 && e.toString().contains('INVALID_PSBT_INPUT')) {
              print(
                  '   [$senderLabel] send attempt $attempt: stale checkpoint, retrying…');
              await Future.delayed(Duration(seconds: 3));
              continue;
            }
            rethrow;
          }
        }
        expect(arkTxid, isNotEmpty,
            reason:
                '$senderLabel: a send only returns a txid if the FROST sig verified + ASP accepted it');
        totalSends++;

        final senderAfter = await sender.listVtxos();
        expect(senderAfter.totalBalance.toInt(), equals(senderPre - sendSats),
            reason: '$senderLabel balance must drop by exactly the sent amount');
        expect(senderAfter.hasActiveDelegate, isFalse,
            reason: 'a send must invalidate any active delegate');

        int recvBal = recvPre;
        for (int i = 0; i < 15; i++) {
          recvBal = (await receiver.listVtxos()).totalBalance.toInt();
          if (recvBal == recvPre + sendSats) break;
          await Future.delayed(Duration(seconds: 1));
        }
        expect(recvBal, equals(recvPre + sendSats),
            reason: '$receiverLabel should receive exactly $sendSats sats');

      }

      // Receiver stores a delegate (FROST-signs), then waits (3-min deadline) for the
      // cosigner to auto-settle it with NO client RPC → one VTXO, fresh txid, balance
      // preserved, delegate cleared. Returns the consolidated balance.
      Future<int> delegateAndAutoSettle(MpcClient c, String label) async {
        // Mining is safe here (no send follows) and is needed both to confirm the
        // just-received VTXO and to drive the auto-settle batch.
        mineNow = true;
        await confirmVtxos(c, label);
        final before = await c.listVtxos();
        final originalTxids = before.vtxos.map((v) => v.txid).toSet();
        final originalBalance = before.totalBalance.toInt();

        final delegated = await c.settleDelegate(storeOnly: true); // client signs
        expect(delegated, isEmpty,
            reason: '$label DELEGATED returns no commitment txid');
        expect((await c.listVtxos()).hasActiveDelegate, isTrue,
            reason: '$label cosigner should report an active delegate');
        totalDelegates++;

        String? newTxid;
        int newBalance = originalBalance;
        bool stillActive = true;
        int vtxoCount = before.vtxos.length;
        final deadline = DateTime.now().add(Duration(minutes: 3));
        while (DateTime.now().isBefore(deadline)) {
          await Future.delayed(Duration(seconds: 5));
          try {
            final r = await c.listVtxos();
            stillActive = r.hasActiveDelegate;
            vtxoCount = r.vtxos.length;
            if (r.vtxos.isNotEmpty) {
              newTxid = r.vtxos.first.txid;
              newBalance = r.totalBalance.toInt();
            }
            if (vtxoCount == 1 &&
                newTxid != null &&
                !originalTxids.contains(newTxid) &&
                !stillActive) {
              break;
            }
          } catch (e) {
            print('   [$label] listVtxos retry: $e');
          }
        }
        // Finalize the freshly consolidated VTXO: keep mining until it's confirmed
        // (expires_at>0) so the NEXT half can spend it with a stable checkpoint.
        if (newTxid != null && !originalTxids.contains(newTxid) && !stillActive) {
          for (int i = 0; i < 40; i++) {
            final r = await c.listVtxos();
            if (r.vtxos.isNotEmpty &&
                r.vtxos.every((v) => v.expiresAt.toInt() > 0)) break;
            await Future.delayed(Duration(seconds: 1));
          }
        }
        mineNow = false; // hold the chain quiet before the next send
        expect(newTxid, isNotNull,
            reason: '$label auto-settle produced no VTXO update within 3min');
        expect(originalTxids.contains(newTxid), isFalse,
            reason: '$label auto-settle must replace the VTXO(s) with a fresh one');
        expect(vtxoCount, equals(1),
            reason: '$label auto-settle must consolidate to a single VTXO');
        expect(newBalance, equals(originalBalance),
            reason: '$label auto-settle must preserve the balance');
        expect(stillActive, isFalse,
            reason: '$label cosigner must clear the delegate after settling');
        totalAutoSettles++;
        return newBalance;
      }

      // ── ping-pong: Alice ⇄ Bob, `cycles` cycles ──
      // Each half the receiver holds 2 VTXOs (its prior + the received one),
      // delegates, and the cosigner auto-settles → 1 VTXO. The NEXT half spends
      // that just-auto-settled VTXO (the regression path).
      for (int cycle = 1; cycle <= cycles; cycle++) {
        // Half 1: Alice → Bob, then Bob delegates + auto-settles.
        await sendAndReceive(alice, 'alice', bob, 'bob', bobArk);
        final bobBal = await delegateAndAutoSettle(bob, 'bob');
        expect(bobBal, equals(b0 + sendSats),
            reason: 'after A→B + auto-settle, Bob should hold B0 + sendSats');

        // Half 2: Bob → Alice (spends Bob's auto-settled VTXO), then Alice
        // delegates + auto-settles.
        await sendAndReceive(bob, 'bob', alice, 'alice', aliceArk);
        final aliceBal = await delegateAndAutoSettle(alice, 'alice');
        expect(aliceBal, equals(a0),
            reason: 'after B→A + auto-settle, Alice should be back to A0');

        // Per-cycle invariant: balances return to their starting values.
        expect((await alice.listVtxos()).totalBalance.toInt(), equals(a0));
        expect((await bob.listVtxos()).totalBalance.toInt(), equals(b0));
        print('cycle $cycle/$cycles ok — sends=$totalSends '
            'delegates=$totalDelegates autoSettles=$totalAutoSettles');
      }

      // ── client-signing proof ──
      expect(totalSends, equals(2 * cycles));
      expect(totalDelegates, equals(2 * cycles));
      expect(totalSends + totalDelegates, equals(4 * cycles),
          reason:
              'client FROST-signed 4*cycles times (2 sends + 2 delegates per cycle)');
      expect(totalAutoSettles, equals(2 * cycles),
          reason:
              'cosigner auto-settled 2*cycles stored delegates with no client RPC');
      print('=== delegate stress complete: $cycles cycles, '
          '${totalSends + totalDelegates} client signatures, '
          '$totalAutoSettles server-side auto-settles ===');
    } finally {
      stillMining = false;
      miningTimer.cancel();
    }
  }, timeout: Timeout(Duration(minutes: 60)));

  /// Stale-cache self-heal: a spent VTXO that the push subscription missed must not survive a
  /// read, or it gets picked as a send input and every send dies with VTXO_ALREADY_SPENT forever.
  ///
  /// Desynchronises for real rather than mocking: spend a VTXO (so the ASP genuinely marks it
  /// spent), write it back into the cosigner's persisted cache, restart so the actor rehydrates
  /// from that poisoned cache, then assert the next read drops it.
  test('Ark: a spent VTXO the stream missed is dropped on read', () async {
    print('--- Stale spent-VTXO self-heal ---');

    print('1. Alice DKG + fund');
    final alice = createClient(storageId: 'stale_vtxo_alice');
    await alice.doDkg();
    alice.setSessionTokenSource(
        StaticSessionToken(await mintSessionToken(alice.userId!, webauthTokenSecret)));
    final groupKey = alice.groupKeyHex!;

    final boardingAddress = await alice.getBoardingAddress();
    await btc.sendToAddress(boardingAddress, 0.005);
    await btc.generateToAddress(1, await btc.getNewAddress());
    final boardingUtxos = await pollBoardingUtxos(boardingAddress, 500000);
    expect(boardingUtxos, isNotEmpty);

    bool mining = true;
    final miner = Timer.periodic(Duration(seconds: 3), (timer) async {
      if (!mining) {
        timer.cancel();
        return;
      }
      try {
        await btc.generateToAddress(1, await btc.getNewAddress());
      } catch (_) {}
    });
    await settleBoarding(alice, boardingUtxos);
    mining = false;
    miner.cancel();

    final arkWallet = MpcArkWallet(alice);
    final funded = await alice.listVtxos();
    expect(funded.vtxos, isNotEmpty, reason: 'Alice must hold a VTXO to spend');
    print('   Alice funded: balance=${funded.totalBalance}');

    // 2. Spend it, so the ASP genuinely considers those outpoints spent. Capture them first —
    //    a successful send removes them from the cache, which is what we then undo.
    print('2. Spend it (ASP now considers these outpoints spent)');
    final spentOutpoints = funded.vtxos
        .map((v) => {'txid': v.txid, 'vout': v.vout, 'amount': v.amount.toInt(),
                     'exit_delay': v.exitDelay, 'created_at': v.createdAt.toInt(),
                     'expires_at': v.expiresAt.toInt()})
        .toList();
    final bob = createClient(storageId: 'stale_vtxo_bob');
    await bob.doDkg();
    final unsigned = await arkWallet.createTransaction(
      destination: await bob.getArkAddress(),
      amountSats: 50000,
    );
    await arkWallet.submit(await arkWallet.signTransaction(unsigned));
    print('   Sent; the spent outpoints are gone from the cache');

    // 3. Poison the persisted cache with the now-spent entries — exactly the state a missed
    //    stream event leaves behind.
    print('3. Re-inject the spent VTXOs alongside the surviving change');
    // Merge, don't replace: the cache a missed stream event leaves behind still holds the change
    // VTXO from the send. Writing only the spent entries would leave nothing to keep, and the
    // "wallet not wiped" assertion below could then pass vacuously.
    final surviving = (await alice.listVtxos()).vtxos.map((v) => {
          'txid': v.txid,
          'vout': v.vout,
          'amount': v.amount.toInt(),
          'exit_delay': v.exitDelay,
          'created_at': v.createdAt.toInt(),
          'expires_at': v.expiresAt.toInt(),
        });
    final poisoned = jsonEncode([...spentOutpoints, ...surviving]);
    // Write straight into the runtime's SQLite KV, the way this used to SET the Redis key.
    // Single quotes are the only metacharacter inside a SQL string literal; JSON escaping
    // leaves none in practice, but double them so a stray one can't break out.
    final sqlValue = poisoned.replaceAll("'", "''");
    final setResult = await Process.run('sqlite3', [
      '${serverTempDir.path}/cosigner.db',
      "INSERT INTO kv (tree, key, value) VALUES ('vtxo_store', '$groupKey', '$sqlValue') "
          "ON CONFLICT (tree, key) DO UPDATE SET value = excluded.value;",
    ]);
    expect(setResult.exitCode, 0,
        reason: 'failed to poison the cache (needs the `sqlite3` CLI on PATH): '
            '${setResult.stderr}');

    // 4. Restart so the actor cold-spawns and rehydrates from the poisoned cache.
    print('4. Restart the cosigner so the actor rehydrates from it');
    final old = serverProcess!;
    serverProcess = null;
    old.kill(ProcessSignal.sigterm);
    await old.exitCode;
    serverProcess = await startCosignerRuntime(
      serverPort,
      serverTempDir,
      extraEnv: cosignerExtraEnv,
    );

    // 5. The read must drop them. Without the check they would still be listed — and the next
    //    send would pick them and fail at the ASP.
    print('5. Read must drop the spent entries');
    final afterHeal = await alice.listVtxos();
    final stillListed = afterHeal.vtxos
        .where((v) => spentOutpoints.any((s) => s['txid'] == v.txid && s['vout'] == v.vout))
        .toList();
    expect(stillListed, isEmpty,
        reason: 'a VTXO the ASP reports as spent must not survive a read '
            '(otherwise it is chosen as a send input and VTXO_ALREADY_SPENT recurs)');
    print('   Spent entries dropped — cache self-healed');

    // 6. And the wallet is not wiped: the change VTXO from the send is still spendable.
    expect(afterHeal.totalBalance.toInt(), greaterThan(0),
        reason: 'pruning must remove only the spent entries, never the whole wallet');
    print('   Change VTXO retained: balance=${afterHeal.totalBalance}');

    print('Stale spent-VTXO self-heal complete!');
  }, timeout: Timeout(Duration(minutes: 10)));

  // A send must spend a VTXO set whose members carry DIFFERENT exit delays.
  //
  // The exit delay is part of a VTXO's taproot tree and therefore of its
  // scriptPubKey, and a wallet legitimately holds a mix: a boarding-settled VTXO
  // and a received one are recorded with different delays. `build_send` used to
  // take `vtxos.first().exit_delay` and reuse that one input's spend script,
  // control block and scriptPubKey for EVERY input, so the non-first input got a
  // wrong prevout and the ASP rejected the send.
  //
  // The send path always spends the whole VTXO set (registry.rs hands the actor
  // every entry), so simply holding two differently-delayed VTXOs and sending is
  // enough to exercise it.
  test('Ark: send spends a mixed-exit-delay VTXO set (boarded + received)',
      () async {
    print('1. Alice + Bob DKG');
    final alice = createClient(storageId: 'mixed_delay_alice');
    final bob = createClient(storageId: 'mixed_delay_bob');
    await alice.doDkg();
    await bob.doDkg();

    // Keep batches flowing for the whole test (ARKD_SCHEDULER_TYPE=block).
    bool mining = true;
    final miner = Timer.periodic(Duration(seconds: 3), (t) async {
      if (!mining) {
        t.cancel();
        return;
      }
      try {
        await btc.generateToAddress(1, await btc.getNewAddress());
      } catch (_) {}
    });

    try {
      print('2. Alice boards — first VTXO');
      final aliceBoarding = await alice.getBoardingAddress();
      await btc.sendToAddress(aliceBoarding, 0.002);
      await btc.generateToAddress(1, await btc.getNewAddress());
      final aliceUtxos = await pollBoardingUtxos(aliceBoarding, 200000);
      expect(aliceUtxos, isNotEmpty, reason: 'Alice boarding deposit not seen');
      await settleBoarding(alice, aliceUtxos);

      print('3. Bob boards, then pays Alice — second VTXO, different delay');
      final bobBoarding = await bob.getBoardingAddress();
      await btc.sendToAddress(bobBoarding, 0.003);
      await btc.generateToAddress(1, await btc.getNewAddress());
      final bobUtxos = await pollBoardingUtxos(bobBoarding, 300000);
      expect(bobUtxos, isNotEmpty, reason: 'Bob boarding deposit not seen');
      await settleBoarding(bob, bobUtxos);

      final aliceArkAddr = await alice.getArkAddress();
      final bobWallet = MpcArkWallet(bob);
      final bobPay = await bobWallet.createTransaction(
        destination: aliceArkAddr,
        amountSats: 150000,
      );
      await bobWallet.submit(await bobWallet.signTransaction(bobPay));

      print('4. Wait for Alice to hold both VTXOs');
      var aliceVtxos = (await alice.listVtxos()).vtxos;
      for (int i = 0; i < 30 && aliceVtxos.length < 2; i++) {
        await Future.delayed(Duration(seconds: 2));
        aliceVtxos = (await alice.listVtxos()).vtxos;
      }
      expect(aliceVtxos.length, greaterThanOrEqualTo(2),
          reason: 'Alice needs a boarded AND a received VTXO for this test');

      final delays = aliceVtxos.map((v) => v.exitDelay).toSet();
      for (final v in aliceVtxos) {
        print('   vtxo ${v.txid.substring(0, 12)}.. '
            'amount=${v.amount} exit_delay=${v.exitDelay}');
      }
      // The whole point: if arkd were configured with equal delays the send
      // below would pass even with the bug present, so assert the mix is real.
      expect(delays.length, greaterThan(1),
          reason: 'VTXO set must carry DIFFERENT exit delays, otherwise this '
              'test cannot detect the shared-spend-info bug '
              '(check ARKD_UNILATERAL_EXIT_DELAY vs ARKD_BOARDING_EXIT_DELAY)');
      print('   Mixed delays confirmed: $delays');

      print('5. Alice sends — spends BOTH inputs');
      final bobArkAddr = await bob.getArkAddress();
      final aliceWallet = MpcArkWallet(alice);
      final unsigned = await aliceWallet.createTransaction(
        destination: bobArkAddr,
        amountSats: 120000,
      );
      final txid =
          await aliceWallet.submit(await aliceWallet.signTransaction(unsigned));
      expect(txid, isNotEmpty,
          reason: 'a send across mixed exit delays must be accepted by the ASP '
              '— a shared spend script yields a wrong prevout and is rejected');
      print('   Sent across mixed delays: $txid');

      print('6. Bob received it');
      int bobBalance = 0;
      for (int i = 0; i < 30; i++) {
        final r = await bob.listVtxos();
        bobBalance = r.totalBalance.toInt();
        if (bobBalance >= 120000) break;
        await Future.delayed(Duration(seconds: 2));
      }
      expect(bobBalance, greaterThanOrEqualTo(120000),
          reason: 'Bob should have received the mixed-input send');
      print('   Bob balance: $bobBalance');

      // ---- Reverse ordering: hold a VTXO first, THEN board, then send. ----
      //
      // The old code took `vtxos.first().exit_delay`, so which VTXO happens to
      // sit first decides which input gets the wrong spend script. Round 1 above
      // had the boarded VTXO first (change/received second); here the send's
      // change VTXO (unilateral delay) is already present and the boarded one
      // arrives after it — the opposite order. Proving both makes the fix
      // order-independent rather than accidentally right for one arrangement.
      print('7. Alice boards AGAIN, on top of her existing change VTXO');
      final changeVtxos = (await alice.listVtxos()).vtxos;
      expect(changeVtxos, isNotEmpty,
          reason: 'Alice should hold change from the send in step 5');
      print('   Existing (change) vtxo exit_delay='
          '${changeVtxos.first.exitDelay} amount=${changeVtxos.first.amount}');

      final aliceBoarding2 = await alice.getBoardingAddress();
      await btc.sendToAddress(aliceBoarding2, 0.002);
      await btc.generateToAddress(1, await btc.getNewAddress());
      final aliceUtxos2 = await pollBoardingUtxos(aliceBoarding2, 200000);
      expect(aliceUtxos2, isNotEmpty,
          reason: 'second Alice boarding deposit not seen');
      await settleBoarding(alice, aliceUtxos2);

      var mixed2 = (await alice.listVtxos()).vtxos;
      for (int i = 0; i < 30 && mixed2.length < 2; i++) {
        await Future.delayed(Duration(seconds: 2));
        mixed2 = (await alice.listVtxos()).vtxos;
      }
      for (final v in mixed2) {
        print('   vtxo ${v.txid.substring(0, 12)}.. '
            'amount=${v.amount} exit_delay=${v.exitDelay}');
      }
      final delays2 = mixed2.map((v) => v.exitDelay).toSet();
      expect(delays2.length, greaterThan(1),
          reason: 'reverse-order set must ALSO carry different exit delays');
      print('   Mixed delays confirmed (reverse order): $delays2');

      print('8. Alice sends again — first input is now the OTHER delay');
      final aliceWallet2 = MpcArkWallet(alice);
      final unsigned2 = await aliceWallet2.createTransaction(
        destination: bobArkAddr,
        amountSats: 100000,
      );
      final txid2 = await aliceWallet2
          .submit(await aliceWallet2.signTransaction(unsigned2));
      expect(txid2, isNotEmpty,
          reason: 'a mixed-delay send must succeed regardless of which delay '
              'the first input carries');
      print('   Sent across mixed delays (reverse order): $txid2');

      final wantBob = bobBalance + 100000;
      int bobBalance2 = 0;
      for (int i = 0; i < 30; i++) {
        bobBalance2 = (await bob.listVtxos()).totalBalance.toInt();
        if (bobBalance2 >= wantBob) break;
        await Future.delayed(Duration(seconds: 2));
      }
      expect(bobBalance2, greaterThanOrEqualTo(wantBob),
          reason: 'Bob should have received the reverse-order mixed send too');
      print('   Bob balance after both mixed sends: $bobBalance2');
    } finally {
      mining = false;
      miner.cancel();
    }

    print('Mixed exit-delay send complete!');
  }, timeout: Timeout(Duration(minutes: 10)));
}
