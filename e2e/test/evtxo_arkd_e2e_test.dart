import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:app_core/ark/ark_send.dart';
import 'package:app_core/ark_wallet.dart';
import 'package:app_core/client.dart';
import 'package:e2e/boarding_poll.dart';
import 'package:app_core/services_registry.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;
import 'package:blockchain_utils/blockchain_utils.dart';
import 'package:e2e/mock_fcm_server.dart';
import 'package:e2e/regtest_helper.dart';
import 'package:hive/hive.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

/// Full e2e (PEER model): a contract eVTXO created WITH a peer receiver, then spent
/// INDEPENDENTLY by that receiver THROUGH arkd — the cosigner co-signs the cooperative
/// leaf with its counter-share, the ASP finalizes; no forged key, no external service.
///
/// 1. Alice (author), Bob (receiver), Carol (payee) DKG.
/// 2. Alice `createEvtxoKey(receiverVk: Bob)` → refresh V onto {Bob, cosigner}; the
///    cosigner ECIES-relays BOTH of Bob's share halves into Bob's inbox.
/// 2b. Bob `fetchContractShares` → decrypts both halves → assembles his pairing share.
/// 3. Alice boards + settles → a normal Ark VTXO.
/// 4. Alice mints the eVTXO (sends to its Ark address).
/// 5. BOB independently spends the eVTXO (routing to the {Bob, cosigner} pairing actor,
///    Alice offline):
///    - allow (within limit + good arg): cosigner co-signs (gate allows) + arkd finalizes
///      → ark_txid returned, Carol credited.
///    - over-limit / bad-arg: the cosigner withholds its share → throws at sign.
///
/// Prereqs (mirrors `make e2e`): bitcoind + arkd +
/// cosigner.wasm/cosigner/ffi/contracts built. The contract wasm is handed to
/// the cosigner at eVTXO creation.

const oracleGateWasmPath =
    '../contracts/examples/oracle-gate/target/wasm32-wasip2/release/oracle_gate.wasm';
const oracleGateTemplateWasmPath =
    '../contracts/examples/oracle-gate-template/target/wasm32-wasip2/release/oracle_gate_template.wasm';
const configProviderWasmPath =
    '../contracts/examples/config-provider/target/wasm32-wasip2/release/config_provider.wasm';

class ArkdAdmin {
  final String adminUrl;
  final String publicUrl;
  ArkdAdmin({
    this.adminUrl = 'http://127.0.0.1:7071',
    this.publicUrl = 'http://127.0.0.1:7070',
  });
  Future<Map<String, dynamic>> getInfo() async {
    final resp = await http.get(Uri.parse('$publicUrl/v1/info'));
    if (resp.statusCode != 200) throw Exception('arkd info failed: ${resp.body}');
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
    final seedResp = await http.get(Uri.parse('$adminUrl/v1/admin/wallet/seed'));
    if (seedResp.statusCode != 200) throw Exception('seed failed: ${seedResp.body}');
    final seed = jsonDecode(seedResp.body)['seed'] as String;
    await http.post(Uri.parse('$adminUrl/v1/admin/wallet/create'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'seed': seed, 'password': 'password'}));
    await Future.delayed(Duration(seconds: 1));
    await http.post(Uri.parse('$adminUrl/v1/admin/wallet/unlock'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'password': 'password'}));
    await Future.delayed(Duration(seconds: 1));
  }

  Future<String> getWalletAddress() async {
    final resp = await http.get(Uri.parse('$adminUrl/v1/admin/wallet/address'));
    if (resp.statusCode != 200) throw Exception('wallet address failed: ${resp.body}');
    return jsonDecode(resp.body)['address'] as String;
  }
}

Future<Process> startCosignerRuntime(
  int port,
  Directory dataDir, {
  Map<String, String> extraEnv = const {},
}) async {
  final serverReady = Completer<void>();
  final serverFailed = Completer<void>();
  final env = {
    'ELECTRUM_URL': '127.0.0.1',
    'ELECTRUM_PORT': '50001',
    'BITCOIN_RPC_USER': 'admin1',
    'BITCOIN_RPC_PASSWORD': '123',
    'ASP_URL': 'http://127.0.0.1:7070',
    'BITCOIN_NETWORK': 'regtest',
    // Huge margin -> auto-settle threshold clamps to 0 (always crossed),
    // independent of ARKD_VTXO_TREE_EXPIRY, so stored intents fire on the
    // next 60s tick.
    'AUTO_SETTLE_SAFETY_MARGIN_SECS': '9999999999',
    'HOME': dataDir.path,
    // Per-run SQLite KV file. Same dir across restarts, so state survives a runtime
    // bounce the way the shared Redis instance used to.
    'SQLITE_PATH': '${dataDir.path}/cosigner.db',
    ...extraEnv,
  };
  final proc = await Process.start(
    '../cosigner/target/release/cosigner',
    ['--port', port.toString()],
    environment: env,
  );
  void watch(Stream<List<int>> s) {
    s.transform(utf8.decoder).listen((data) {
      print('[Server]: $data');
      if (!serverReady.isCompleted && data.contains('MPC Wallet Server listening on')) {
        serverReady.complete();
      }
    }, onDone: () {
      if (!serverReady.isCompleted && !serverFailed.isCompleted) serverFailed.complete();
    });
  }

  watch(proc.stdout);
  watch(proc.stderr);
  try {
    await Future.any([
      serverReady.future,
      serverFailed.future.then((_) => throw Exception('MPC Server failed')),
    ]).timeout(Duration(seconds: 30),
        onTimeout: () => throw Exception('MPC Server not ready in time'));
  } catch (e) {
    proc.kill();
    rethrow;
  }
  return proc;
}

void main() {
  late RegtestHelper btc;
  late ArkdAdmin arkd;
  late Directory tempDir;
  late Directory serverTempDir;
  late MockFcmServer mockFcm;
  Process? serverProcess;
  late int serverPort;

  setUpAll(() async {
    print('--- eVTXO-through-arkd E2E Setup ---');
    tempDir = await Directory.systemTemp.createTemp('mpc_evtxo_arkd_');
    Hive.init(tempDir.path);

    btc = RegtestHelper();
    try {
      await btc.createWallet('default');
    } catch (e) {
      if (!e.toString().contains('already loaded')) rethrow;
    }
    btc = RegtestHelper(rpcUrl: 'http://127.0.0.1:18443/wallet/default');
    await btc.getNewAddress();

    arkd = ArkdAdmin();
    bool ready = false;
    for (int i = 0; i < 10; i++) {
      if (await arkd.isReady()) {
        ready = true;
        break;
      }
      await Future.delayed(Duration(seconds: 3));
    }
    if (!ready) {
      await arkd.initWallet();
      await Future.delayed(Duration(seconds: 2));
    }
    try {
      final aspAddr = await arkd.getWalletAddress();
      final minerAddr = await btc.getNewAddress();
      await btc.generateToAddress(101, minerAddr);
      await btc.sendToAddress(aspAddr, 10.0);
      await btc.generateToAddress(1, minerAddr);
      await Future.delayed(Duration(seconds: 5));
    } catch (e) {
      print('  Warning: could not fund ASP: $e');
    }

    mockFcm = MockFcmServer();
    await mockFcm.start();
    const fcmTestProjectId = 'mpc-wallet-e2e-test';
    final keyPem = await File('../e2e/fixtures/fcm_test_key.pem').readAsString();
    final fcmServiceAccountJson = jsonEncode({
      'type': 'service_account',
      'project_id': fcmTestProjectId,
      'private_key_id': 'e2e-mock',
      'private_key': keyPem,
      'client_email': 'fcm-e2e@$fcmTestProjectId.iam.gserviceaccount.com',
      'token_uri': mockFcm.tokenUri,
    });

    final portSocket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    serverPort = portSocket.port;
    await portSocket.close();
    serverTempDir = await Directory.systemTemp.createTemp('mpc_evtxo_arkd_server_');
    serverProcess = await startCosignerRuntime(serverPort, serverTempDir, extraEnv: {
      'FCM_SERVICE_ACCOUNT_JSON': fcmServiceAccountJson,
      'FCM_BASE_URL': mockFcm.baseUrl,
    });
    print('--- Setup Complete (port $serverPort) ---');
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

  /// Settle Alice's boarding UTXO into a VTXO, mining blocks to trigger batches.
  Future<void> settleWithMining(MpcClient client) async {
    bool settling = true;
    final timer = Timer.periodic(Duration(seconds: 3), (t) async {
      if (!settling) {
        t.cancel();
        return;
      }
      try {
        final a = await btc.getNewAddress();
        await btc.generateToAddress(1, a);
      } catch (_) {}
    });
    try {
      final boardingUtxos = await scanBoardingFor(client);
      await settleBoarding(client, boardingUtxos);
    } finally {
      settling = false;
      timer.cancel();
    }
  }

  test('eVTXO through arkd: mint via send, arkd co-signs cooperative spend, deny over-limit/bad-arg',
      () async {
    // 1. Alice (author), Bob (the contract RECEIVER), Carol (a clean payee) DKG.
    final alice =
        MpcClient.rest('http://127.0.0.1:$serverPort', storageId: 'alice');
    await alice.doDkg();
    final bob = MpcClient.rest('http://127.0.0.1:$serverPort', storageId: 'bob');
    await bob.doDkg();
    final carol =
        MpcClient.rest('http://127.0.0.1:$serverPort', storageId: 'carol');
    await carol.doDkg();
    final carolArk = await carol.getArkAddress();
    print('1. DKG done. alice=${alice.userId?.substring(0, 12)}, bob=${bob.userId?.substring(0, 12)}');

    // 2. eVTXO bound to the oracle-gate contract, created WITH Bob as the receiver: the
    // cosigner refreshes Alice's V onto {Bob, cosigner} and drops BOTH ECIES halves of
    // Bob's share into Bob's inbox. No service, no URL.
    final arkInfo = await alice.getArkInfo();
    var serverPkHex = arkInfo.signerPubkey;
    if (serverPkHex.length == 66) serverPkHex = serverPkHex.substring(2);
    final serverPk = Uint8List.fromList(BytesUtils.fromHexString(serverPkHex));
    final exitDelay = arkInfo.unilateralExitDelay.toInt();
    // 2a. Bob PUBLISHES the oracle-gate TEMPLATE (a wasm importing a typed, self-documenting
    // `oracle:gate/config` interface) + its provider STUB + the config schema. Alice DISCOVERS it,
    // then creates a contract FROM the template with her own TYPED config: oracle-token "ORACLE-OK"
    // + a per-instance max-sats of 50_000. The cosigner synthesizes a provider from those values,
    // COMPOSES it into the template, and the composed sha256 becomes the bound contract_id.
    final dir = ContractDirectory();
    final serverUrl = 'http://127.0.0.1:$serverPort';
    final templateWasm = await File(oracleGateTemplateWasmPath).readAsBytes();
    final stubWasm = await File(configProviderWasmPath).readAsBytes();
    final templateId = Uint8List.fromList(QuickCrypto.sha256Hash(templateWasm));
    await dir.registerTemplate(
        cosignerBase: serverUrl,
        authorVkHex: bob.userId!,
        contractIdHex: BytesUtils.toHexString(templateId),
        wasm: templateWasm,
        providerStubWasm: stubWasm,
        schema: '[{"name":"oracle-token","type":"bytes"},{"name":"max-sats","type":"u64"}]',
        name: 'Oracle Gate',
        description: 'spend if oracle token matches + total ≤ max-sats');
    final rows = await dir.listContracts(serverUrl);
    final row = rows.firstWhere((r) =>
        r.authorVkHex == bob.userId! &&
        r.contractIdHex == BytesUtils.toHexString(templateId));
    expect(row.isTemplate, isTrue, reason: 'published entry carries a provider stub');
    print('2a. Bob published the "Oracle Gate" TEMPLATE; Alice discovered it (schema: ${row.schema})');

    // Phase 3 — a BACKEND subscriber (Bob, acting as a server-side service) holds an SSE event
    // stream open and reacts to cosigner events; a mobile wallet would get the same event via FCM.
    // Register Bob's device token (FCM) + open his SSE stream BEFORE Alice creates, so BOTH channels
    // are live when the contract-share event fires.
    await bob.registerDeviceToken(fcmToken: 'bob-token-e2e', platform: 'android');
    mockFcm.clearSends();
    final sseEvents = <String>[];
    final sseSub =
        bob.subscribeEvents().listen((e) => sseEvents.add(e.type), onError: (_) {});
    await Future.delayed(Duration(seconds: 2)); // let the SSE connection establish

    final configBlob = encodeContractConfig([
      ('oracle-token', CfgBytes(Uint8List.fromList(utf8.encode('ORACLE-OK')))),
      ('max-sats', CfgU64(50000)),
    ]);
    final evtxo = await alice.createEvtxoFromTemplate(
        templateId: row.contractIdHex,
        stubId: row.stubId,
        configBlob: configBlob,
        serverPk: serverPk,
        exitDelay: exitDelay,
        receiverVk: row.authorVk);
    expect(evtxo.contractId, isNotEmpty,
        reason: 'cosigner returns the COMPOSED contract id (binds the variables)');
    expect(evtxo.contractId, isNot(equals(templateId)),
        reason: 'composed contract id differs from the bare template id');

    // 2a-bis. The contract-share event fired on BOTH channels: the live backend SSE stream and
    // (for a mobile wallet) the FCM push.
    var gotSse = false;
    for (var i = 0; i < 20 && !gotSse; i++) {
      gotSse = sseEvents.contains('contract_share');
      if (!gotSse) await Future.delayed(Duration(milliseconds: 250));
    }
    expect(gotSse, isTrue,
        reason: 'backend SSE subscriber should receive a live contract_share event');
    unawaited(sseSub.cancel()); // long-lived SSE; don't block the test on teardown
    final push = await mockFcm.waitForFirstSend(timeout: Duration(seconds: 10));
    expect(push?.data?['type'], equals('contract_share'),
        reason: 'a mobile FCM push should also fire for the contract share');
    print('2a-bis. contract_share delivered to a live backend (SSE) + mobile (FCM)');
    // qEvtxo = the eVTXO's taproot OUTPUT key (the address). The cooperative multisig
    // leaf reuses the wallet's key V (no separate V′).
    final qEvtxo = Uint8List.fromList(evtxo.scriptPubkey.sublist(2));
    final vPrimeXonly = _xonlyOf(evtxo.publicKeyPackage);

    // Coop leaf key == V: the new model reuses V (no reshare).
    final vXonly = _xonlyOf(alice.getPublicKeyPackage()!);
    expect(BytesUtils.toHexString(vPrimeXonly),
        equals(BytesUtils.toHexString(vXonly)),
        reason: 'coop leaf reuses V — createEvtxoKey no longer reshares');
    print('   V (coop leaf) x-only: ${BytesUtils.toHexString(vXonly)}');

    // 2b. Bob picks up his contract share from his inbox, decrypts BOTH ECIES halves,
    // and assembles his {Bob, cosigner} pairing key package — INDEPENDENT of Alice.
    final shares = await bob.fetchContractShares();
    expect(shares, hasLength(1), reason: 'Bob should have one pending contract share');
    final share = shares.first;
    expect(BytesUtils.toHexString(_xonlyOf(share.publicKeyPackage)),
        equals(BytesUtils.toHexString(vXonly)),
        reason: 'Bob assembles a share of the SAME key V');
    expect(BytesUtils.toHexString(Uint8List.fromList(share.scriptPubkey)),
        equals(BytesUtils.toHexString(evtxo.scriptPubkey)),
        reason: 'Bob receives the share for Alice\'s eVTXO');
    await bob.ackContractShare(Uint8List.fromList(share.scriptPubkey));
    print('2b. Bob assembled his pairing share for the eVTXO');

    final evtxoArkAddr =
        arkEvtxoArkAddress(serverPk: serverPk, qEvtxo: qEvtxo, network: arkInfo.network);
    print('2. eVTXO key created; ark address=$evtxoArkAddr');

    // 3. Board + settle Alice → a normal VTXO.
    final boardingAddress = await alice.getBoardingAddress();
    final minerAddr = await btc.getNewAddress();
    await btc.sendToAddress(boardingAddress, 0.01); // 1,000,000 sats
    await btc.generateToAddress(1, minerAddr);
    await Future.delayed(Duration(seconds: 5));
    await settleWithMining(alice);
    final afterSettle = await alice.listVtxos();
    expect(afterSettle.vtxos, isNotEmpty, reason: 'Alice should hold a VTXO after settle');
    print('3. Settled. Alice balance=${afterSettle.totalBalance}');

    // 4. Mint the eVTXO: send to its Ark address → arkd tracks a VTXO at Q_evtxo.
    // The contract gate runs on the CHECKPOINT PSBT, whose single output forwards the FULL eVTXO
    // value into the Ark layer — so the contract's max-sats effectively caps the eVTXO denomination.
    // Here max-sats is the PER-INSTANCE 50_000 Alice supplied (NOT any hardcoded template value):
    // mint a 40k one (under → allow) and a 60k one (over → deny).
    final wallet = MpcArkWallet(alice);
    Future<String> mint(int sats) async {
      final u = await wallet.createTransaction(destination: evtxoArkAddr, amountSats: sats);
      final s = await wallet.signTransaction(u);
      final txid = await wallet.submit(s);
      expect(txid, isNotEmpty, reason: 'mint send should return an ark_txid');
      await Future.delayed(Duration(seconds: 2));
      return txid; // recipient (eVTXO) is output 0; change is output 1
    }

    final mint40 = await mint(40000);
    final mint60 = await mint(60000);
    print('4. Minted eVTXOs: $mint40:0 (40k), $mint60:0 (60k)');

    // 5. BOB — using only his assembled pairing share — INDEPENDENTLY spends the eVTXO.
    // His spend routes to the {Bob, cosigner} pairing actor (keyed by the eVTXO spk); the
    // cosigner co-signs with its counter-share C (and gates the spend), with Alice OFFLINE.
    final bobWallet = MpcArkWallet(bob);
    final spkRoute =
        BytesUtils.toHexString(Uint8List.fromList(share.scriptPubkey));
    Future<UnsignedArkTransaction> buildSpend(
            String txid, int inAmt, String args) =>
        bobWallet.createEvtxoSpend(
          destination: carolArk,
          amountSats: 25000,
          inputTxid: txid,
          inputVout: 0,
          inputAmountSats: inAmt,
          contractId: Uint8List.fromList(share.contractId),
          evtxoPk: vPrimeXonly,
          exitDelay: share.exitDelay,
          ownerPkOverride:
              BytesUtils.toHexString(Uint8List.fromList(share.ownerPk)),
          contractArgs: Uint8List.fromList(utf8.encode(args)),
        );

    // 5a. DENY (over per-instance limit): the 60k eVTXO exceeds the composed-in max-sats=50k. The
    // gate fires at sign time (before submit), so the input needn't be unspent.
    await _expectDenied(
        () async => bobWallet.signEvtxoSpend(await buildSpend(mint60, 60000, 'ORACLE-OK'),
            evtxoKeyPkg: share.keyPackage, evtxoPkp: share.publicKeyPackage,
            routeGroupKeyHex: spkRoute),
        'over-limit');
    print('5a. DENY over per-instance limit: cosigner refused (gate)');

    // 5b. DENY (bad arg): wrong oracle token on the 40k eVTXO.
    await _expectDenied(
        () async => bobWallet.signEvtxoSpend(await buildSpend(mint40, 40000, 'WRONG-TOKEN'),
            evtxoKeyPkg: share.keyPackage, evtxoPkp: share.publicKeyPackage,
            routeGroupKeyHex: spkRoute),
        'bad-arg');
    print('5b. DENY bad-arg: cosigner refused (gate)');

    // 5c. ALLOW — 40k eVTXO (≤ per-instance 50k) + good arg: the cosigner co-signs Bob's
    // independent spend with its counter-share, arkd finalizes the cooperative spend.
    final allowSigned = await bobWallet.signEvtxoSpend(
        await buildSpend(mint40, 40000, 'ORACLE-OK'),
        evtxoKeyPkg: share.keyPackage,
        evtxoPkp: share.publicKeyPackage,
        routeGroupKeyHex: spkRoute);
    final spendArkTxid = await bobWallet.submit(allowSigned);
    expect(spendArkTxid, isNotEmpty,
        reason: 'cosigner+arkd must co-sign Bob\'s independent eVTXO spend');
    print('5c. ALLOW: cosigner co-signed Bob\'s independent eVTXO spend, ark_txid=$spendArkTxid');

    // Carol credited by Bob's eVTXO spend (proves the peer off-chain transfer landed).
    int carolBalance = 0;
    for (int i = 0; i < 10; i++) {
      carolBalance = (await carol.listVtxos()).totalBalance.toInt();
      if (carolBalance >= 25000) break;
      await Future.delayed(Duration(seconds: 1));
    }
    expect(carolBalance, equals(25000),
        reason: 'Carol should receive 25000 sats from Bob\'s independent eVTXO spend');

    print('eVTXO-through-arkd E2E complete (Phase 2): template+typed-config composed; Bob '
        'independently spent (allow); over per-instance-limit + bad-arg refused.');
  }, timeout: Timeout(Duration(minutes: 12)));
}

/// x-only (32-byte) public key from a FROST group public key package (V′).
Uint8List _xonlyOf(threshold.PublicKeyPackage pkp) {
  final compressed = threshold.elemSerializeCompressed(pkp.verifyingKey.E);
  return Uint8List.fromList(compressed.sublist(1));
}

Future<void> _expectDenied(Future<void> Function() op, String because) async {
  try {
    await op();
    fail('cosigner should have refused ($because)');
  } catch (e) {
    print('   denied as expected ($because): $e');
    expect(e.toString().toLowerCase(), contains('deni'),
        reason: 'expected a contract permission-denied error, got: $e');
  }
}
