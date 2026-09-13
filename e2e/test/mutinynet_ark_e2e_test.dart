/// MutinyNet (signet) Ark integration test.
///
/// Prerequisites:
///   1. Generate funder key: cd e2e && dart run bin/gen_funder_key.dart
///   2. Export: MUTINYNET_FUNDER_KEY=<hex>
///   3. Fund the funder's tb1p... address via https://faucet.mutinynet.com
///   4. Build: make ffi-build cosigner-build runtime-build signer-build
///   5. Run:  make e2e-mutinynet-ark
///
/// The test:
///   - Starts MPC server pointed at mutinynet.com Electrum + public ASP
///   - Alice: DKG, get boarding address, fund, settle (board into Ark)
///   - Verify VTXOs
///   - Bob: DKG, get Ark address
///   - Alice sends off-chain to Bob
///   - Verify balances
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:app_core/ark_wallet.dart';
import 'package:app_core/client.dart';
import 'package:e2e/boarding_poll.dart';
import 'package:e2e/mutinynet_funder.dart';
import 'package:e2e/logger.dart';
import 'package:hive/hive.dart';

const _aspUrl = 'https://mutinynet.arkade.sh';

void main() {
  Process? serverProcess;
  late MutinyNetFunder funder;
  late Directory tempDir;
  late Directory serverTempDir;
  late int serverPort;

  setUpAll(() async {
    Log.header('MutinyNet Ark E2E Setup');

    // 0. Validate env
    final funderKey = Platform.environment['MUTINYNET_FUNDER_KEY'];
    if (funderKey == null || funderKey.isEmpty) {
      throw Exception(
          'MUTINYNET_FUNDER_KEY env var not set. '
          'Run: cd e2e && dart run bin/gen_funder_key.dart');
    }

    // 1. Hive init
    tempDir = await Directory.systemTemp.createTemp('mpc_mutinynet_ark_e2e_');
    Hive.init(tempDir.path);

    // 2. Connect funder to MutinyNet Electrum
    funder = MutinyNetFunder(funderKey);
    await funder.connect();
    final balance = await funder.getBalanceSats();
    Log.info('Funder address: ${funder.address}');
    Log.info('Funder balance: $balance sats');
    if (balance < 20000) {
      throw Exception(
          'Funder balance too low ($balance sats). '
          'Fund ${funder.address} with at least 20,000 sats via '
          'https://faucet.mutinynet.com');
    }
    Log.ok('Funder wallet ready.');

    // 3. Start MPC server pointed at MutinyNet + public ASP
    Log.info('Starting MPC Server (MutinyNet + Ark)...');
    final portSocket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    serverPort = portSocket.port;
    await portSocket.close();
    serverTempDir = await Directory.systemTemp.createTemp('mpc_server_mutinynet_ark_');

    final serverReady = Completer<void>();
    final serverFailed = Completer<void>();
    serverProcess = await Process.start(
      '../cosigner/target/release/cosigner',
      [
        '--port', serverPort.toString(),
      ],
      mode: ProcessStartMode.normal,
      environment: {
        'ELECTRUM_URL': 'electrum.mutinynet.com',
        'ELECTRUM_PORT': '50001',
        'BITCOIN_NETWORK': 'signet',
        'ASP_URL': _aspUrl,
        'HOME': serverTempDir.path,
        // Per-run SQLite KV file. Same dir across restarts, so state survives a runtime
        // bounce the way the shared Redis instance used to.
        'STORE_DIR': '${serverTempDir.path}/store',
      },
    );

    final outputBuffer = StringBuffer();
    void handleOutput(String data) {
      outputBuffer.write(data);
      Log.server(data);
      if (!serverReady.isCompleted &&
          outputBuffer.toString().contains('MPC Wallet Server listening on')) {
        serverReady.complete();
      }
    }

    serverProcess!.stdout.transform(utf8.decoder).listen(handleOutput,
        onDone: () {
      if (!serverReady.isCompleted && !serverFailed.isCompleted) {
        serverFailed.complete();
      }
    });
    serverProcess!.stderr.transform(utf8.decoder).listen(handleOutput,
        onDone: () {
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
      serverProcess?.kill();
      rethrow;
    }
    Log.ok('MPC Server ready on port $serverPort (ASP: $_aspUrl)');
    Log.separator();
  });

  tearDownAll(() async {
    serverProcess?.kill();
    await funder.close();
    try {
      await serverTempDir.delete(recursive: true);
    } catch (_) {}
    try {
      await tempDir.delete(recursive: true);
    } catch (_) {}
  });

  test('MutinyNet Ark: Board + Send', () async {
    // 1. Alice DKG
    Log.step(1, 'Alice DKG');
    final alice = MpcClient.rest('http://127.0.0.1:$serverPort', storageId: "alice_mutinynet_ark");
    await alice.doDkg();
    Log.ok('Alice DKG complete.');

    // 2. Get Ark info from public ASP
    Log.step(2, 'Get Ark Info');
    final arkInfo = await alice.getArkInfo();
    Log.info('network=${arkInfo.network}');
    Log.info('signerPubkey=${arkInfo.signerPubkey.substring(0, 16)}...');
    Log.info('boardingExitDelay=${arkInfo.boardingExitDelay}');
    expect(arkInfo.signerPubkey, isNotEmpty);
    expect(arkInfo.network, isNotEmpty);

    // 3. Get Ark address
    Log.step(3, 'Get Ark Address');
    final arkAddress = await alice.getArkAddress();
    Log.info('Ark address: $arkAddress');
    expect(
      arkAddress.startsWith('ark1') || arkAddress.startsWith('tark1'),
      isTrue,
      reason: 'Ark address should start with ark1 or tark1, got: $arkAddress',
    );

    // 4. Get boarding address
    Log.step(4, 'Get Boarding Address');
    final boardingAddress = await alice.getBoardingAddress();
    Log.info('Boarding address: $boardingAddress');
    expect(boardingAddress.startsWith('tb1p'), isTrue,
        reason: 'Boarding address should be signet P2TR, got: $boardingAddress');

    // 5. Fund boarding address from funder
    Log.step(5, 'Fund Boarding Address');
    const fundAmountSats = 10000;
    Log.info('Sending $fundAmountSats sats to boarding address...');
    final fundTxid = await funder.sendToAddress(boardingAddress, fundAmountSats);
    Log.ok('Funding txid: $fundTxid');

    // 6. Wait for confirmation
    Log.step(6, 'Waiting for Funding Confirmation');
    Log.info('Waiting for MutinyNet block (~30s)...');
    await funder.waitForConfirmation(fundTxid, timeoutSecs: 180);
    Log.ok('Funding confirmed on MutinyNet.');

    // 7. Settle (board into Ark)
    Log.step(7, 'Settle (Board into Ark)');
    Log.info('Calling settle() — waiting for ASP batch round...');
    final boardingUtxos = await pollBoardingUtxos(
        await alice.getBoardingAddress(), 1,
        host: 'mutinynet.com', port: 50001);
    final commitmentTxid = await settleBoarding(alice, boardingUtxos);
    Log.ok('Settled! commitment_txid=$commitmentTxid');
    expect(commitmentTxid, isNotEmpty);

    // 8. Verify VTXOs after settle
    Log.step(8, 'Verify VTXOs after settle');
    final vtxosResp = await alice.listVtxos();
    final aliceBalanceAfterSettle = vtxosResp.totalBalance.toInt();
    Log.info('VTXOs: ${vtxosResp.vtxos.length}, balance: $aliceBalanceAfterSettle');
    expect(vtxosResp.vtxos.length, equals(1),
        reason: 'Alice should have exactly 1 VTXO after settle');
    expect(aliceBalanceAfterSettle, equals(fundAmountSats),
        reason: 'Alice balance should equal funded amount');
    expect(vtxosResp.vtxos.first.exitDelay, greaterThan(0),
        reason: 'exit_delay must not be 0');
    expect(vtxosResp.vtxos.first.script, isNotEmpty,
        reason: 'VTXO script must be populated');
    Log.ok('Alice: 1 VTXO, balance=$aliceBalanceAfterSettle, exit_delay=${vtxosResp.vtxos.first.exitDelay}');

    // 9. Bob DKG
    Log.step(9, 'Bob DKG');
    final bob = MpcClient.rest('http://127.0.0.1:$serverPort', storageId: 'bob_mutinynet_ark');
    await bob.doDkg();
    final bobArkAddress = await bob.getArkAddress();
    Log.ok('Bob Ark address: $bobArkAddress');

    // 10. Alice sends off-chain to Bob
    Log.step(10, 'Alice sends to Bob (off-chain)');
    const sendAmount = 3000;
    final aliceArkWallet = MpcArkWallet(alice);
    final unsigned = await aliceArkWallet.createTransaction(
      destination: bobArkAddress,
      amountSats: sendAmount,
    );
    Log.info('Built tx: ${unsigned.sighashes.length} sighashes');
    final signed = await aliceArkWallet.signTransaction(unsigned);
    final arkTxid = await aliceArkWallet.submit(signed);
    Log.ok('Send ark_txid: $arkTxid');
    expect(arkTxid, isNotEmpty);

    // 11. Verify Alice's change balance
    Log.step(11, 'Verify Alice change');
    final aliceAfterSend = await alice.listVtxos();
    final aliceChange = aliceAfterSend.totalBalance.toInt();
    Log.info('Alice: ${aliceAfterSend.vtxos.length} VTXOs, balance=$aliceChange');
    expect(aliceChange, equals(aliceBalanceAfterSettle - sendAmount),
        reason: 'Alice should have exactly ${aliceBalanceAfterSettle - sendAmount} sats remaining');
    // Verify change VTXO has non-empty script
    for (final vtxo in aliceAfterSend.vtxos) {
      expect(vtxo.script, isNotEmpty, reason: 'Change VTXO must have a script');
    }

    // 12. Verify Bob received
    Log.step(12, 'Verify Bob received');
    // Poll — indexer subscription may take a moment
    int bobBalance = 0;
    for (int i = 0; i < 15; i++) {
      final resp = await bob.listVtxos();
      bobBalance = resp.totalBalance.toInt();
      if (bobBalance > 0) break;
      Log.info('Waiting for Bob VTXO... (${i + 1}/15)');
      await Future.delayed(Duration(seconds: 1));
    }
    Log.info('Bob: balance=$bobBalance');
    expect(bobBalance, equals(sendAmount),
        reason: 'Bob should have received exactly $sendAmount sats');

    Log.separator();
    Log.ok('MutinyNet Ark E2E test passed!');
  }, timeout: Timeout(Duration(minutes: 15)));
}
