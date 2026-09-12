/// MutinyNet (signet) Bitcoin integration test.
///
/// Prerequisites:
///   1. Generate funder key: cd e2e && dart run bin/gen_funder_key.dart
///   2. Export: MUTINYNET_FUNDER_KEY=<hex>
///   3. Fund the funder's tb1p... address via https://faucet.mutinynet.com
///   4. Build: make ffi-build cosigner-build runtime-build
///   5. Run:  make e2e-mutinynet
///
/// The test:
///   - Starts the MPC server pointed at mutinynet.com Electrum
///   - Runs DKG to create an MPC wallet
///   - Funder sends 100k sats to the MPC wallet
///   - Waits for MutinyNet confirmation (~30s)
///   - MPC wallet signs and sends 50k sats back to funder
///   - Verifies balance decreased
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:app_core/client.dart';
import 'package:app_core/bitcoin.dart';
import 'package:e2e/mutinynet_funder.dart';
import 'package:e2e/logger.dart';
import 'package:hive/hive.dart';

void main() {
  Process? serverProcess;
  late MutinyNetFunder funder;
  late Directory tempDir;
  late Directory serverTempDir;
  late int serverPort;

  setUpAll(() async {
    Log.header('MutinyNet E2E Setup');

    // 0. Validate env
    final funderKey = Platform.environment['MUTINYNET_FUNDER_KEY'];
    if (funderKey == null || funderKey.isEmpty) {
      throw Exception(
          'MUTINYNET_FUNDER_KEY env var not set. '
          'Run: cd e2e && dart run bin/gen_funder_key.dart');
    }

    // 1. Hive init
    tempDir = await Directory.systemTemp.createTemp('mpc_mutinynet_e2e_');
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

    // 3. Start MPC server pointed at MutinyNet
    Log.info('Starting MPC Server (MutinyNet)...');
    final portSocket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    serverPort = portSocket.port;
    await portSocket.close();
    serverTempDir = await Directory.systemTemp.createTemp('mpc_server_mutinynet_');

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
        'HOME': serverTempDir.path,
        // Per-run SQLite KV file. Same dir across restarts, so state survives a runtime
        // bounce the way the shared Redis instance used to.
        'SQLITE_PATH': '${serverTempDir.path}/cosigner.db',
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
    Log.ok('MPC Server ready on port $serverPort');
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

  test('MutinyNet: DKG + Fund + Send', () async {
    // 1. MPC Setup
    Log.step(1, 'MPC Setup (DKG)');
    final client = MpcClient.rest('http://127.0.0.1:$serverPort');
    await client.doDkg();
    Log.ok('DKG complete.');

    // 2. Init Wallet
    Log.step(2, 'Init Wallet');
    final wallet = MpcBitcoinWallet(client, networkName: 'signet');
    await wallet.init();
    final walletAddress = wallet.toAddress();
    Log.info('MPC wallet address: $walletAddress');
    expect(walletAddress.startsWith('tb1p'), isTrue,
        reason: 'Signet P2TR address should start with tb1p');

    // 3. Fund from funder wallet
    Log.step(3, 'Funding MPC Wallet');
    const fundAmountSats = 10000; // 10k sats -- keep small to preserve funder balance
    Log.info('Sending $fundAmountSats sats from funder to MPC wallet...');
    final fundTxid = await funder.sendToAddress(walletAddress, fundAmountSats);
    Log.ok('Funding txid: $fundTxid');

    // 4. Wait for confirmation (~30-60s on MutinyNet)
    Log.step(4, 'Waiting for Confirmation');
    Log.info('Waiting for MutinyNet block (~30s)...');
    await funder.waitForConfirmation(fundTxid, timeoutSecs: 180);
    Log.ok('Funding transaction confirmed.');

    // 5. Sync wallet
    Log.step(5, 'Syncing Wallet');
    bool synced = false;
    for (var i = 0; i < 60; i++) {
      await wallet.sync();
      final utxos = await wallet.store.getUtxos();
      if (utxos.isNotEmpty) {
        synced = true;
        break;
      }
      Log.info('Waiting for Electrum indexing... (${60 - i} retries left)');
      await Future.delayed(Duration(seconds: 5));
    }
    expect(synced, isTrue, reason: 'Wallet should have synced UTXOs');
    final balance = await wallet.getBalance();
    Log.ok('Wallet balance: $balance sats');
    expect(balance, greaterThan(BigInt.zero));

    // 6. Send back to funder (proves MPC signing works on signet)
    Log.step(6, 'MPC Send');
    const sendAmountSats = 5000; // send half back to funder
    Log.info('Sending $sendAmountSats sats back to funder...');
    final unsigned = await wallet.createTransaction(
      destination: funder.address,
      amount: BigInt.from(sendAmountSats),
      feeRate: 1,
    );
    final signed = await wallet.signTransaction(unsigned);
    final sendTxid = await wallet.broadcast(signed);
    Log.ok('Send txid: $sendTxid');

    // 7. Wait for send confirmation
    Log.step(7, 'Waiting for Send Confirmation');
    await funder.waitForConfirmation(sendTxid, timeoutSecs: 180);
    Log.ok('Send transaction confirmed.');

    // 8. Verify balance decreased
    Log.step(8, 'Verify Final Balance');
    // Sync again to pick up change UTXO
    for (var i = 0; i < 30; i++) {
      await wallet.sync();
      final utxos = await wallet.store.getUtxos();
      final hasChange = utxos.any((u) => u.utxo.txHash == sendTxid);
      if (hasChange) break;
      await Future.delayed(Duration(seconds: 5));
    }
    final newBalance = await wallet.getBalance();
    Log.ok('New balance: $newBalance sats');
    expect(newBalance, lessThan(balance),
        reason: 'Balance should have decreased after send');
    expect(newBalance, greaterThan(BigInt.zero),
        reason: 'Should have change remaining');

    Log.separator();
    Log.ok('MutinyNet E2E test passed!');
  }, timeout: Timeout(Duration(minutes: 10)));
}
