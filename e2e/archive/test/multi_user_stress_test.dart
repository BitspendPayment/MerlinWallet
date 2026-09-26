import 'dart:io';
import 'dart:async';
import 'package:test/test.dart';
import 'package:app_core/client.dart';
import 'package:app_core/bitcoin.dart';
import 'package:e2e/regtest_helper.dart';
import 'package:e2e/logger.dart';
import 'package:hive/hive.dart';

void main() {
  late RegtestHelper btc;
  late Directory tempDir;

  setUpAll(() async {
    tempDir = await Directory.systemTemp.createTemp('mpc_multi_stress_');
    Hive.init(tempDir.path);
    btc = RegtestHelper(rpcUrl: "http://127.0.0.1:18443/wallet/default");

    try {
      await btc.getNewAddress();
    } catch (e) {
      throw Exception("Bitcoind not reachable. Run 'make regtest' first: $e");
    }
  });

  tearDownAll(() async {
    try {
      await tempDir.delete(recursive: true);
    } catch (_) {}
  });

  test('Multi-User Stress Test: Concurrent DKGs and Sequential Transactions',
      () async {
    const serverUrl = 'http://127.0.0.1:7074';
    final clientA =
        MpcClient.rest(serverUrl, storageId: 'user_a_stress');
    final clientB =
        MpcClient.rest(serverUrl, storageId: 'user_b_stress');

    Log.step(2, 'Concurrent DKG — User A & User B');
    await Future.wait([
      clientA.doDkg(),
      clientB.doDkg(),
    ]);
    Log.ok('DKG complete for both users.');

    final walletA = MpcBitcoinWallet(clientA,
        networkName: 'regtest', storageId: 'user_a_wallet_stress');
    final walletB = MpcBitcoinWallet(clientB,
        networkName: 'regtest', storageId: 'user_b_wallet_stress');
    await Future.wait([walletA.init(), walletB.init()]);

    final addrA = walletA.toAddress();
    final addrB = walletB.toAddress();
    Log.info('User A: $addrA');
    Log.info('User B: $addrB');

    // Fund A
    Log.step(3, 'Funding User A');
    final minerAddr = await btc.getNewAddress();
    await btc.sendToAddress(addrA, 1.0);
    await btc.generateToAddress(1, minerAddr);

    Log.info('Syncing User A (waiting for funding)…');
    await _waitForBalance(walletA, BigInt.zero);
    Log.ok('User A balance: ${await walletA.getBalance()} sats');

    // Run 5 rounds of A -> B -> A
    for (int i = 1; i <= 5; i++) {
      Log.separator();
      Log.step(i + 3, 'Transaction Round $i');

      // A -> B
      Log.info('User A → User B (10,000 sats)');
      final txAB = await walletA.createTransaction(
          destination: addrB, amount: BigInt.from(10000), feeRate: 1);
      final hexAB = await walletA.signTransaction(txAB);
      final idAB = await walletA.broadcast(hexAB);
      Log.ok('Broadcast A→B · txid: $idAB');
      await btc.generateToAddress(1, minerAddr);

      final oldBalanceB = await walletB.getBalance();
      await _waitForBalance(walletB, oldBalanceB);
      Log.info('User B balance: ${await walletB.getBalance()} sats');

      // B -> A
      Log.info('User B → User A (5,000 sats)');
      final txBA = await walletB.createTransaction(
          destination: addrA, amount: BigInt.from(5000), feeRate: 1);
      final hexBA = await walletB.signTransaction(txBA);
      final idBA = await walletB.broadcast(hexBA);
      Log.ok('Broadcast B→A · txid: $idBA');
      await btc.generateToAddress(1, minerAddr);

      final oldBalanceA = await walletA.getBalance();
      await _waitForBalance(walletA, oldBalanceA);
      Log.info('User A balance: ${await walletA.getBalance()} sats');
    }

    Log.separator();
    Log.ok('Multi-User Stress Test complete.');
  }, timeout: Timeout(Duration(minutes: 10)));
}

Future<void> _waitForBalance(
    MpcBitcoinWallet wallet, BigInt currentBalance) async {
  int retries = 30;
  while (retries > 0) {
    try {
      await wallet.sync();
      final newBalance = await wallet.getBalance();
      if (newBalance != currentBalance) return;
    } catch (e) {
      Log.warn('_waitForBalance sync error (retries left: $retries): $e');
    }
    retries--;
    if (retries > 0) await Future.delayed(Duration(seconds: 2));
  }
  throw Exception(
      "Timeout waiting for balance change from $currentBalance sats");
}
