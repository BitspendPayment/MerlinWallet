/// Full MutinyNet E2E test against a deployed enclave.
///
/// Usage:
///   export MUTINYNET_FUNDER_KEY=<hex>
///   cd e2e && dart run bin/enclave_mutinynet_test.dart <enclave-url>
///
/// Example:
///   dart run bin/enclave_mutinynet_test.dart https://13.216.225.232
library;

import 'dart:async';
import 'dart:io';

import 'package:app_core/client.dart';
import 'package:app_core/bitcoin.dart';
import 'package:e2e/mutinynet_funder.dart';
import 'package:hive/hive.dart';

void main(List<String> args) async {
  if (args.isEmpty) {
    print('Usage: dart run bin/enclave_mutinynet_test.dart <enclave-url>');
    exit(1);
  }

  final baseUrl = args[0].replaceAll(RegExp(r'/+$'), '');
  final funderKey = Platform.environment['MUTINYNET_FUNDER_KEY'];
  if (funderKey == null || funderKey.isEmpty) {
    print('MUTINYNET_FUNDER_KEY env var not set.');
    exit(1);
  }

  // Allow self-signed certs for enclave
  HttpOverrides.global = _AllowAllCerts();

  final tempDir = await Directory.systemTemp.createTemp('enclave_mutiny_');
  Hive.init(tempDir.path);

  print('=== Enclave MutinyNet E2E Test ===');
  print('Enclave: $baseUrl');
  print('');

  // 1. Connect funder
  print('1. Connecting funder wallet...');
  final funder = MutinyNetFunder(funderKey);
  await funder.connect();
  final balance = await funder.getBalanceSats();
  print('   Funder: ${funder.address}');
  print('   Balance: $balance sats');
  if (balance < 20000) {
    print('   ERROR: Balance too low. Fund ${funder.address} via https://faucet.mutinynet.com');
    exit(1);
  }

  // 2. DKG
  print('2. DKG...');
  final client = MpcClient.rest(baseUrl);
  await client.doDkg();
  print('   DKG complete. userId=${client.userId?.substring(0, 16)}...');

  // 3. Init wallet
  print('3. Init wallet...');
  final wallet = MpcBitcoinWallet(client, networkName: 'signet');
  await wallet.init();
  final address = wallet.toAddress();
  print('   Address: $address');

  // 4. Fund wallet
  print('4. Funding wallet (10k sats)...');
  final fundTxid = await funder.sendToAddress(address, 10000);
  print('   Txid: $fundTxid');

  // 5. Wait for confirmation
  print('5. Waiting for MutinyNet confirmation (~30s)...');
  await funder.waitForConfirmation(fundTxid, timeoutSecs: 180);
  print('   Confirmed!');

  // 6. Sync wallet
  print('6. Syncing wallet...');
  for (var i = 0; i < 60; i++) {
    await wallet.sync();
    final utxos = await wallet.store.getUtxos();
    if (utxos.isNotEmpty) break;
    if (i % 10 == 0) print('   Waiting for indexing... (${60 - i} retries)');
    await Future.delayed(Duration(seconds: 5));
  }
  final walletBalance = await wallet.getBalance();
  print('   Balance: $walletBalance sats');

  // 7. Send back to funder
  print('7. Sending 5k sats back to funder...');
  final unsigned = await wallet.createTransaction(
    destination: funder.address,
    amount: BigInt.from(5000),
    feeRate: 1,
  );
  final signed = await wallet.signTransaction(unsigned);
  final sendTxid = await wallet.broadcast(signed);
  print('   Send txid: $sendTxid');

  // 8. Wait for send confirmation
  print('8. Waiting for send confirmation...');
  await funder.waitForConfirmation(sendTxid, timeoutSecs: 180);
  print('   Confirmed!');

  // 9. Verify balance decreased
  print('9. Verifying balance...');
  await wallet.sync();
  final newBalance = await wallet.getBalance();
  print('   New balance: $newBalance sats');

  await funder.close();
  await tempDir.delete(recursive: true);

  print('');
  print('=== Enclave MutinyNet E2E PASSED ===');
}

class _AllowAllCerts extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (cert, host, port) => true;
  }
}
