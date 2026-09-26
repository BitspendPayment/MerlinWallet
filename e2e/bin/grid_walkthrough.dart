/// The send-to-bank walkthrough: naira to a Nigerian bank through Lightspark Grid, paid back out of
/// the customer's escrow.
///
/// Alice sends ₦30,000 to a bank account. MerlinPlatform pays it first — a Grid payout, funded just
/// in time — and is reimbursed out of Alice's escrow only once the cosigner has fetched, with its
/// own read-only Grid token, both the payout and the payee's account, and found what Alice sealed.
///
/// ```text
///   GRID_VIEW_ID=… GRID_VIEW_SECRET=… dart run bin/grid_walkthrough.dart
/// ```
///
/// Expects regtest (`make regtest-ark`) and MerlinPlatform (`cargo run` in ~/MerlinPlatform, with
/// its TRANSACT token) already running. It boots the enclave itself, because the image has to name
/// the platform, Grid's origin and the VIEW token before it starts.
///
/// **Grid here is the SANDBOX.** No naira moves; the Bitcoin is regtest; every signature and
/// policy decision is the production code path.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:app_core/asp/asp_client.dart' show IndexerVtxo;
import 'package:app_core/client.dart';
import 'package:app_core/threshold_types.dart' as ark_threshold;
import 'package:e2e/boarding_poll.dart';
import 'package:e2e/enclave_harness.dart';
import 'package:e2e/escrow_service.dart' show HostSideDelivery;
import 'package:e2e/logger.dart';
import 'package:e2e/regtest_helper.dart';

/// Has to match what MerlinPlatform was started with — its `--label` and `--port`.
const platformLabel = 'merlin-platform';
const platformPort = 7200;

/// Spelled exactly as the policy's provider: the cosigner compares the two as strings.
const gridOrigin = 'https://api.lightspark.com';
const gridApi = '/grid/2025-10-13';

const fundingSats = 100000;
const amountKobo = 3000000; // ₦30,000
/// Grid's sandbox pays an account out unless its last three digits say otherwise.
const accountNumber = '0123456789';
const payeeName = 'Ada Obi';

final platformIdentifier =
    ark_threshold.Identifier.derive(Uint8List.fromList(platformLabel.codeUnits));

late final HttpClient _http = HttpClient();

Future<void> main(List<String> args) async {
  final platformBase = 'http://127.0.0.1:$platformPort';
  final viewId = Platform.environment['GRID_VIEW_ID'] ?? '';
  final viewSecret = Platform.environment['GRID_VIEW_SECRET'] ?? '';
  final viewToken = '$viewId:$viewSecret';
  if (viewId.isEmpty || viewSecret.isEmpty) {
    stderr.writeln('set GRID_VIEW_ID and GRID_VIEW_SECRET — a VIEW-only Grid sandbox token.');
    stderr.writeln('It goes into the enclave image, which the dev harness keeps in /nix/store:');
    stderr.writeln('never use a token that can TRANSACT here.');
    exit(1);
  }
  // dev-enclave.sh admits only these characters in a --guest-env value.
  if (!RegExp(r'^[A-Za-z0-9:/._-]*$').hasMatch(viewToken)) {
    stderr.writeln('the VIEW token has characters dev-enclave.sh will not pass to the guest.');
    exit(1);
  }

  _banner();
  await _requireUp(platformBase);
  final bankName =
      Platform.environment['GRID_BANK_NAME'] ?? await _firstNigerianBank(viewId, viewSecret);

  // 192.168.127.254 is this host as the guest sees it. The image names the platform (so a wallet
  // naming its id resolves to it), lets the cosigner reach Grid, and binds the VIEW token to Grid's
  // origin — so it is sent there and nowhere else.
  final platformId = _hex(platformIdentifier.serialize());
  final harness = await EnclaveHarness.start(
    serviceOrigins: '$platformId:http://192.168.127.254:$platformPort',
    extraEgress: [gridOrigin],
    extraEnv: {
      'SERVICE_CREDENTIALS_GRID': viewToken,
      'SERVICE_CREDENTIAL_ORIGIN_GRID': gridOrigin,
    },
  );
  Log.info('enclave up: pcr16=${harness.pcr16.substring(0, 16)}…');

  final btc = RegtestHelper(rpcUrl: 'http://127.0.0.1:18443/wallet/default');
  final alice = await harness.wallet('alice', aspHost: '127.0.0.1', aspPort: 7070);

  try {
    await alice.client.doDkg();

    _step(1, 'Create an escrow and pair MerlinPlatform into it');
    final escrow = await alice.client.createEscrow();
    print('  escrow key       ${escrow.escrowKeyHex}');
    await alice.client.pairService(
      escrowKeyHex: escrow.escrowKeyHex,
      serviceIdentifier: platformIdentifier,
      delivery: HostSideDelivery(),
    );
    print('  paired           ${await _awaitPaired(alice.client, escrow.escrowKeyHex)}');

    _step(2, 'Fund the escrow ($fundingSats sats)');
    final escrowAddress = await alice.client.escrowArkAddress(escrow.escrowKeyHex);
    await _fund(alice, btc, escrowAddress, fundingSats);
    final before = await _escrowSats(alice, escrow.escrowKeyHex);
    print('  the escrow holds $before sats');

    _step(3, 'Ask MerlinPlatform to send ₦${amountKobo ~/ 100} to $bankName $accountNumber');
    // Alice's app picks the tag. A tag the platform picked could be handed to two customers.
    final dealTag = _hex(List.generate(16, (_) => Random.secure().nextInt(256)));
    final quoted = (await _postJson(platformBase, '/payouts', {
      'escrow_key': escrow.escrowKeyHex,
      'account_number': accountNumber,
      'bank_name': bankName,
      'full_name': payeeName,
      'amount_kobo': amountKobo,
      'deal_tag': dealTag,
    })) as Map<String, dynamic>;
    if (quoted['error'] != null) throw StateError('no quote: ${quoted['error']}');
    final requestId = quoted['request_id'] as String;
    print('  quote            ${quoted['quote_id']}, expires ${quoted['expires_at']}');
    print('  price            ${quoted['sats']} sats — what Alice agrees to pay');
    print('  platform\'s cost  ${(quoted['grid_cost_micro_usdb'] as int) / 1e6} USDB at Grid, funded '
        'just in time; priced at ${quoted['sats_per_usd']} sats/USD');

    _step(4, 'Check the policy, then seal it');
    final policy = (quoted['policy'] as Map).cast<String, dynamic>();
    _checkPolicy(
      policy,
      accountId: quoted['external_account_id'] as String,
      dealTag: dealTag,
      bankName: bankName,
      priceSats: quoted['sats'] as int,
    );
    print('  every pinned value is what Alice asked for');
    final deadline = DateTime.now().add(const Duration(minutes: 10));
    final described = await alice.client.openEscrowSession(
      escrowKeyHex: escrow.escrowKeyHex,
      policy: policy,
      deadline: deadline,
    );
    print('  Alice agrees: $described');

    _step(5, 'MerlinPlatform checks it will be repaid, then pays');
    final funded = (await _postEmpty(platformBase, '/payouts/$requestId/fund'))
        as Map<String, dynamic>;
    if (funded['outcome'] != 'funded') throw StateError('not funded: ${jsonEncode(funded)}');
    print('  the cosigner refused only because the payout had not completed — so it paid');
    print('  payout           ${funded['transaction_id']}');

    _step(6, 'Grid pays the bank; the cosigner checks for itself; the platform is repaid');
    final done = await _awaitReimbursed(platformBase, requestId);
    print('  ark txid         ${done['ark_txid']}');
    print('  repaid           ${done['sats']} sats — the price Alice agreed');

    final after = await _escrowSats(alice, escrow.escrowKeyHex);
    if (before - after != done['sats']) {
      throw StateError('the escrow moved ${before - after} sats, not ${done['sats']}');
    }
    print('');
    print('  ' + '=' * 60);
    print('  ₦${amountKobo ~/ 100} sent to $accountNumber; the escrow paid ${before - after} sats');
    print('');
  } finally {
    await alice.close();
    await harness.stop();
  }
}

/// The app's side of the trust boundary: refuse to seal a policy that does not pin what Alice
/// asked for. `openEscrowSession` takes any map, and a platform could return `{"op":"always"}`.
void _checkPolicy(
  Map<String, dynamic> policy, {
  required String accountId,
  required String dealTag,
  required String bankName,
  required int priceSats,
}) {
  void need(bool ok, String what) {
    if (!ok) throw StateError('refusing to seal: $what\n${jsonEncode(policy)}');
  }

  need(policy['op'] == 'all_of', 'the policy is not an all_of');
  final terms = (policy['of'] as List).cast<Map<String, dynamic>>();
  const allowed = {'outputs_only_to', 'total_out_max', 'released_total_max', 'fee_max', 'http_get'};
  need(terms.every((t) => allowed.contains(t['op'])), 'it has a term Alice cannot read');
  Map<String, dynamic> term(String op) => terms.firstWhere((t) => t['op'] == op);
  // Exactly the price shown to Alice — no more may leave, in one release or in all of them.
  need(term('total_out_max')['sats'] == priceSats, 'one release may exceed the price');
  need(term('released_total_max')['sats'] == priceSats, 'the releases may exceed the price');
  need(term('fee_max')['sats'] == 0, 'the escrow may lose fees');
  need((term('outputs_only_to')['scripts'] as List).length == 1, 'it pays more than the platform');

  final gets = terms.where((t) => t['op'] == 'http_get').toList();
  need(gets.length == 2, 'it does not fetch exactly the payee and the payout');
  for (final get in gets) {
    need(get['provider'] == gridOrigin && get['credentials'] == 'GRID', 'it asks somebody else');
  }
  bool pins(Map<String, dynamic> get, String is_, String at, [Object? value]) =>
      (get['expect'] as List).any((e) =>
          e['is'] == is_ && e['at'] == at && (value == null || e['value'] == value));

  final payee = gets.firstWhere((g) => (g['path'] as String).contains('/external-accounts/'),
      orElse: () => const {});
  need(payee['path'] == '$gridApi/platform/external-accounts/$accountId', 'wrong payee record');
  need(pins(payee, 'equals', 'accountInfo.accountNumber', accountNumber), 'not this account');
  need(pins(payee, 'equals', 'accountInfo.bankName', bankName), 'not this bank');

  final payout = gets.firstWhere((g) => g['path'] == '$gridApi/transactions/{reference}',
      orElse: () => const {});
  need(payout.isNotEmpty, 'it does not fetch the payout');
  need(pins(payout, 'matches_reference', 'id'), 'the payout is not the one claimed');
  need(pins(payout, 'equals', 'description', dealTag), 'not this deal');
  need(pins(payout, 'equals', 'destination.accountId', accountId), 'not to this payee');
  need(pins(payout, 'equals', 'receivedAmount.currency.code', 'NGN'), 'not naira');
  need(pins(payout, 'at_least', 'receivedAmount.amount', amountKobo), 'not this amount');
  need(pins(payout, 'equals', 'status', 'COMPLETED'), 'not a completed payout');
}

/// Poll the platform until this payout's reimbursement is confirmed, or given up on.
Future<Map<String, dynamic>> _awaitReimbursed(String platformBase, String requestId) async {
  final deadline = DateTime.now().add(const Duration(minutes: 8));
  String? last;
  while (true) {
    final status = (await _getJson(platformBase, '/status')) as Map<String, dynamic>;
    final row = (status['reimbursements'] as List)
        .cast<Map<String, dynamic>>()
        .firstWhere((r) => r['request_id'] == requestId);
    final stage = row['stage'] as String;
    if (stage != last) {
      print('  state            $stage');
      last = stage;
    }
    if (stage == 'Release confirmed') return row;
    if (row['given_up'] == true) throw StateError('given up: ${row['last_refusal']}');
    if (DateTime.now().isAfter(deadline)) {
      throw StateError('not repaid in time; last refusal: ${row['last_refusal']}');
    }
    await Future<void>.delayed(const Duration(seconds: 3));
  }
}

/// Grid's first bank for NGN — `bankName` must be one it lists.
Future<String> _firstNigerianBank(String id, String secret) async {
  final request =
      await _http.getUrl(Uri.parse('$gridOrigin$gridApi/discoveries?country=NG&currency=NGN'));
  request.headers.set('authorization', 'Basic ${base64.encode(utf8.encode('$id:$secret'))}');
  final response = await request.close();
  final body = jsonDecode(await response.transform(utf8.decoder).join());
  if (response.statusCode != 200) throw StateError('Grid discoveries: $body');
  return ((body['data'] as List).first as Map)['bankName'] as String;
}

// ------------------------------------------------------------------------------------------------
// From card_walkthrough.dart.
// ------------------------------------------------------------------------------------------------

void _banner() {
  print('');
  print('  Merlin send-to-bank — Lightspark Grid SANDBOX, regtest Bitcoin');
  print('  ' + '=' * 60);
}

void _step(int n, String what) {
  print('');
  print('  $n. $what');
  print('  ' + '-' * 60);
}

Future<String> _awaitPaired(MpcClient client, String escrowKeyHex) async {
  final deadline = DateTime.now().add(const Duration(seconds: 30));
  while (true) {
    final listed = await client.escrowStatus();
    final row = listed.firstWhere((e) => e.escrowKey.toLowerCase() == escrowKeyHex.toLowerCase());
    if (row.serviceReady) return 'service=yes wallet=yes';
    if (DateTime.now().isAfter(deadline)) {
      throw StateError('not paired: service=${row.serviceConfirmed} wallet=${row.walletConfirmed}');
    }
    await Future<void>.delayed(const Duration(milliseconds: 250));
  }
}

Future<int> _escrowSats(Wallet alice, String escrowKeyHex) async {
  final key = escrowKeyHex.toLowerCase();
  final List<IndexerVtxo> vtxos =
      await alice.client.vtxosAtArkAddress(key.length == 66 ? key.substring(2) : key);
  return vtxos.fold<int>(0, (a, v) => a + v.amountSats);
}

/// Board, settle, and send the escrow its funding, mining while each waits on a round.
Future<void> _fund(Wallet alice, RegtestHelper btc, String escrowAddress, int sats) async {
  final boarding = await alice.client.getBoardingAddress();
  await btc.sendToAddress(boarding, 0.002);
  await btc.generateToAddress(1, await btc.getNewAddress());
  final deposits = await pollBoardingUtxos(boarding, 200000);
  if (deposits.isEmpty) throw StateError('the deposit was never indexed');
  await _whileMining(btc, () => settleBoarding(alice.client, deposits));
  await _whileMining(btc, () => alice.client.sendVtxo(escrowAddress, sats));
}

Future<T> _whileMining<T>(RegtestHelper btc, Future<T> Function() body) async {
  var mining = true;
  final miner = () async {
    while (mining) {
      await Future<void>.delayed(const Duration(seconds: 2));
      if (!mining) break;
      try {
        await btc.generateToAddress(1, await btc.getNewAddress());
      } catch (_) {}
    }
  }();
  try {
    return await body();
  } finally {
    mining = false;
    await miner;
  }
}

Future<void> _requireUp(String base) async {
  try {
    await _getJson(base, '/status');
  } catch (e) {
    stderr.writeln('MerlinPlatform is not answering at $base — `cargo run` in ~/MerlinPlatform');
    stderr.writeln('  ($e)');
    exit(1);
  }
}

/// A fresh connection per call — see card_walkthrough.dart.
Future<dynamic> _getJson(String base, String path) async {
  final request = await _http.getUrl(Uri.parse('$base$path'));
  request.persistentConnection = false;
  final response = await request.close();
  return jsonDecode(await response.transform(utf8.decoder).join());
}

Future<dynamic> _postJson(String base, String path, Map<String, dynamic> body) async {
  final request = await _http.postUrl(Uri.parse('$base$path'));
  request.persistentConnection = false;
  request.headers.contentType = ContentType.json;
  request.write(jsonEncode(body));
  final response = await request.close();
  return jsonDecode(await response.transform(utf8.decoder).join());
}

Future<dynamic> _postEmpty(String base, String path) async {
  final request = await _http.postUrl(Uri.parse('$base$path'));
  request.persistentConnection = false;
  request.contentLength = 0;
  final response = await request.close();
  return jsonDecode(await response.transform(utf8.decoder).join());
}

String _hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
