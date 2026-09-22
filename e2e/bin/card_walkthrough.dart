/// The card-escrow walkthrough, end to end and visible.
///
/// Alice commits Bitcoin to an escrow for card spending, buys a $20 coffee, and the card
/// programme's settlement service is reimbursed out of the escrow — but only after the cosigner
/// has verified, for itself, that the purchase actually cleared.
///
/// ```text
///   dart run bin/card_walkthrough.dart
/// ```
///
/// Expects the mock provider and the settlement service already running; see
/// `examples/card-escrow/README.md` for the exact commands. It boots the enclave itself, because
/// the image has to name the service before it starts.
///
/// **Every card payment here is simulated.** The Bitcoin is real regtest Bitcoin and every
/// signature, policy decision and Ark transaction is the production code path.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:app_core/asp/asp_client.dart' show IndexerVtxo;
import 'package:app_core/client.dart';
import 'package:app_core/threshold_types.dart' as ark_threshold;
import 'package:e2e/boarding_poll.dart';
import 'package:e2e/enclave_harness.dart';
import 'package:e2e/escrow_service.dart' show HostSideDelivery;
import 'package:e2e/logger.dart';
import 'package:e2e/regtest_helper.dart';

/// Has to match what the service was started with: the enclave's image resolves this label to the
/// service's origin, and a service it cannot name it cannot pair with.
const serviceLabel = 'merlin-e2e-escrow-service';
const servicePort = 7099;
const providerPort = 7100;

/// The terms, from `examples/card-escrow/src/policy.rs`. Test-only values.
const fundingSats = 100000;
const allowanceSats = 80000;
const purchaseCents = 2000;
const satsPerUsd = 1000;
const reimbursementSats = purchaseCents * satsPerUsd ~/ 100;

final serviceIdentifier =
    ark_threshold.Identifier.derive(Uint8List.fromList(serviceLabel.codeUnits));

late final HttpClient _http = HttpClient();

Future<void> main(List<String> args) async {
  final serviceBase = 'http://127.0.0.1:$servicePort';
  final providerBase = 'http://127.0.0.1:$providerPort';

  _banner();
  await _requireUp(serviceBase, 'the settlement service');
  await _requireUp(providerBase, 'the mock provider', path: '/simulate/ledger');

  // 192.168.127.254 is this host as the guest sees it. The image must name BOTH the service (so a
  // wallet naming its id resolves to it) and the provider (so the cosigner may dial it) — and the
  // credential must be bound to the provider's origin, or it will not be sent.
  final serviceId = _hex(serviceIdentifier.serialize());
  final origins = '$serviceId:http://192.168.127.254:$servicePort';

  final harness = await EnclaveHarness.start(
    serviceOrigins: origins,
    extraEgress: ['http://192.168.127.254:$providerPort'],
    extraEnv: {
      'SERVICE_CREDENTIALS_MOCKPROVIDER': 'demo-read-key:',
      'SERVICE_CREDENTIAL_ORIGIN_MOCKPROVIDER': 'http://192.168.127.254:$providerPort',
    },
  );
  Log.info('enclave up: pcr16=${harness.pcr16.substring(0, 16)}…');

  final btc = RegtestHelper(rpcUrl: 'http://127.0.0.1:18443/wallet/default');
  final alice = await harness.wallet('alice', aspHost: '127.0.0.1', aspPort: 7070);

  try {
    await alice.client.doDkg();

    // ---- 1. create and pair the escrow --------------------------------------------------------
    _step(1, 'Create and pair escrow');
    final escrow = await alice.client.createEscrow();
    print('  escrow key       ${escrow.escrowKeyHex}');
    final pairing = await alice.client.pairService(
      escrowKeyHex: escrow.escrowKeyHex,
      serviceIdentifier: serviceIdentifier,
      delivery: HostSideDelivery(),
    );
    print('  cosigner delivered its half over the runtime-held stream');
    print('  wallet delivered its own half straight to ${pairing.serviceOrigin}');
    final ready = await _awaitPaired(alice.client, escrow.escrowKeyHex);
    print('  both parties confirmed: $ready');
    _state('Paired');

    // ---- fund it -------------------------------------------------------------------------------
    _step(0, 'Fund the escrow ($fundingSats sats)');
    final escrowAddress = await alice.client.escrowArkAddress(escrow.escrowKeyHex);
    print('  escrow is paid at $escrowAddress');
    await _fund(alice, btc, escrowAddress, fundingSats);
    print('  funded: $fundingSats sats');

    // ---- 2. commit the policy -------------------------------------------------------------------
    _step(2, 'Commit spending policy');
    final policy = await _policy(serviceBase);
    // Short, because step 8 waits it out — which is the only way a deal ends.
    final deadline = DateTime.now().add(const Duration(seconds: 90));
    final described = await alice.client.openEscrowSession(
      escrowKeyHex: escrow.escrowKeyHex,
      policy: policy,
      deadline: deadline,
    );
    print('  the deal runs until ${deadline.toLocal()}, and cannot be ended early');
    print('  Alice agrees: $described');
    await _post(serviceBase, '/escrow/active/${escrow.escrowKeyHex}');
    _state('Escrow active');

    // ---- 3. simulate the card authorization ------------------------------------------------------
    _step(3, 'Simulate a \$20.00 card authorization  [SIMULATED]');
    final authorized = await _postJson(serviceBase, '/card/authorize', {
      'escrow_key': escrow.escrowKeyHex,
      'amount_minor': purchaseCents,
      'currency': 'USD',
    });
    final requestId = authorized['request_id'] as String;
    print('  authorization    ${authorized['authorization']}   (a HOLD — not a payment)');
    print('  worth on clearing ${authorized['sats_when_cleared']} sats at $satsPerUsd sats/USD');
    _state('Card authorized');

    // ---- 4. ask before it has cleared -------------------------------------------------------------
    _step(4, 'Request reimbursement BEFORE clearing');
    print('  a settlement service would not ask yet — money is owed on the clearing,');
    print('  and a hold can still expire or be reversed. So we ask badly on purpose,');
    print('  naming the AUTHORIZATION, to see what the cosigner does with it.');
    final early = await _postEmpty(serviceBase, '/reimburse/$requestId?against=authorization');
    print('  → ${early['outcome']}: ${early['reason'] ?? ''}');
    _moved(false);

    // ---- 5. simulate clearing ----------------------------------------------------------------------
    _step(5, 'Simulate clearing  [SIMULATED]');
    final cleared = await _postEmpty(serviceBase, '/card/clear/$requestId');
    print('  clearing         ${cleared['clearing']}   (a NEW record)');
    print('  settles          ${cleared['authorization']}');
    _state('Card cleared');

    // ---- 5b. break the connection ---------------------------------------------------------------
    _step(0, 'Drop the connection the enclave is holding');
    final dropped = await _postEmpty(serviceBase, '/connections/drop');
    print('  dropped          ${dropped['dropped']} held connection(s)');
    final rightAfter = await _getJson(serviceBase, '/connections');
    print('  held now         ${(rightAfter['held'] as List).length}   ← nothing');
    print('  the service cannot dial the enclave — it has no passkey and never will.');
    print('  the RUNTIME re-dials, on a backoff of 1s growing to 5m. The work owed');
    print('  is not lost with the socket: the ask waits for the connection to return.');
    _state('Card cleared  (waiting on a reconnect)');

    // ---- 6. ask again ------------------------------------------------------------------------------
    _step(6, 'Request reimbursement again, across the reconnect');
    print('  the service claims: payment ${cleared['clearing']}, $reimbursementSats sats');
    print('  the cosigner fetches, itself, from the provider its IMAGE names,');
    print('  with a read-only credential bound to that origin — and checks six things.');
    final began = DateTime.now();
    final paid = await _reimburseUntilSettled(serviceBase, requestId);
    final waited = DateTime.now().difference(began);
    final backAgain = await _getJson(serviceBase, '/connections');
    print('  held now         ${(backAgain['held'] as List).length}   ← the runtime re-dialled');
    print('  the ask took     ${waited.inMilliseconds}ms, most of it waiting for that');
    if (paid['outcome'] != 'confirmed') {
      print('  → ${paid['outcome']}: ${paid['reason']}');
      throw StateError('the release was not signed: ${jsonEncode(paid)}');
    }
    _state('Evidence verified → Release signed');

    // ---- 7. the outcome ----------------------------------------------------------------------------
    _step(7, 'Submit and confirm');
    print('  ark txid         ${paid['ark_txid']}');
    print('  reimbursed       ${paid['sats']} sats');
    _state('Release confirmed');
    _moved(true);

    // ---- 8. close and reclaim -------------------------------------------------------------------------
    _step(8, 'Wait out the deal, and reclaim what is left');
    print('  a deal has no ending but its deadline. Alice cannot cut it short —');
    print('  a commitment she could revoke would leave the card programme,');
    print('  which has already paid the merchant, holding the loss.');
    await _untilPast(deadline);
    print('  the deadline passed; nothing ran, and nothing was written');
    print('  the service may take no more; Alice may take back what is left');
    final left = await _escrowVtxos(alice, escrow.escrowKeyHex);
    final leftSats = left.fold<int>(0, (a, v) => a + v.amountSats);
    print('  the escrow still holds $leftSats sats');
    final reclaimed = await alice.client.reclaimEscrow(
      escrowKeyHex: escrow.escrowKeyHex,
      vtxos: left,
    );
    print('  reclaimed        ${reclaimed.amountSats} sats');
    print(
        '  to               ${reclaimed.toArkAddress}   (derived by the cosigner, not asked for)');
    print('  ark txid         ${reclaimed.arkTxid}');

    _summary(fundingSats, reimbursementSats, reclaimed.amountSats);
  } finally {
    await alice.close();
    await harness.stop();
  }
}

// ------------------------------------------------------------------------------------------------
// The narration. The point of the walkthrough is that you can see what each party knew.
// ------------------------------------------------------------------------------------------------

void _banner() {
  print('');
  print('  Merlin card escrow — a worked example');
  print('  ' + '=' * 60);
  print('  Card payments below are SIMULATED. No card network is involved and');
  print('  no real money moves on the payments side. The Bitcoin is regtest, and');
  print('  every signature and policy decision is the production code path.');
  print('');
}

void _step(int n, String what) {
  print('');
  print('  ${n == 0 ? '  ' : '$n.'} $what');
  print('  ' + '-' * 60);
}

void _state(String stage) => print('  state            $stage');

void _moved(bool did) => print('  funds moved      ${did ? 'YES' : 'no — nothing was signed'}');

void _summary(int funded, int reimbursed, int reclaimed) {
  print('');
  print('  ' + '=' * 60);
  print('  funded      $funded sats');
  print('  reimbursed  $reimbursed sats   → the service, on verified evidence');
  print('  reclaimed   $reclaimed sats   → Alice, once the deal was over');
  print('  allowance   $allowanceSats sats was the cap; $reimbursed was used');
  print('');
}

// ------------------------------------------------------------------------------------------------

/// The policy, built by the service from the shared terms so the demo and the code agree.
Future<Map<String, dynamic>> _policy(String serviceBase) async {
  final body = await _getJson(serviceBase, '/policy');
  return (body as Map).cast<String, dynamic>();
}

/// Ask, and keep asking while the answer is "the enclave is not connected".
///
/// Exactly what the service's own retry loop does — done here too so the walkthrough shows the
/// recovery rather than waiting silently through it. A repeat is safe because the request id does
/// not change: the cosigner answers it by signing again and charging nothing.
Future<Map<String, dynamic>> _reimburseUntilSettled(String serviceBase, String requestId) async {
  final deadline = DateTime.now().add(const Duration(seconds: 90));
  var waited = false;
  while (true) {
    final answer = (await _postEmpty(serviceBase, '/reimburse/$requestId')) as Map<String, dynamic>;
    final reason = (answer['reason'] ?? '').toString();
    final transient = answer['outcome'] == 'failed' &&
        (reason.contains('not been connected') || reason.contains('already running'));
    if (!transient) {
      if (waited) print('  the connection came back, and the work was still owed.');
      return answer;
    }
    if (!waited) {
      print('  waiting for the runtime to re-dial…');
      waited = true;
    }
    if (DateTime.now().isAfter(deadline)) return answer;
    await Future<void>.delayed(const Duration(seconds: 2));
  }
}

/// Wait until the clock is past [deadline], with a second to spare.
Future<void> _untilPast(DateTime deadline) async {
  final remaining = deadline.difference(DateTime.now());
  if (remaining.isNegative) return;
  print('  waiting ${remaining.inSeconds + 1}s for the deadline…');
  await Future<void>.delayed(remaining + const Duration(seconds: 1));
}

Future<String> _awaitPaired(MpcClient client, String escrowKeyHex) async {
  final deadline = DateTime.now().add(const Duration(seconds: 30));
  while (true) {
    final listed = await client.escrowStatus();
    final row = listed.firstWhere((e) => e.escrowKey.toLowerCase() == escrowKeyHex.toLowerCase());
    if (row.serviceReady) return 'service=yes wallet=yes';
    if (DateTime.now().isAfter(deadline)) {
      return 'service=${row.serviceConfirmed} wallet=${row.walletConfirmed} (not ready)';
    }
    await Future<void>.delayed(const Duration(milliseconds: 250));
  }
}

Future<List<IndexerVtxo>> _escrowVtxos(Wallet alice, String escrowKeyHex) async {
  final key = escrowKeyHex.toLowerCase();
  return alice.client.vtxosAtArkAddress(key.length == 66 ? key.substring(2) : key);
}

/// Board, settle, and send the escrow its funding.
///
/// Mining while the settle runs, because a settle waits on a round the chain has to advance for —
/// the same thing the e2e suite does, spelled out here rather than borrowed from a test.
Future<void> _fund(Wallet alice, RegtestHelper btc, String escrowAddress, int sats) async {
  final boarding = await alice.client.getBoardingAddress();
  await btc.sendToAddress(boarding, 0.002);
  await btc.generateToAddress(1, await btc.getNewAddress());
  final deposits = await pollBoardingUtxos(boarding, 200000);
  if (deposits.isEmpty) throw StateError('the deposit was never indexed');
  await _whileMining(btc, () => settleBoarding(alice.client, deposits));
  await _whileMining(btc, () => alice.client.sendVtxo(escrowAddress, sats));
}

/// Keep the chain moving while [body] runs.
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

Future<void> _requireUp(String base, String what, {String path = '/status'}) async {
  try {
    await _getJson(base, path);
  } catch (e) {
    stderr.writeln('$what is not answering at $base — see examples/card-escrow/README.md');
    stderr.writeln('  ($e)');
    exit(1);
  }
}

/// Every call opens its own connection.
///
/// The service answers some routes without reading a body and may close the socket as it does, and
/// a reused keep-alive connection then fails on the next write with a broken pipe. A demo is not
/// the place to be clever about connection pooling.
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

/// POST with no body, for a route that takes none. Sending one anyway makes the server close the
/// connection before the body is written, which the client sees as a broken pipe.
Future<dynamic> _postEmpty(String base, String path) async {
  final request = await _http.postUrl(Uri.parse('$base$path'));
  request.persistentConnection = false;
  request.contentLength = 0;
  final response = await request.close();
  return jsonDecode(await response.transform(utf8.decoder).join());
}

Future<void> _post(String base, String path) async {
  final request = await _http.postUrl(Uri.parse('$base$path'));
  request.persistentConnection = false;
  request.contentLength = 0;
  final response = await request.close();
  await response.drain<void>();
}

String _hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
