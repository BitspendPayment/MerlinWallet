/// Sending to banks and mobile money, end to end, on the fake Grid.
///
/// ```text
///   make send-walkthrough      (starts regtest, arkd, MerlinPlatform and the fake Grid first)
/// ```
///
/// Alice pays a Nigerian bank, a Kenyan M-PESA wallet, Ghanaian mobile money, a Ghanaian bank and a
/// South African bank, through the same wallet library the app uses (`BankSend`): quote, check the
/// policy, top the escrow up to the price and seal, and let MerlinPlatform pay and be repaid — each
/// payout counting the passkey approvals it really took. Then the
/// cases that must not work: a payout that fails, a payee the bank does not know, messages the
/// enclave did not send, a policy sealed with a term added, a deal too short to be repaid in.
///
/// **Every payout here is simulated.** The fake Grid answers the way Grid's sandbox does, and marks
/// everything it returns `simulated`. The Bitcoin is real regtest Bitcoin, and every signature,
/// policy decision and Ark transaction is the production code path.
library;

import 'dart:convert';
import 'dart:io';

import 'package:app_core/asp/asp_client.dart' show IndexerVtxo;
import 'package:app_core/client.dart';
import 'package:app_core/enclave/authenticator.dart' show SoftwareAuthenticator;
import 'package:app_core/platform/bank_send.dart';
import 'package:app_core/platform/platform_client.dart';
import 'package:app_core/sessions/service_delivery.dart' show RewritingDelivery;
import 'package:e2e/boarding_poll.dart';
import 'package:e2e/e2e_profile.dart';
import 'package:e2e/logger.dart';
import 'package:e2e/regtest_helper.dart';

final platformBase = Uri.parse('http://127.0.0.1:$platformPort');
const operatorBase = 'http://127.0.0.1:7201';

Future<void> main() async {
  await _requireUp('$platformBase/corridors', 'MerlinPlatform (make platform-up)');

  final harness = await startE2eEnclave();
  Log.info('enclave up: pcr16=${harness.pcr16.substring(0, 16)}…');
  // The platform believes an enclave only once it knows this boot's PCRs and root.
  await writeEnclavePins(harness);

  final btc = RegtestHelper(rpcUrl: 'http://127.0.0.1:18443/wallet/default');
  final alice = await harness.wallet('alice', aspHost: '127.0.0.1', aspPort: 7070);
  final platform = PlatformClient(platformBase);
  final send = BankSend(
    wallet: alice.client,
    platform: platform,
    platformId: platformIdentifier,
    gridOrigin: gridOriginFromEnclave,
    delivery: RewritingDelivery(),
  );

  try {
    await alice.client.doDkg();
    _step('Alice boards 0.005 BTC and settles it into her wallet');
    await _board(alice.client, btc, 0.005);

    final corridors = {for (final c in await platform.corridors()) c.country: c};
    Future<Map<String, String>> fields(String country, String rail, String number) async {
      final r = corridors[country]!.rails.firstWhere((r) => r.kind == rail);
      final out = <String, String>{};
      for (final f in r.fields) {
        if (f.key == 'accountNumber' || f.key == 'phoneNumber') {
          out[f.key] = number;
        } else if (f.options.isNotEmpty) {
          out[f.key] = f.options.first;
        } else if (f.fromBankList) {
          out[f.key] = (await platform.banks(country)).first;
        }
      }
      return out;
    }

    final flow = _Flow(send, alice.client, alice.gate.authenticator as SoftwareAuthenticator, btc);

    _step('1. ₦30,000 to a Nigerian bank — the first send also sets up the escrow');
    await flow.pay('NG', 'bank', await fields('NG', 'bank', '0123456789'), 3000000,
        approvals: 2);

    _step('2. Straight after: KSh 1,500 to M-PESA — the last deal was spent, so the escrow is free');
    await flow.pay('KE', 'mobile_money', await fields('KE', 'mobile_money', '+254712345678'), 150000,
        approvals: 1);

    _step('3. Ghana, mobile money and then a bank; then a South African bank');
    await flow.pay('GH', 'mobile_money', await fields('GH', 'mobile_money', '+233241234567'), 20000,
        approvals: 1);
    await flow.pay('GH', 'bank', await fields('GH', 'bank', '1234567890'), 20000, approvals: 1);
    await flow.pay('ZA', 'bank', await fields('ZA', 'bank', '1234567890'), 50000, approvals: 1);

    _step('4. R 500 to a South African account the bank cannot pay (…002)');
    await flow.pay('ZA', 'bank', await fields('ZA', 'bank', '1234567002'), 50000,
        approvals: 1, fails: true);
    _say('the platform ended the deal it gave up on, so the escrow still holds that price — and the '
        'next send of the same amount needs no top-up');
    await flow.pay('ZA', 'bank', await fields('ZA', 'bank', '1234567890'), 50000, approvals: 1);

    _step('5. A Nigerian account whose holder the bank does not recognise (…102)');
    try {
      await send.quote(
        escrowKeyHex: flow.escrow!,
        country: 'NG',
        rail: 'bank',
        fields: await fields('NG', 'bank', '0123456102'),
        fullName: 'Ada Obi',
        amountMinor: 3000000,
      );
      throw StateError('a payee the bank does not recognise was quoted');
    } on PlatformException catch (e) {
      if (!e.refused) rethrow;
      _say('refused before anything was sealed: ${e.message}');
    }

    _step('6. Messages the enclave did not send');
    final wire = '${'00' * 16}-svc-${platformIdentifierHex.substring(0, 40)}';
    final forged = await _post('$platformBase/escrow/send?id=$wire', {
      'kind': 'release-refused',
      'request_id': 'reimb-0001',
      'reason': 'status is "PENDING", not "COMPLETED"',
    });
    final dialled = await _get('$platformBase/escrow/stream?id=$wire');
    _say('a forged answer: HTTP $forged; an unattested connection: HTTP $dialled');
    if (forged != 401 || dialled != 401) throw StateError('the platform heard the unattested');

    _step('7. What an app could seal instead of what it was offered — neither is paid');
    final offered = await send.quote(
      escrowKeyHex: flow.escrow!,
      country: 'NG',
      rail: 'bank',
      fields: await fields('NG', 'bank', '0123456789'),
      fullName: 'Ada Obi',
      amountMinor: 3000000,
    );
    await _whileMining(btc, () async {
      final short = BankSend.shortfall(offered.sats, await send.held(flow.escrow!));
      if (short > 0) {
        await alice.client.sendVtxo(await alice.client.escrowArkAddress(flow.escrow!), short);
      }
    });
    await alice.client.openEscrowSession(
      escrowKeyHex: flow.escrow!,
      policy: {
        'op': 'all_of',
        'of': [offered.policy, {'op': 'never'}],
      },
      deadline: DateTime.now().add(Duration(seconds: offered.dealSeconds)),
    );
    await _refusedToFund(send, offered, 'a policy with a term added');

    // The escrow above is held by that deal until its deadline, so this one needs its own.
    final second = await send.ensureEscrow();
    final hurried = await send.quote(
      escrowKeyHex: second,
      country: 'NG',
      rail: 'bank',
      fields: await fields('NG', 'bank', '0123456789'),
      fullName: 'Ada Obi',
      amountMinor: 3000000,
    );
    await _whileMining(btc, () async {
      await alice.client.sendVtxo(await alice.client.escrowArkAddress(second), hurried.sats);
    });
    await alice.client.openEscrowSession(
      escrowKeyHex: second,
      policy: hurried.policy,
      deadline: DateTime.now().add(const Duration(seconds: 90)),
    );
    await _refusedToFund(send, hurried, 'a deal that ends before it could be repaid');

    print('\n  ${'=' * 60}\n  every payout paid, every refusal refused\n');
  } finally {
    await alice.close();
    await harness.stop();
  }
}

/// One payout after another through the same escrow, checking that exactly the price moves — and
/// that the owner was asked exactly as often as the app says they will be.
class _Flow {
  _Flow(this.send, this.wallet, this.passkey, this.btc);
  final BankSend send;
  final MpcClient wallet;

  /// Counts its assertions, and every approval is one: what the owner was really asked.
  final SoftwareAuthenticator passkey;
  final RegtestHelper btc;
  String? escrow;

  Future<void> pay(String country, String rail, Map<String, String> fields, int amountMinor,
      {required int approvals, bool fails = false}) async {
    final hadEscrow = escrow != null;
    final askedBefore = passkey.counter;
    escrow = await send.ensureEscrow(known: escrow);
    final quote = await send.quote(
      escrowKeyHex: escrow!,
      country: country,
      rail: rail,
      fields: fields,
      fullName: 'Ada Obi',
      amountMinor: amountMinor,
    );
    _say('${quote.currency} ${amountMinor / 100} to ${fields.values.join(' ')} '
        'for ${quote.sats} sats; the bank says ${quote.nameAtBank ?? '—'} (${quote.nameCheck ?? 'no check'})');

    final needed = BankSend.approvalsNeeded(hasEscrow: hadEscrow);
    if (needed != approvals) {
      throw StateError('expected $approvals approvals, the flow needs $needed');
    }

    final treasuryBefore = await _treasurySats();
    final committed = await _whileMining(
        btc, () => send.commit(quote, escrowKeyHex: escrow!, fields: fields));
    final asked = passkey.counter - askedBefore;
    if (asked != approvals) {
      throw StateError('the owner was asked $asked times, not the $approvals the app says');
    }
    final escrowBefore = _sats(await send.held(escrow!));
    _say('sealed: ${committed.agreed}');
    await send.fund(quote);

    PayoutStatus? last;
    await for (final status in send.follow(quote.dealTag)) {
      _say('  ${status.state}${status.gridStatus == null ? '' : ' (Grid: ${status.gridStatus})'}');
      last = status;
    }
    final escrowAfter = _sats(await send.held(escrow!));
    if (fails) {
      if (last!.state != 'failed') throw StateError('a payout that should fail ended ${last.state}');
      if (!last.dealEnded) throw StateError('the platform did not end the deal it gave up on');
      if (escrowAfter != escrowBefore) throw StateError('a failed payout moved the escrow');
      return;
    }
    if (last!.state != 'repaid') throw StateError('the payout ended ${last.state}: ${last.failure}');
    if (escrowBefore - escrowAfter != quote.sats) {
      throw StateError('the escrow paid ${escrowBefore - escrowAfter} sats, not ${quote.sats}');
    }
    final gained = await _eventually(() async => await _treasurySats() - treasuryBefore,
        until: (g) => g >= quote.sats);
    if (gained != quote.sats) throw StateError('the platform gained $gained sats, not ${quote.sats}');
    _say('repaid ${quote.sats} sats: the escrow paid exactly the price, and the platform got it');
  }
}

Future<void> _refusedToFund(BankSend send, PayoutQuote quote, String what) async {
  try {
    await send.fund(quote);
    throw StateError('the platform funded $what');
  } on PlatformException catch (e) {
    if (!e.refused) rethrow;
    _say('$what: ${e.message}');
  }
}

int _sats(List<IndexerVtxo> vtxos) =>
    vtxos.where((v) => !v.isSpent).fold<int>(0, (a, v) => a + v.amountSats);

Future<int> _treasurySats() async {
  final client = HttpClient();
  try {
    final response = await (await client.getUrl(Uri.parse('$operatorBase/treasury'))).close();
    final body = jsonDecode(await utf8.decodeStream(response)) as Map<String, dynamic>;
    return body['balance_sats'] as int;
  } finally {
    client.close(force: true);
  }
}

Future<T> _eventually<T>(Future<T> Function() read, {required bool Function(T) until}) async {
  final deadline = DateTime.now().add(const Duration(seconds: 30));
  while (true) {
    final value = await read();
    if (until(value) || DateTime.now().isAfter(deadline)) return value;
    await Future<void>.delayed(const Duration(seconds: 1));
  }
}

Future<void> _board(MpcClient client, RegtestHelper btc, double btcAmount) async {
  final boarding = await client.getBoardingAddress();
  await btc.sendToAddress(boarding, btcAmount);
  await btc.generateToAddress(1, await btc.getNewAddress());
  final deposits = await pollBoardingUtxos(boarding, (btcAmount * 1e8).round());
  if (deposits.isEmpty) throw StateError('the deposit was never indexed');
  await _whileMining(btc, () => settleBoarding(client, deposits));
}

/// Nothing moves on regtest unless somebody mines.
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

Future<int> _post(String url, Object body) async {
  final client = HttpClient();
  try {
    final request = await client.postUrl(Uri.parse(url));
    request.headers.contentType = ContentType.json;
    request.write(jsonEncode(body));
    final response = await request.close();
    await response.drain<void>();
    return response.statusCode;
  } finally {
    client.close(force: true);
  }
}

Future<int> _get(String url) async {
  final client = HttpClient();
  try {
    final response = await (await client.getUrl(Uri.parse(url))).close();
    final status = response.statusCode;
    // A held stream would never end; a refusal does at once.
    await response.drain<void>().timeout(const Duration(seconds: 2), onTimeout: () {});
    return status;
  } finally {
    client.close(force: true);
  }
}

Future<void> _requireUp(String url, String what) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 3);
  try {
    final response = await (await client.getUrl(Uri.parse(url))).close();
    await response.drain<void>();
    if (response.statusCode == 200) return;
  } catch (_) {
  } finally {
    client.close(force: true);
  }
  stderr.writeln('$what is not answering at $url');
  exit(1);
}

void _step(String what) => print('\n$what');
void _say(String what) => print('  $what');
