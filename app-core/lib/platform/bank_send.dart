/// Sending to a bank account or a mobile-money wallet, paid for out of an escrow.
///
/// ```text
///   ensureEscrow   an escrow the platform is paired into          first time: 1 approval
///   quote          the platform prices the payout, writes the policy
///   commit         check the policy · top the escrow up to the price and seal the deal
///                                                                  1 approval
///   fund           the platform asks the cosigner, then pays       none
///   follow         the platform's word on how it is going          none
/// ```
///
/// One approval per cosigner call, so each step that needs the cosigner is one call: minting the
/// escrow and pairing the platform into it are one stream, and so are the top-up and the seal.
///
/// The app and the e2e walkthrough drive these same steps, so what the walkthrough proves is what
/// the app does. Nothing here keeps state: each step returns what the caller should remember.
///
/// **Why the escrow is topped up per send.** Money in an escrow is not renewed, and a VTXO that is
/// not renewed is swept when it expires. So the escrow holds what the next payout needs and no
/// more: what it already holds (a failed payout's leftover, say) counts toward the price, and only
/// the shortfall is sent to it.
library;

import 'dart:math';

import 'package:convert/convert.dart' show hex;

import '../asp/ark_info.dart';
import '../client.dart';
import '../sessions/service_delivery.dart';
import '../threshold_types.dart' as threshold;
import 'platform_client.dart';
import 'policy_check.dart';

/// Grid's API version, as a sealed policy names it.
const gridApiPath = '/grid/2025-10-13';

class BankSend {
  BankSend({
    required this.wallet,
    required this.platform,
    required this.platformId,
    required this.gridOrigin,
    this.delivery,
  });

  final MpcClient wallet;
  final PlatformClient platform;

  /// The platform's identifier, as the enclave's image names it.
  final threshold.Identifier platformId;

  /// Grid as the enclave reaches it — what every policy must fetch its evidence from. Pinned by the
  /// app for its environment, never taken from the platform.
  final String gridOrigin;

  /// How the wallet's pairing half reaches the platform. `null` is plain HTTPS.
  final DeliverToService? delivery;

  /// 16 random bytes, hex: the app's name for one payout. Chosen here, never by the platform — a
  /// tag the platform chose could be given to two customers, and one payout would then satisfy two
  /// deals.
  static String newDealTag() {
    final random = Random.secure();
    return hex.encode(List<int>.generate(16, (_) => random.nextInt(256)));
  }

  /// What must be sent to the escrow for it to hold [price]: nothing if it already does, and never
  /// less than the ASP's dust, which is the smallest output it accepts.
  static int shortfall(int price, List<IndexerVtxo> held, {int dust = 330}) {
    final have = held.where((v) => !v.isSpent).fold<int>(0, (a, v) => a + v.amountSats);
    final short = price - have;
    return short <= 0 ? 0 : max(short, dust);
  }

  /// How many times the owner will be asked to approve, so the app can say so before it starts.
  static int approvalsNeeded({required bool hasEscrow}) => (hasEscrow ? 0 : 1) + 1;

  /// The escrow payouts are paid from: [known] if this wallet still holds it, otherwise a new one,
  /// minted and paired with the platform.
  ///
  /// The caller forgets [known] once it reclaims from it — a reclaim retires an escrow for good.
  Future<String> ensureEscrow({String? known}) async {
    if (known != null && wallet.escrows.any((e) => _same(e.escrowKeyHex, known))) return known;
    final set = await wallet.setUpEscrow(serviceIdentifier: platformId, delivery: delivery);
    return set.escrow.escrowKeyHex;
  }

  /// What the escrow holds right now, from the indexer.
  Future<List<IndexerVtxo>> held(String escrowKeyHex) =>
      wallet.vtxosAtArkAddress(_xOnly(escrowKeyHex));

  Future<PayoutQuote> quote({
    required String escrowKeyHex,
    required String country,
    required String rail,
    required Map<String, String> fields,
    required String fullName,
    required int amountMinor,
    String? dealTag,
  }) =>
      platform.quote(
        escrowKeyHex: escrowKeyHex,
        country: country,
        rail: rail,
        fields: fields,
        fullName: fullName,
        amountMinor: amountMinor,
        dealTag: dealTag ?? newDealTag(),
      );

  /// Commit the escrow to this payout: refuse a policy that is not what the owner was shown, top the
  /// escrow up to the price, and seal the deal.
  ///
  /// [fields] are what the owner typed — the policy must hold the payee to every one of them.
  /// [onStep] is told as each step begins, for a screen to show where it has got to.
  Future<Commitment> commit(
    PayoutQuote quote, {
    required String escrowKeyHex,
    required Map<String, String> fields,
    void Function(CommitStep step)? onStep,
  }) async {
    onStep?.call(CommitStep.policy);
    checkPayoutPolicy(
      quote.policy,
      ExpectedPayout(
        gridOrigin: gridOrigin,
        gridApiPath: gridApiPath,
        accountId: quote.accountId,
        payeeFields: fields,
        currency: quote.currency,
        amountMinor: quote.amountMinor,
        dealTag: quote.dealTag,
        priceSats: quote.sats,
      ),
    );

    final info = await wallet.getArkInfo();
    final topUp = shortfall(quote.sats, await held(escrowKeyHex), dust: info.dust);
    onStep?.call(CommitStep.seal);

    final deadline = DateTime.now().add(Duration(seconds: quote.dealSeconds));
    String? topUpTxid;
    String? agreed;
    if (topUp > 0) {
      final funded = await _untilPaired(() => wallet.fundEscrowDeal(
            escrowKeyHex: escrowKeyHex,
            amountSats: topUp,
            policy: quote.policy,
            deadline: deadline,
          ));
      topUpTxid = funded.arkTxid;
      agreed = funded.agreed;
    }
    // Nothing to top up — or a cosigner from before a send could commit, which topped up only.
    final sealed = agreed ??
        await _untilPaired<String>(() => wallet.openEscrowSession(
              escrowKeyHex: escrowKeyHex,
              policy: quote.policy,
              deadline: deadline,
            ));
    return Commitment(agreed: sealed, deadline: deadline, topUpSats: topUp, topUpTxid: topUpTxid);
  }

  /// [commit], asked again while the pairing is not yet usable.
  ///
  /// A pairing is usable once the platform's confirmation has reached the cosigner, which follows
  /// the pairing itself by a moment. By the time an owner has read a quote it almost always has;
  /// if not, the cosigner says so and this asks again, rather than polling for it beforehand.
  ///
  /// Safe to repeat because the cosigner refuses that way only before anything is built: a send
  /// that commits is checked when it opens, and whatever fails once its money has moved says so in
  /// other words. Each ask is one more approval.
  static Future<T> _untilPaired<T>(Future<T> Function() commit) async {
    for (var attempt = 1;; attempt++) {
      try {
        return await commit();
      } catch (e) {
        if (attempt >= 3 || !'$e'.contains('pairing is not finished')) rethrow;
        await Future<void>.delayed(const Duration(seconds: 2));
      }
    }
  }

  /// The go-ahead. The platform asks the cosigner before it pays, and pays only if the deal it
  /// offered is the one sealed, with time enough left to be repaid in.
  Future<void> fund(PayoutQuote quote) => platform.fund(quote.requestId);

  /// How the payout is going, until it is repaid or has failed. Asks the platform, never the
  /// cosigner: the platform costs no approval to ask.
  ///
  /// A failed payout is given up, and its deal ended, a moment after Grid says it failed — and the
  /// deal ending is what frees the escrow. So after a failure this waits, up to [settle], for the
  /// platform to say the deal has ended, and the last status says whether it has.
  Stream<PayoutStatus> follow(String dealTag,
      {Duration every = const Duration(seconds: 3),
      Duration settle = const Duration(seconds: 60)}) async* {
    String? last;
    DateTime? failedAt;
    while (true) {
      final status = await platform.status(dealTag);
      final now = '${status.state}/${status.gridStatus}/${status.arkTxid}/${status.dealEnded}';
      if (now != last) {
        last = now;
        yield status;
      }
      if (status.state == 'repaid') return;
      if (status.state == 'failed') {
        failedAt ??= DateTime.now();
        if (status.dealEnded || DateTime.now().difference(failedAt) > settle) return;
      }
      await Future<void>.delayed(every);
    }
  }

  static bool _same(String a, String b) => _xOnly(a) == _xOnly(b);

  static String _xOnly(String key) {
    final k = key.toLowerCase();
    return k.length == 66 ? k.substring(2) : k;
  }
}

/// Where [BankSend.commit] has got to.
enum CommitStep {
  /// Reading the policy against what the owner was shown.
  policy,

  /// Sending the escrow what it is short of the price, if anything, and committing it to the deal:
  /// one approval.
  seal,
}

/// What committing a payout did.
class Commitment {
  Commitment({
    required this.agreed,
    required this.deadline,
    required this.topUpSats,
    this.topUpTxid,
  });

  /// The sealed policy, as the cosigner renders it: what the owner agreed to.
  final String agreed;
  final DateTime deadline;

  /// What was sent to the escrow to reach the price, and the send's txid. 0 and null when the
  /// escrow already held it.
  final int topUpSats;
  final String? topUpTxid;
}
