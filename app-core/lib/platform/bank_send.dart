/// Sending to a bank account or a mobile-money wallet, paid for out of an escrow.
///
/// ```text
///   quote    the platform prices the payout, writes the policy           none
///   commit   check the policy · mint an escrow, pair the platform into   1 approval
///            it and seal the deal
///            · send the escrow the price                                 1 approval
///   fund     the platform asks the cosigner, then pays                   none
///   follow   the platform's word on how it is going                      none
/// ```
///
/// One escrow per payout, and nothing minted until the owner has seen the price and pressed send —
/// a quote looked at and left costs nothing. One approval per cosigner call: the escrow's own
/// session, which mints it, pairs the platform in and strikes the deal on one stream, and the send
/// that funds it.
///
/// The app and the e2e walkthrough drive these same steps, so what the walkthrough proves is what
/// the app does. Nothing here keeps state: each step returns what the caller should remember.
///
/// **What a failed payout leaves.** Money in an escrow is not renewed, and a VTXO that is not
/// renewed is swept when it expires — so the price a failed payout leaves in its escrow is taken
/// back by reclaiming that escrow, which its platform frees by ending the deal.
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

  /// How many times the owner is asked to approve a payout, so the app can say so before it
  /// starts: the escrow's session, and the send that funds it.
  static const approvals = 2;

  /// What an escrow holds right now, from the indexer.
  Future<List<IndexerVtxo>> held(String escrowKeyHex) =>
      wallet.vtxosAtArkAddress(_xOnly(escrowKeyHex));

  Future<PayoutQuote> quote({
    required String country,
    required String rail,
    required Map<String, String> fields,
    required String fullName,
    required int amountMinor,
    String? dealTag,
  }) =>
      platform.quote(
        country: country,
        rail: rail,
        fields: fields,
        fullName: fullName,
        amountMinor: amountMinor,
        dealTag: dealTag ?? newDealTag(),
      );

  /// Commit to this payout: refuse a policy that is not what the owner was shown, set up an escrow
  /// with the platform paired in and the deal sealed, and send it the price.
  ///
  /// [fields] are what the owner typed — the policy must hold the payee to every one of them.
  /// [onStep] is told as each step begins, for a screen to show where it has got to. [onSealed] is
  /// told the escrow once its deal is sealed, before any money moves to it — so a caller remembers
  /// it whatever the send that funds it does.
  Future<Commitment> commit(
    PayoutQuote quote, {
    required Map<String, String> fields,
    void Function(CommitStep step)? onStep,
    Future<void> Function(String escrowKeyHex)? onSealed,
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

    onStep?.call(CommitStep.seal);
    final deadline = DateTime.now().add(Duration(seconds: quote.dealSeconds));
    final set = await wallet.setUpEscrow(
      serviceIdentifier: platformId,
      policy: quote.policy,
      deadline: deadline,
      delivery: delivery,
    );
    final escrowKeyHex = set.escrow.escrowKeyHex;
    await onSealed?.call(escrowKeyHex);

    onStep?.call(CommitStep.fund);
    final txid = await wallet.sendVtxo(await wallet.escrowArkAddress(escrowKeyHex), quote.sats);
    return Commitment(
      escrowKeyHex: escrowKeyHex,
      agreed: set.agreed,
      deadline: deadline,
      fundedSats: quote.sats,
      fundTxid: txid,
    );
  }

  /// The go-ahead, for the escrow [commit] set up. The platform asks the cosigner before it pays,
  /// and pays only if the deal it offered is the one sealed on that escrow, with time enough left
  /// to be repaid in.
  Future<void> fund(PayoutQuote quote, Commitment commitment) =>
      _untilPaired(() => platform.fund(quote.requestId, escrowKeyHex: commitment.escrowKeyHex));

  /// [fund], asked again while the pairing is not yet usable.
  ///
  /// A pairing is usable once the platform's confirmation has reached the cosigner, which follows
  /// the escrow's session by a moment — it cannot arrive while that stream holds the tenant. By
  /// the time the funding send is approved it almost always has; if not, the cosigner tells the
  /// platform so and this asks again. Asking the platform costs no approval.
  static Future<T> _untilPaired<T>(Future<T> Function() ask) async {
    for (var attempt = 1;; attempt++) {
      try {
        return await ask();
      } catch (e) {
        if (attempt >= 3 || !'$e'.contains('pairing is not finished')) rethrow;
        await Future<void>.delayed(const Duration(seconds: 2));
      }
    }
  }

  /// How the payout is going, until it is repaid or has failed. Asks the platform, never the
  /// cosigner: the platform costs no approval to ask.
  ///
  /// A failed payout is given up, and its deal ended, a moment after Grid says it failed — and the
  /// deal ending is what lets its escrow be taken back. So after a failure this waits, up to
  /// [settle], for the platform to say the deal has ended, and the last status says whether it has.
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

  static String _xOnly(String key) {
    final k = key.toLowerCase();
    return k.length == 66 ? k.substring(2) : k;
  }
}

/// Where [BankSend.commit] has got to.
enum CommitStep {
  /// Reading the policy against what the owner was shown.
  policy,

  /// Setting up the escrow — minted, the platform paired in, the deal sealed: one approval.
  seal,

  /// Sending the escrow the price: one approval.
  fund,
}

/// What committing a payout did.
class Commitment {
  Commitment({
    required this.escrowKeyHex,
    required this.agreed,
    required this.deadline,
    required this.fundedSats,
    required this.fundTxid,
  });

  /// The payout's own escrow.
  final String escrowKeyHex;

  /// The sealed policy, as the cosigner renders it: what the owner agreed to.
  final String agreed;
  final DateTime deadline;

  /// What was sent to the escrow — the price — and the send's txid.
  final int fundedSats;
  final String fundTxid;
}
