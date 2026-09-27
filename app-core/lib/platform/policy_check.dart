/// The owner's side of a payout: refusing to seal a policy that does not say what she agreed to.
///
/// A payout platform writes the policy an escrow is committed to, and `openEscrowSession` seals
/// whatever map it is given — a platform could hand back `{"op":"always"}`, or a policy that checks
/// somebody else's bank account, or one whose evidence comes from a provider the platform runs
/// itself. So before anything is sealed, this reads the policy and holds it to what the owner was
/// shown: this price and no more, to this account at this bank (or this phone, on mobile money),
/// in this currency, at least this amount, completed, and proven by Grid itself.
///
/// It does not require the policy to be exactly one shape. More terms under `all_of` only refuse
/// more releases, which can cost the platform its repayment but never the owner her money. What it
/// refuses is anything that could let more leave: an unknown term, a cap above the price, a second
/// destination, a fetch from anybody but the pinned provider, or a missing check.
library;

/// What the owner was shown, and so what the sealed policy must hold the platform to.
class ExpectedPayout {
  const ExpectedPayout({
    required this.gridOrigin,
    required this.gridApiPath,
    required this.accountId,
    required this.payeeFields,
    required this.currency,
    required this.amountMinor,
    required this.dealTag,
    required this.priceSats,
  });

  /// Where the cosigner must fetch its evidence: Grid, as the enclave reaches it. Pinned by the app
  /// per environment, never taken from the platform.
  final String gridOrigin;

  /// Grid's API version prefix, e.g. `/grid/2025-10-13`.
  final String gridApiPath;

  /// The payee record the platform registered, from its quote.
  final String accountId;

  /// What the owner typed, by Grid's field names — `accountNumber` and `bankName` for a bank,
  /// `phoneNumber` and `provider` (or `bankName`) for mobile money. Every one must be pinned.
  final Map<String, String> payeeFields;

  final String currency;
  final int amountMinor;
  final String dealTag;

  /// The agreed price. Nothing more may leave, in one release or in all of them.
  final int priceSats;
}

/// A policy the owner must not seal, and why.
class PolicyRefused implements Exception {
  PolicyRefused(this.reason);
  final String reason;
  @override
  String toString() => 'refusing to seal this payout: $reason';
}

const _known = {'outputs_only_to', 'total_out_max', 'released_total_max', 'fee_max', 'http_get'};

/// Throws [PolicyRefused] unless [policy] holds the platform to [expected].
void checkPayoutPolicy(Map<String, dynamic> policy, ExpectedPayout expected) {
  void need(bool ok, String what) {
    if (!ok) throw PolicyRefused(what);
  }

  need(policy['op'] == 'all_of', 'it is not a list of conditions that must all hold');
  final terms = (policy['of'] as List? ?? const []).whereType<Map<String, dynamic>>().toList();
  need(terms.isNotEmpty, 'it has no conditions');
  need(terms.every((t) => _known.contains(t['op'])), 'it has a condition the app cannot read');

  List<Map<String, dynamic>> all(String op) => terms.where((t) => t['op'] == op).toList();
  // Every cap of a kind, not the first: a second, looser one would be the one a reader believes.
  bool capped(String op) =>
      all(op).isNotEmpty && all(op).every((t) => t['sats'] == expected.priceSats);
  need(capped('total_out_max'), 'one release may take more than the price');
  need(capped('released_total_max'), 'the releases together may take more than the price');
  need(all('fee_max').isNotEmpty && all('fee_max').every((t) => t['sats'] == 0),
      'the escrow may lose sats to fees');
  final destinations = all('outputs_only_to');
  need(
      destinations.length == 1 && (destinations.single['scripts'] as List? ?? const []).length == 1,
      'it may pay somebody besides the platform');

  final fetches = all('http_get');
  need(fetches.length == 2, 'it does not check exactly the payee and the payout');
  for (final fetch in fetches) {
    need(fetch['provider'] == expected.gridOrigin, 'it asks somebody other than Grid');
    need(fetch['credentials'] == 'GRID', 'it asks Grid under another credential');
  }
  bool pins(Map<String, dynamic> fetch, String is_, String at, [Object? value]) =>
      (fetch['expect'] as List? ?? const []).whereType<Map<String, dynamic>>().any((p) =>
          p['is'] == is_ && p['at'] == at && (value == null || p['value'] == value));

  final api = expected.gridApiPath;
  final payee = fetches.firstWhere(
      (f) => f['path'] == '$api/platform/external-accounts/${expected.accountId}',
      orElse: () => const {});
  need(payee.isNotEmpty, 'it does not check the payee the platform registered');
  for (final field in expected.payeeFields.entries) {
    need(pins(payee, 'equals', 'accountInfo.${field.key}', field.value),
        'it does not hold the payee to the ${field.key} you entered');
  }

  final payout = fetches.firstWhere((f) => f['path'] == '$api/transactions/{reference}',
      orElse: () => const {});
  need(payout.isNotEmpty, 'it does not check the payout');
  need(pins(payout, 'matches_reference', 'id'), 'the payout checked is not the one claimed');
  need(pins(payout, 'equals', 'description', expected.dealTag), 'the payout is not for this deal');
  need(pins(payout, 'equals', 'destination.accountId', expected.accountId),
      'the payout is not to this payee');
  need(pins(payout, 'equals', 'receivedAmount.currency.code', expected.currency),
      'the payout is not in ${expected.currency}');
  need(pins(payout, 'at_least', 'receivedAmount.amount', expected.amountMinor),
      'the payout may be less than you are sending');
  need(pins(payout, 'equals', 'status', 'COMPLETED'), 'the payout need not have completed');
}
