/// The delegate: funds renewed on a schedule by the cosigner, with nobody connected.
///
/// A VTXO has to be refreshed in a batch round before the ASP's expiry. The wallet signs, while it is
/// here, an intent to refresh everything it holds — valid from the earliest expiry less a margin —
/// and the forfeits the round will need, and the cosigner seals them. When the deadline comes the
/// cosigner runs that round itself, from a background task, against its ASP: no phone, no passkey.
///
/// Renewing it rides the end of every `Send` and `Renew`, on the same stream and under the same
/// approval — the passkey gesture that approved the operation also unlocked the share that signs
/// the delegate. Funds that arrive any other way, a receive, are not covered until the wallet
/// renews it again; [DelegateStatus] is how the app notices, and `MpcClient.protectFunds` how it
/// renews it.
library;

import 'package:protocol/cosigner_v1.dart' as cs;

import '../asp/ark_info.dart';
import '../cosigner/connection.dart';
import '../passkey/operation_secrets.dart';
import '../threshold_types.dart' as threshold;
import 'exit_plan.dart';
import 'in_band_round.dart';
import 'send_session.dart';

/// What the sealed delegate covers.
class DelegateStatus {
  DelegateStatus({
    required this.validAt,
    required this.margin,
    required this.covered,
    this.deviceEnrolled = false,
    this.exits = const [],
  });

  factory DelegateStatus.fromRenewed(cs.DelegateRenewed s, {List<ExitTx> exits = const []}) =>
      DelegateStatus(
        validAt: DateTime.fromMillisecondsSinceEpoch(s.validAtSecs.toInt() * 1000),
        margin: Duration(seconds: s.marginSecs.toInt()),
        covered: s.covered.toSet(),
        deviceEnrolled: s.deviceEnrolled,
        exits: exits,
      );

  factory DelegateStatus.fromJson(Map<String, dynamic> j) => DelegateStatus(
        validAt: DateTime.fromMillisecondsSinceEpoch((j['validAt'] as num).toInt() * 1000),
        margin: Duration(seconds: (j['margin'] as num).toInt()),
        covered: (j['covered'] as List).cast<String>().toSet(),
        exits: [
          for (final e in (j['exits'] as List? ?? const []))
            ExitTx.fromJson((e as Map).cast<String, dynamic>()),
        ],
      );

  Map<String, dynamic> toJson() => {
        'validAt': validAt.millisecondsSinceEpoch ~/ 1000,
        'margin': margin.inSeconds,
        'covered': covered.toList(),
        'exits': [for (final e in exits) e.toJson()],
      };

  /// When the cosigner will run it.
  final DateTime validAt;

  /// How long before the earliest expiry that is.
  final Duration margin;

  /// `txid:vout` of each VTXO it refreshes.
  final Set<String> covered;

  /// Whether the device token the renewal carried was enrolled for wakes. Only meaningful on the
  /// renewal that carried one, so not persisted.
  final bool deviceEnrolled;

  /// A signed unilateral exit per covered VTXO, when the wallet had an exit address for them. What
  /// the owner broadcasts if this cosigner is never heard from again — see
  /// `sessions/exit_plan.dart`.
  final List<ExitTx> exits;

  bool covers(IndexerVtxo vtxo) => covered.contains('${vtxo.txid}:${vtxo.vout}');
}

/// The wallet's set once the indexer reflects an operation: [gone] no longer held, [arrived] held
/// with a known expiry, and every held VTXO's expiry known. Polls, because indexing trails the ASP
/// by a moment; gives up with null rather than renewing over a set that is not settled yet.
Future<List<IndexerVtxo>?> heldOnceIndexed(
  Future<List<IndexerVtxo>> Function() read, {
  Set<String> gone = const {},
  String? arrived,
  Duration timeout = const Duration(seconds: 20),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (true) {
    final held = (await read()).where((v) => !v.isSpent).toList();
    final outpoints = {for (final v in held) '${v.txid}:${v.vout}'};
    final settled = outpoints.intersection(gone).isEmpty &&
        (arrived == null || outpoints.contains(arrived)) &&
        held.every((v) => v.expiresAt > 0);
    if (settled) return held;
    if (DateTime.now().isAfter(deadline)) return null;
    await Future<void>.delayed(const Duration(milliseconds: 750));
  }
}

/// [deviceToken], when not empty, is enrolled for wakes as the delegate is renewed — see `DkgOpen`
/// in `cosign_session.proto` for why it rides here.
cs.RenewDelegate renewDelegateRequest(
  List<IndexerVtxo> held,
  ArkInfo info, {
  String deviceToken = '',
  String exitScriptPubkeyHex = '',
}) =>
    cs.RenewDelegate(
      vtxos: vtxosToProto(held),
      arkInfo: arkInfoToProto(info),
      deviceToken: deviceToken,
      exitScriptPubkey: hexBytes(exitScriptPubkeyHex),
    );

/// Hex to bytes, for the scriptPubKey that rides the renewal.
List<int> hexBytes(String hex) => [
      for (var i = 0; i + 1 < hex.length; i += 2)
        int.parse(hex.substring(i, i + 2), radix: 16),
    ];

/// The in-band delegate renewal: sighashes in, the wallet's half of the round out, the renewed
/// delegate in. The caller has already sent whatever opens it — `RenewDelegate` after a `Complete`,
/// or a `RenewOpen` with `delegateOnly`.
///
/// [resolve] is the operation's key: handed whatever dealt share these sighashes carried. For a
/// `delegateOnly` open that is the stream's first round and brings the share; after a `Complete` it
/// brings nothing, and the share the send or renewal already rebuilt is reused — see `KeyResolver`.
Future<DelegateStatus> answerDelegateRenewal<Q, R>({
  required Duplex<Q, R> duplex,
  required KeyResolver resolve,
  required threshold.PublicKeyPackage groupPubKey,
  required ({
    List<List<int>> sighashes,
    List<List<int>> exitMessages,
    List<cs.Commitment> commitments,
    String identifier,
    bool scriptPathSpend,
    List<int> dealtShare,
  })? Function(R) sighashesOf,
  required Q Function(List<cs.WalletRound>) signed,
  required cs.DelegateRenewed? Function(R) renewedOf,
  ExitPlan? exits,
}) async {
  final h = sighashesOf(await duplex.next("the delegate's sighashes"));
  if (h == null) throw CosignerException("expected the delegate's sighashes");
  // One round signs the delegate and then the exits. What the cosigner asks for has to be what
  // this wallet independently built, or nothing here is signed.
  final plan = exits ?? ExitPlan.none;
  plan.checkAsked(h.exitMessages);
  final keyPkg = resolve(h.dealtShare);
  duplex.send(signed(answerRound(
    sighashes: [...h.sighashes, ...h.exitMessages],
    cosignerCommitments: h.commitments,
    cosignerIdentifier: h.identifier,
    scriptPathSpend: h.scriptPathSpend,
    keyPkg: keyPkg,
    groupPubKey: groupPubKey,
  )));
  final renewed = renewedOf(await duplex.next('the renewed delegate'));
  if (renewed == null) throw CosignerException('expected the renewed delegate');
  return DelegateStatus.fromRenewed(renewed, exits: plan.accept(renewed.exitTxs));
}

/// Renew the delegate as the last exchange of a stream that just completed. Null when it could not
/// be — the operation already succeeded, and funds left without a delegate are something the app
/// shows, not a failure of the send.
Future<DelegateStatus?> renewDelegateAfter<Q, R>({
  required Duplex<Q, R> duplex,
  required Future<List<IndexerVtxo>?> held,
  required ArkInfo info,
  required KeyResolver resolve,
  required threshold.PublicKeyPackage groupPubKey,
  required Q Function(cs.RenewDelegate) request,
  String deviceToken = '',
  String exitScriptPubkeyHex = '',
  required ({
    List<List<int>> sighashes,
    List<List<int>> exitMessages,
    List<cs.Commitment> commitments,
    String identifier,
    bool scriptPathSpend,
    List<int> dealtShare,
  })? Function(R) sighashesOf,
  required Q Function(List<cs.WalletRound>) signed,
  required cs.DelegateRenewed? Function(R) renewedOf,
  String ownerXOnlyHex = '',
}) async {
  try {
    final set = await held;
    if (set == null || set.isEmpty) return null;
    duplex.send(request(renewDelegateRequest(
      set,
      info,
      deviceToken: deviceToken,
      exitScriptPubkeyHex: exitScriptPubkeyHex,
    )));
    return await answerDelegateRenewal(
      duplex: duplex,
      resolve: resolve,
      groupPubKey: groupPubKey,
      sighashesOf: sighashesOf,
      signed: signed,
      renewedOf: renewedOf,
      exits: exitScriptPubkeyHex.isEmpty
          ? null
          : ExitPlan(
              ownerXOnlyHex: ownerXOnlyHex,
              info: info,
              destinationScriptPubkeyHex: exitScriptPubkeyHex,
              vtxos: set,
            ),
    );
  } on ContributionProtocolException {
    // Not an unlucky renewal: the cosigner sent a second dealt share on one stream. The send or
    // renewal before this did happen, but a cosigner that breaks the one rule about when half a key
    // travels is not something to carry on past quietly.
    rethrow;
  } catch (_) {
    return null;
  }
}
