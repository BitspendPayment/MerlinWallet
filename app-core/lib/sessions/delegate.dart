/// The delegate: funds renewed on a schedule by the cosigner, with nobody connected.
///
/// A VTXO has to be refreshed in a batch round before the ASP's expiry. The wallet signs, while it is
/// here, an intent to refresh everything it holds — valid from the earliest expiry less a margin —
/// and the forfeits the round will need, and the cosigner seals them. When the deadline comes the
/// cosigner runs that round itself, from a background task, against its ASP: no phone, no passkey.
///
/// Sealing rides the end of every `Send` and `Settle`, on the same stream and under the same
/// approval — the passkey gesture that approved the operation also unlocked the share that signs
/// the delegate. Funds that arrive any other way, a receive, are not covered until the wallet seals
/// again; [DelegateStatus] is how the app notices, and `MpcClient.protectFunds` how it seals.
library;

import 'package:protocol/cosigner_v1.dart' as cs;

import '../asp/ark_info.dart';
import '../cosigner/connection.dart';
import '../threshold_types.dart' as threshold;
import 'in_band_round.dart';
import 'send_session.dart';

/// What the sealed delegate covers.
class DelegateStatus {
  DelegateStatus({
    required this.validAt,
    required this.margin,
    required this.covered,
    this.deviceEnrolled = false,
  });

  factory DelegateStatus.fromSealed(cs.DelegateSealed s) => DelegateStatus(
        validAt: DateTime.fromMillisecondsSinceEpoch(s.validAtSecs.toInt() * 1000),
        margin: Duration(seconds: s.marginSecs.toInt()),
        covered: s.covered.toSet(),
        deviceEnrolled: s.deviceEnrolled,
      );

  factory DelegateStatus.fromJson(Map<String, dynamic> j) => DelegateStatus(
        validAt: DateTime.fromMillisecondsSinceEpoch((j['validAt'] as num).toInt() * 1000),
        margin: Duration(seconds: (j['margin'] as num).toInt()),
        covered: (j['covered'] as List).cast<String>().toSet(),
      );

  Map<String, dynamic> toJson() => {
        'validAt': validAt.millisecondsSinceEpoch ~/ 1000,
        'margin': margin.inSeconds,
        'covered': covered.toList(),
      };

  /// When the cosigner will run it.
  final DateTime validAt;

  /// How long before the earliest expiry that is.
  final Duration margin;

  /// `txid:vout` of each VTXO it refreshes.
  final Set<String> covered;

  /// Whether the device token the seal carried was enrolled for wakes. Only meaningful on the seal
  /// that carried one, so not persisted.
  final bool deviceEnrolled;

  bool covers(IndexerVtxo vtxo) => covered.contains('${vtxo.txid}:${vtxo.vout}');
}

/// The wallet's set once the indexer reflects an operation: [gone] no longer held, [arrived] held
/// with a known expiry, and every held VTXO's expiry known. Polls, because indexing trails the ASP
/// by a moment; gives up with null rather than sealing over a set that is not settled yet.
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

/// [deviceToken], when not empty, is enrolled for wakes as the delegate is sealed — see `DkgOpen` in
/// `cosign_session.proto` for why it rides here.
cs.SealDelegate sealMessage(List<IndexerVtxo> held, ArkInfo info, {String deviceToken = ''}) =>
    cs.SealDelegate(vtxos: vtxosToProto(held), arkInfo: arkInfoToProto(info), deviceToken: deviceToken);

/// The in-band seal exchange: sighashes in, the wallet's half of the round out, the sealed delegate
/// in. The caller has already sent whatever opens it — `SealDelegate` after a `Complete`, or a
/// `SettleOpen` with `sealOnly`.
Future<DelegateStatus> answerSeal<Q, R>({
  required Duplex<Q, R> duplex,
  required threshold.KeyPackage keyPkg,
  required threshold.PublicKeyPackage groupPubKey,
  required ({
    List<List<int>> sighashes,
    List<cs.Commitment> commitments,
    String identifier,
    bool scriptPathSpend,
  })? Function(R) sighashesOf,
  required Q Function(List<cs.WalletRound>) signed,
  required cs.DelegateSealed? Function(R) sealedOf,
}) async {
  final h = sighashesOf(await duplex.next("the delegate's sighashes"));
  if (h == null) throw CosignerException("expected the delegate's sighashes");
  duplex.send(signed(answerRound(
    sighashes: h.sighashes,
    cosignerCommitments: h.commitments,
    cosignerIdentifier: h.identifier,
    scriptPathSpend: h.scriptPathSpend,
    keyPkg: keyPkg,
    groupPubKey: groupPubKey,
  )));
  final sealed = sealedOf(await duplex.next('the sealed delegate'));
  if (sealed == null) throw CosignerException('expected the sealed delegate');
  return DelegateStatus.fromSealed(sealed);
}

/// Seal a delegate as the last exchange of a stream that just completed. Null when it could not be —
/// the operation already succeeded, and funds left without a delegate are something the app shows,
/// not a failure of the send.
Future<DelegateStatus?> sealAfter<Q, R>({
  required Duplex<Q, R> duplex,
  required Future<List<IndexerVtxo>?> held,
  required ArkInfo info,
  required threshold.KeyPackage keyPkg,
  required threshold.PublicKeyPackage groupPubKey,
  required Q Function(cs.SealDelegate) seal,
  String deviceToken = '',
  required ({
    List<List<int>> sighashes,
    List<cs.Commitment> commitments,
    String identifier,
    bool scriptPathSpend,
  })? Function(R) sighashesOf,
  required Q Function(List<cs.WalletRound>) signed,
  required cs.DelegateSealed? Function(R) sealedOf,
}) async {
  try {
    final set = await held;
    if (set == null || set.isEmpty) return null;
    duplex.send(seal(sealMessage(set, info, deviceToken: deviceToken)));
    return await answerSeal(
      duplex: duplex,
      keyPkg: keyPkg,
      groupPubKey: groupPubKey,
      sighashesOf: sighashesOf,
      signed: signed,
      sealedOf: sealedOf,
    );
  } catch (_) {
    return null;
  }
}
