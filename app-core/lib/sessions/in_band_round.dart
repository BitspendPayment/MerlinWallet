/// The wallet's half of a FROST round, carried inside the stream that needs the signatures.
///
/// A send and a settle both stop for the wallet to sign sighashes the cosigner built. They used to
/// open a *second* stream — a nested `Sign` per sighash — while the outer stream waited. That
/// deadlocks inside enclave-runtime, which runs **one request per tenant for the whole life of a
/// stream**: the outer stream holds the tenant, the nested one waits for it, and nothing moves
/// until the interaction deadline kills both. This was measured against a running enclave, and a
/// second call blocks just the same on a separate TCP connection, so a second channel is no way
/// round it.
///
/// So the round rides the stream it belongs to, and costs one round trip for the whole batch where
/// the nested form cost two per signature:
///
/// ```text
///   cosigner → sighashes + its commitment for each
///   wallet   → its commitment + its share for each     ← this file
///   cosigner → aggregates, and carries on
/// ```
///
/// The cosigner commits first, and that is fine: FROST needs both commitments before either share,
/// not the wallet's before the cosigner's. By the time these arrive the wallet holds both.
///
/// What the wallet no longer does is verify the finished signature — it never sees it. That was
/// never the protection it looked like. A share is bound to one message and one pair of
/// commitments, so it cannot be aggregated over anything else; it would simply fail to verify. And
/// the cosigner checks every share against its verifying share before summing, so a bad share is
/// refused there, by index, rather than by the ASP with nothing to say.
library;

import 'dart:typed_data';

import 'package:protocol/cosigner_v1.dart' as cs;

import '../cosigner/connection.dart';
import '../threshold/frost/ceremony.dart';
import '../threshold_types.dart' as threshold;

/// Commit and sign every sighash the cosigner sent, in the order it sent them.
///
/// [scriptPathSpend] comes from the cosigner and selects the taproot tweak. It is always true on
/// these streams: the cosigner signs untweaked, and a key-path tweak is compensated entirely on the
/// wallet's share — which the cosigner's share check would refuse. So a `false` here is not a
/// signature waiting to happen but a protocol the cosigner does not speak, and is refused as such.
List<cs.WalletRound> answerRound({
  required List<List<int>> sighashes,
  required List<cs.Commitment> cosignerCommitments,
  required String cosignerIdentifier,
  required bool scriptPathSpend,
  required threshold.KeyPackage keyPkg,
  required threshold.PublicKeyPackage groupPubKey,
}) {
  if (cosignerCommitments.length != sighashes.length) {
    // One short would sign every message against its neighbour's commitment, and the failure would
    // come back naming the wrong message.
    throw CosignerException(
      'the cosigner sent ${cosignerCommitments.length} commitments for '
      '${sighashes.length} sighashes',
    );
  }
  if (!scriptPathSpend) {
    throw CosignerException(
      'the cosigner asked for a key-path signature in-band, which cannot aggregate: the tweak is '
      'compensated on the wallet share alone and the cosigner signs untweaked',
    );
  }
  if (cosignerIdentifier.isEmpty && sighashes.isNotEmpty) {
    throw CosignerException('the cosigner sent commitments without saying whose they are');
  }

  // The keys `frostRound2` expects are identifiers as hex numbers. Parsed as integers on the other
  // side, so leading zeros neither help nor hurt — the cosigner's 32-byte form and this one name
  // the same identifier.
  final ours = keyPkg.identifier.toScalar().toRadixString(16);

  return [
    for (var i = 0; i < sighashes.length; i++)
      _answer(
        message: Uint8List.fromList(sighashes[i]),
        theirs: cosignerCommitments[i],
        theirId: cosignerIdentifier,
        ourId: ours,
        keyPkg: keyPkg,
        groupPubKey: groupPubKey,
      ),
  ];
}

cs.WalletRound _answer({
  required Uint8List message,
  required cs.Commitment theirs,
  required String theirId,
  required String ourId,
  required threshold.KeyPackage keyPkg,
  required threshold.PublicKeyPackage groupPubKey,
}) {
  // A fresh nonce per message. Its scalars never leave Rust, and the FFI refuses a second use.
  final round1 = frostRound1(keyPkg);
  final round2 = frostRound2(
    commitments: {
      theirId: (hiding: theirs.hiding, binding: theirs.binding),
      ourId: (hiding: round1.hiding, binding: round1.binding),
    },
    message: message,
    round1: round1,
    keyPkg: keyPkg,
    groupPubKey: groupPubKey,
    // Always false here — refused above otherwise. Kept as the expression it means rather than a
    // literal, so the relationship to `scriptPathSpend` stays readable.
    applyTweak: false,
  );
  return cs.WalletRound(hiding: round1.hiding, binding: round1.binding, share: round2.share);
}
