/// The wallet's half of a FROST signing round, independent of how it is carried.
///
/// These were inline in `MpcClient.signWithContext`, which was fine while signing was the only
/// thing that signed. It is not: a send and a renewal both pause for the wallet to sign sighashes
/// the cosigner hands back, and each did it by calling the whole of `signWithContext` again. Here
/// the three steps are separate so a driver can run round 1, wait for whatever it is waiting for,
/// and run round 2.
///
/// Nothing about the FFI changes — same `newNonce`, same `frost.sign`, same tweak. Only where they
/// are called from.
library;

import 'dart:typed_data';

import '../threshold.dart' as threshold;
import 'commitment.dart' as frost_comm;
import 'signing.dart' as frost;

/// A nonce and the commitments that go with it.
///
/// The nonce's scalars never leave Rust — the Dart object holds an opaque handle, and the FFI
/// refuses a second use of it. That is what makes a single-use nonce single-use here rather than by
/// convention.
class Round1 {
  Round1(this.nonce, this.hiding, this.binding);
  final frost_comm.SigningNonce nonce;
  final List<int> hiding;
  final List<int> binding;
}

/// Generate this wallet's nonce and commitments for one ceremony.
Round1 frostRound1(threshold.KeyPackage keyPkg) {
  final nonce = frost_comm.newNonce(keyPkg.secretShare);
  return Round1(
    nonce,
    threshold.elemSerializeCompressed(nonce.commitments.hiding),
    threshold.elemSerializeCompressed(nonce.commitments.binding),
  );
}

/// The wallet's signature share, and the public package the result verifies under.
///
/// `applyTweak` is the taproot key-path tweak: on for a key-path spend, off for a script-path one.
/// Getting it wrong produces a share that aggregates to a signature valid under the *other* key,
/// which the ASP rejects with nothing useful to say — so it is a parameter, never a default.
({Uint8List share, threshold.PublicKeyPackage pubPackage}) frostRound2({
  required Map<String, ({List<int> hiding, List<int> binding})> commitments,
  required Uint8List message,
  required Round1 round1,
  required threshold.KeyPackage keyPkg,
  required threshold.PublicKeyPackage groupPubKey,
  required bool applyTweak,
}) {
  final map = <threshold.Identifier, frost_comm.SigningCommitments>{};
  commitments.forEach((idHex, c) {
    map[threshold.Identifier(BigInt.parse(idHex, radix: 16))] = frost_comm.SigningCommitments(
      threshold.elemDeserializeCompressed(Uint8List.fromList(c.binding)),
      threshold.elemDeserializeCompressed(Uint8List.fromList(c.hiding)),
    );
  });

  final pkg = frost_comm.SigningPackage(map, message);
  final signingKey = applyTweak ? keyPkg.tweak(null) : keyPkg;
  final pubPackage = applyTweak ? groupPubKey.tweak(null) : groupPubKey;

  final share = frost.sign(pkg, round1.nonce, signingKey);
  return (share: threshold.bigIntToBytes(share.s), pubPackage: pubPackage);
}

/// Rebuild the aggregate the cosigner returned and check it against the group key.
///
/// Verifying is not a formality: the cosigner aggregates, so this is the wallet's only chance to
/// notice that what came back does not sign the message it asked about.
threshold.Signature frostFinish({
  required List<int> rPoint,
  required List<int> zScalar,
  required threshold.PublicKeyPackage pubPackage,
  required Uint8List message,
}) {
  final r = threshold.elemDeserializeCompressed(Uint8List.fromList(rPoint));
  final z = threshold.bytesToBigInt(Uint8List.fromList(zScalar));
  return threshold.Signature(r, z).verify(pubPackage.verifyingKey, message);
}

/// A BIP-340 signature as the 64 bytes a witness carries: `R.x ‖ z`.
///
/// The compressed R is 33 bytes with a parity prefix; BIP-340 is x-only, so the prefix comes off.
/// This was written out five times across the old client — in each of send, settle, delegate settle
/// and both Ark-wallet signing paths — which is four more chances to drop the wrong byte.
Uint8List schnorr64(threshold.Signature sig) {
  final serialized = sig.serialize();
  return Uint8List.fromList(serialized);
}
