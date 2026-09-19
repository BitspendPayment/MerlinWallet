/// Rebuilding the wallet's FROST share from its two halves.
///
/// A share is the sum of both dealers' polynomials at the wallet's identifier:
///
/// ```text
///   s = f_wallet(id) + f_cosigner(id)
/// ```
///
/// The first term is derived from the passkey's PRF (`key_derivation.dart`). The second is the one
/// scalar the cosigner sealed at DKG and hands back — on `Recover` to a device that has nothing,
/// and on the first round of every `Sign`, `Send` and `Settle` since the wallet stopped keeping a
/// share. Neither term is the key; the sum is, and it is held for one operation.
///
/// **Nothing is taken on the cosigner's word.** What the sum is checked against — the identifier,
/// the verifying share, the group key — is what this device stored when the wallet was made, not
/// what arrived with the contribution. So a cosigner that sends the wrong scalar, a passkey that is
/// not this wallet's, and a PRF that answers differently all end the same way: a typed refusal
/// here, before anything is signed, rather than a FROST aggregation failure several messages later
/// that names none of them.
library;

import 'dart:typed_data';

import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/passkey/wallet_public_state.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;

/// Why a share could not be rebuilt. Each is a different thing to tell the owner.
sealed class ShareReconstructionException implements Exception {
  const ShareReconstructionException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// The passkey derives a different wallet: its identifier is not the one this wallet was made with.
/// A different passkey, or the same one with a PRF that answers differently on this device.
final class WrongPasskey extends ShareReconstructionException {
  const WrongPasskey()
      : super('this passkey does not derive this wallet: the identifier it gives is not the one '
            'the wallet was made with. It is a different passkey, or its PRF answers differently '
            'here than when the wallet was made.');
}

/// The identifier is not in the key package: this wallet took no part in that ceremony.
final class NotAMember extends ShareReconstructionException {
  const NotAMember()
      : super('this wallet is not a member of that ceremony — its identifier is not in the key '
            'package');
}

/// The key package is for another wallet: its group key is not the expected one.
final class GroupKeyMismatch extends ShareReconstructionException {
  GroupKeyMismatch({required String expected, required String got})
      : super('the key package is for a different wallet: expected group key $expected, got $got');
}

/// What the cosigner sent is not a scalar a share could be built from.
final class InvalidContribution extends ShareReconstructionException {
  const InvalidContribution(String why) : super('the cosigner\'s half of the share is unusable: $why');
}

/// Both halves were well-formed and the sum is still not this wallet's share.
final class ShareMismatch extends ShareReconstructionException {
  const ShareMismatch()
      : super('the share this passkey and the cosigner rebuild is not the one this wallet signs '
            'with: what the cosigner returned is not what it dealt this wallet.');
}

/// The identifier [polynomial] deals as: `Identifier.derive(compressed(a0·G))`.
threshold.Identifier identifierOf(WalletPolynomial polynomial) => threshold.Identifier.derive(
    threshold.elemSerializeCompressed(threshold.elemBaseMul(polynomial.a0.scalar)));

/// The wallet's key package, from its own [polynomial] and the [dealtShare] the cosigner returned,
/// checked against [wallet].
///
/// `dkg_part3` normalizes every share to an even-Y group key, which negates it when the group key
/// came out odd — so the sum is right up to a sign, and the verifying share says which. Trying both
/// is not guesswork: exactly one can match.
///
/// Throws a [ShareReconstructionException]. Never returns a share that has not been shown to be
/// the right one.
threshold.KeyPackage reconstructWalletShare({
  required WalletPolynomial polynomial,
  required List<int> dealtShare,
  required WalletPublicState wallet,
}) {
  final identifier = identifierOf(polynomial);
  if (identifier != wallet.identifier) throw const WrongPasskey();

  if (dealtShare.length != 32) {
    throw InvalidContribution('it is ${dealtShare.length} bytes, not 32');
  }
  final n = threshold.secp256k1Curve.n;
  final dealt = threshold.bytesToBigInt(Uint8List.fromList(dealtShare));
  // Zero would make the "sum" the wallet's own half, and anything at or above n is not a scalar
  // the cosigner could have dealt. Neither can pass the check below, but each deserves its name.
  if (dealt == BigInt.zero) throw const InvalidContribution('it is zero');
  if (dealt >= n) throw const InvalidContribution('it is not below the group order');

  final own = threshold.evaluatePolynomial(
      identifier, [polynomial.a0.scalar, ...polynomial.higherCoefficients]);
  final sum = (own + dealt) % n;
  final expected = wallet.verifyingShare.toLowerCase();
  for (final candidate in [sum, (n - sum) % n]) {
    if (candidate == BigInt.zero) continue;
    if (threshold.elemBaseMul(candidate).toLowerCase() == expected) {
      return threshold.KeyPackage(
        identifier,
        candidate,
        wallet.verifyingShare,
        wallet.publicKeyPackage.verifyingKey,
        wallet.minSigners,
      );
    }
  }
  throw const ShareMismatch();
}

/// What a device with nothing stored learns from `Recover`: the ceremony's public half, checked
/// for being one ceremony about one wallet that [identifier] took part in.
///
/// This is the one place the public state comes from the cosigner rather than from this device, so
/// it is also where the two things the cosigner said are checked against each other.
WalletPublicState publicStateFromRecovery({
  required threshold.PublicKeyPackage publicKeyPackage,
  required String claimedGroupKeyHex,
  required threshold.Identifier identifier,
  required int minSigners,
}) {
  // Hex from two languages: compared as bytes would be, not as the strings happen to be cased.
  final derived = publicKeyPackage.verifyingKey.E.toLowerCase();
  if (derived != claimedGroupKeyHex.toLowerCase()) {
    throw GroupKeyMismatch(expected: claimedGroupKeyHex.toLowerCase(), got: derived);
  }
  if (!publicKeyPackage.verifyingShares.containsKey(identifier)) throw const NotAMember();
  return WalletPublicState.fromPublicKeyPackage(publicKeyPackage, identifier,
      minSigners: minSigners);
}
