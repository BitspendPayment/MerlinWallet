/// Every secret this wallet holds, derived from the passkey.
///
/// The passkey's PRF returns the same 32 bytes for the same credential, on any device it is synced
/// to. That is the only durable secret the wallet has — the share on disk dies with the phone — so
/// this file turns it into the wallet's key material: the two coefficients of the FROST polynomial
/// the wallet deals at DKG, and the scalar that blinds the resulting share at rest.
///
/// Derived, not stored, which is what makes a wallet recoverable: the same passkey on a new phone
/// re-derives the same polynomial, and therefore the same identifier and the same half of the
/// share. The other half comes back from the cosigner, which sealed it during the ceremony — see
/// `MpcClient.recover`.
///
/// A KDF is enough here, and a verifiable random function would buy nothing: nobody has to be
/// convinced these were derived correctly. The phone only has to reproduce them, and what it
/// reproduces is checked against the public key the cosigner sealed — a wrong seed fails that check
/// rather than quietly producing a wallet that cannot sign.
///
/// # Labels
///
/// One seed, one HKDF, a label per purpose. Sharing a derivation between two purposes is how a
/// blinding factor ends up equal to a secret key; `SECURITY_FINDINGS` TH-6 flags the repo's earlier
/// improvised derivation (a zero-constant refresh polynomial abused as a KDF, and defined
/// differently in Dart and Rust) for exactly that reason. These labels are versioned because
/// changing one changes every wallet derived from it: a new label is a new wallet.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show Hkdf, Hmac, SecretKey;

import 'package:app_core/threshold/threshold.dart' as threshold;

/// What the wallet deals at DKG: `f(x) = a0 + a1·x`.
///
/// [a0] is also the wallet's own key — its public point is the verifying key the identifier is
/// derived from, and the README's recovery leaf names it as the key that would spend a VTXO alone.
class WalletPolynomial {
  const WalletPolynomial({required this.a0, required this.a1});

  final threshold.SecretKey a0;
  final BigInt a1;

  /// The coefficients in the order `dkgPart1` takes them, `a0` excluded — it is passed separately.
  List<BigInt> get higherCoefficients => [a1];
}

/// The labels. Each is a distinct purpose; none may be reused for another.
const String _a0Label = 'merlin/frost/dkg/a0/v1';
const String _a1Label = 'merlin/frost/dkg/a1/v1';
const String _blindLabel = 'merlin/frost/blind/v1';

/// The salt is fixed and public: HKDF's salt adds nothing when the input is already a uniform
/// 32-byte PRF output, and a per-wallet salt would be one more thing to recover.
final Uint8List _salt = Uint8List.fromList('merlin/frost/v1'.codeUnits);

/// The polynomial this wallet deals, from the passkey's PRF output.
Future<WalletPolynomial> walletPolynomial(Uint8List seed) async => WalletPolynomial(
      a0: threshold.SecretKey(await _scalar(seed, _a0Label)),
      a1: await _scalar(seed, _a1Label),
    );

/// The scalar the share is blinded by at rest. Blind and reconstruct cancel because both derive it
/// from the same seed; a wrong seed gives a wrong share, never the real one.
Future<BigInt> blindingScalar(Uint8List seed) => _scalar(seed, _blindLabel);

/// HKDF-SHA256 to 64 bytes, reduced mod n.
///
/// Sixty-four bytes rather than thirty-two: reducing a 32-byte value biases the result towards
/// small scalars by about 2^-128, which is negligible but free to avoid. Zero is refused — it is
/// not a usable scalar and, for `a0`, would be a wallet with no key at all.
Future<BigInt> _scalar(Uint8List seed, String label) async {
  final bytes = await Hkdf(hmac: Hmac.sha256(), outputLength: 64).deriveKey(
    secretKey: SecretKey(seed),
    nonce: _salt,
    info: Uint8List.fromList(label.codeUnits),
  );
  final scalar = threshold.modNFromBytesBE(Uint8List.fromList(bytes.bytes));
  if (scalar == BigInt.zero) {
    // Unreachable short of a broken hash, and not something to paper over if it happens.
    throw StateError('deriving $label gave a zero scalar');
  }
  return scalar;
}
