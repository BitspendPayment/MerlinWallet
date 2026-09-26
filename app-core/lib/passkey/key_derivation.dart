/// Every secret this wallet holds, derived from the passkey.
///
/// The passkey's PRF returns the same 32 bytes for the same credential, on any device it is synced
/// to. That is the only durable secret the wallet has — nothing secret is kept on the device at
/// all — so this file turns it into the wallet's key material: the two coefficients of the FROST
/// polynomial the wallet deals at DKG.
///
/// Derived, not stored, and derived again for every operation: the same passkey re-derives the
/// same polynomial, and therefore the same identifier and the same half of the share. The other
/// half comes back from the cosigner, which sealed it during the ceremony — on the first round of
/// each signing stream, and from `Recover` on a device that has nothing. See
/// `share_reconstruction.dart` for the sum and `operation_secrets.dart` for how long it lives.
///
/// A KDF is enough here, and a verifiable random function would buy nothing: nobody has to be
/// convinced these were derived correctly. The phone only has to reproduce them, and what it
/// reproduces is checked against the public key the cosigner sealed — a wrong seed fails that check
/// rather than quietly producing a wallet that cannot sign.
///
/// # Labels
///
/// One seed, one HKDF, a label per purpose. Sharing a derivation between two purposes is how one
/// secret ends up equal to another; `SECURITY_FINDINGS` TH-6 flags the repo's earlier improvised
/// derivation (a zero-constant refresh polynomial abused as a KDF, and defined differently in Dart
/// and Rust) for exactly that reason. These labels are versioned because changing one changes
/// every wallet derived from it: a new label is a new wallet.
///
/// **Retired, never to be reused:** `merlin/frost/blind/v1`. It derived the scalar that blinded the
/// share at rest, while a share was kept at rest. Wallets were made under it, so giving it another
/// meaning would make some old device's blinding factor somebody's key.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show Hkdf, Hmac, SecretKey;

import 'package:app_core/threshold/threshold.dart' as threshold;

/// What the wallet deals at DKG: `f(x) = a0 + a1·x`.
///
/// [a0] is also the wallet's own key — its public point is the verifying key the identifier is
/// derived from, and the README's recovery leaf names it as the key that would spend a VTXO alone.
/// It used to be stored beside the share as `onchainSecret`, in the clear, for a consumer that was
/// never written. It is not stored now: whatever comes to need it derives it here, from the
/// passkey, inside an operation — `walletPolynomial(seed).a0`.
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
const String _escrowD0Label = 'merlin/frost/escrow/d0/v1';
const String _escrowD1Label = 'merlin/frost/escrow/d1/v1';
const String _pairingSlopeLabel = 'merlin/frost/pairing/slope/v1';

/// The salt is fixed and public: HKDF's salt adds nothing when the input is already a uniform
/// 32-byte PRF output, and a per-wallet salt would be one more thing to recover.
final Uint8List _salt = Uint8List.fromList('merlin/frost/v1'.codeUnits);

/// The polynomial this wallet deals, from the passkey's PRF output.
Future<WalletPolynomial> walletPolynomial(Uint8List seed) async => WalletPolynomial(
      a0: threshold.SecretKey(await _scalar(seed, _a0Label)),
      a1: await _scalar(seed, _a1Label),
    );

/// What this wallet deals to mint one escrow key: `Δ(x) = d0 + d1·x`.
///
/// Escrowed money must be as recoverable as ordinary money, so this delta is derived rather than
/// drawn — the same passkey on a new device reproduces it, and with the scalar the cosigner sealed
/// that is enough to rebuild the escrow share. A random delta would have made escrow the one thing
/// a lost phone could not get back.
///
/// [context] separates one escrow from the next. **It must never repeat for the same wallet**: two
/// escrows dealt on one delta are two points on one line, and two points determine it. The caller
/// draws it fresh — see `MpcClient.createEscrow` — and the cosigner records which context minted
/// which key, so a repeat is visible rather than silent.
Future<WalletPolynomial> escrowPolynomial(Uint8List seed, Uint8List context) async =>
    WalletPolynomial(
      a0: threshold.SecretKey(await _scalar(seed, _escrowD0Label, context)),
      a1: await _scalar(seed, _escrowD1Label, context),
    );

/// The slope this wallet deals when pairing a service into an escrow.
///
/// Derived rather than drawn, for one reason: **a delivery that failed must be retryable.** The
/// wallet's contribution and the cosigner's reach the service by different routes, and if the
/// wallet's does not arrive it has to be sent again — which means computing the same scalar again.
/// A drawn slope could not be, so "retry" would mean throwing away the cosigner's half as well and
/// pairing from scratch.
///
/// [context] is the escrow key and the attempt id together, so one attempt reproduces and a second
/// attempt is a different line. Reusing a context across two *pairings* would put two of this
/// wallet's dealings on one slope — what `crates/threshold/src/service_poly.rs` exists to warn
/// about — which is why the attempt id is in it, and why the cosigner refuses a confirmation
/// naming an attempt other than the one it sealed.
Future<BigInt> pairingSlope(Uint8List seed, Uint8List context) =>
    _scalar(seed, _pairingSlopeLabel, context);

/// HKDF-SHA256 to 64 bytes, reduced mod n.
///
/// Sixty-four bytes rather than thirty-two: reducing a 32-byte value biases the result towards
/// small scalars by about 2^-128, which is negligible but free to avoid. Zero is refused — it is
/// not a usable scalar and, for `a0`, would be a wallet with no key at all.
/// [context], when given, is appended to the label after a zero byte, so a label with a context and
/// the same label without one can never collide.
Future<BigInt> _scalar(Uint8List seed, String label, [Uint8List? context]) async {
  final info = Uint8List.fromList(
    context == null ? label.codeUnits : [...label.codeUnits, 0, ...context],
  );
  final bytes = await Hkdf(hmac: Hmac.sha256(), outputLength: 64).deriveKey(
    secretKey: SecretKey(seed),
    nonce: _salt,
    info: info,
  );
  final scalar = threshold.modNFromBytesBE(Uint8List.fromList(bytes.bytes));
  if (scalar == BigInt.zero) {
    // Unreachable short of a broken hash, and not something to paper over if it happens.
    throw StateError('deriving $label gave a zero scalar');
  }
  return scalar;
}
