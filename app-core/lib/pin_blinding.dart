/// Blinding the wallet's FROST share at rest.
///
/// The share is never persisted in the clear: what the device stores is `δ = share − b`, where `b`
/// comes from the passkey's PRF output (`passkey/key_derivation.dart`). Reconstruct with
/// `share = δ + b`. Only the right passkey yields the real share — a wrong one produces a scalar
/// that fails FROST aggregation rather than anything spendable — and the cosigner's own share is
/// untouched, so this is purely a client-side lock.
///
/// The blinding scalar used to come from a zero-constant refresh polynomial seeded with the PRF
/// output, a derivation defined differently in Dart and Rust and flagged as a footgun by
/// `SECURITY_FINDINGS` TH-6. It is now one label of the same HKDF that derives the wallet's key, so
/// there is one derivation with one meaning per label.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;

import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;

/// Derive the blinding seed from a user PIN.
///
/// WARNING: a PIN is low-entropy — this is a UX lock, not cryptographic protection. It is also not
/// a wallet's seed: the key itself is derived from the passkey's PRF (`passkey/key_derivation.dart`)
/// and a wallet whose seed is a PIN has no way back from a lost device. The PRF is the real source.
Uint8List seedFromPin(String pin) =>
    Uint8List.fromList(sha256.convert(utf8.encode(pin)).bytes);

/// Blind [share] under [seed]: returns `δ = share − b` (32 bytes), safe to persist.
Future<Uint8List> blindShare(threshold.SecretKey share, Uint8List seed) async {
  final b = await blindingScalar(seed);
  return threshold.bigIntToBytes(threshold.modNSub(share.scalar, b));
}

/// Reconstruct `share = δ + b` from [delta] and [seed].
Future<threshold.SecretKey> reconstructShare(Uint8List delta, Uint8List seed) async {
  final b = await blindingScalar(seed);
  return threshold.SecretKey(threshold.modNAdd(threshold.bytesToBigInt(delta), b));
}
