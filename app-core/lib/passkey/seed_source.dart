import 'dart:typed_data';

import 'package:app_core/pin_blinding.dart' show seedFromPin;

/// Source of the 32-byte blinding seed for the wallet's FROST share (see
/// `pin_blinding.dart`). The consumer treats the seed as OPAQUE bytes, so the
/// source is swappable without touching the blinding math:
///  - the app's `PlatformPasskey.seedSource` (production, device-only) — the passkey's PRF
///    output `prfResults.first` (32 unguessable bytes → real security).
///  - [PinSeedSource] — `sha256(PIN)` (a UX lock; low entropy, brute-forceable).
///  - [FixedSeedSource] — a constant seed standing in for a PRF output in
///    headless tests / e2e (no device needed).
abstract class SeedSource {
  Future<Uint8List> deriveSeed();
}

/// PIN-derived seed. Reads the PIN on demand (via the supplied callback) so the
/// PIN is never cached in this object. UX lock only — a passkey's PRF is the real thing.
class PinSeedSource implements SeedSource {
  final String Function() _readPin;

  PinSeedSource(this._readPin);

  @override
  Future<Uint8List> deriveSeed() async => seedFromPin(_readPin());
}

/// A fixed high-entropy seed — the e2e / headless stand-in for a real passkey PRF
/// output. NOT for production use.
class FixedSeedSource implements SeedSource {
  final Uint8List _seed;

  FixedSeedSource(this._seed) {
    if (_seed.length != 32) {
      throw ArgumentError(
          'a PRF-style seed must be 32 bytes, got ${_seed.length}');
    }
  }

  @override
  Future<Uint8List> deriveSeed() async => _seed;
}
