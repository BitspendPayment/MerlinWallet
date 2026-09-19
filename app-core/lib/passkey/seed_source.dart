import 'dart:typed_data';

/// Where the wallet's 32-byte seed comes from: the passkey's PRF output, or something standing in
/// for one. Everything the wallet derives — its polynomial, and so its half of its share — comes
/// from these bytes (`key_derivation.dart`), and they are never stored.
///
/// # One gesture, one seed, one owner
///
/// A seed is asked for *around* the approval of the operation that needs it:
///
/// ```dart
/// final seed = await source.seedDuring(() => connection.approveAhead('Send'));
/// ```
///
/// A passkey evaluates its PRF on the same assertion that approves a call, so the approval's own
/// fingerprint yields the seed and an operation costs one gesture, not two. [seedDuring] is that
/// hand-off made explicit. It used to be implicit — every assertion left its PRF output in a cache
/// for two minutes and `deriveSeed()` read whatever was there — which made the seed's lifetime a
/// clock's business and let an approval for something else entirely leave one lying around.
///
/// The contract:
///  * [approve] is run exactly once, and its failure is the caller's failure.
///  * The bytes returned are a fresh copy that **the caller owns and must overwrite** — see
///    `WalletOperation.begin`, which does.
///  * The source keeps nothing afterwards. An assertion made outside a [seedDuring] leaves no seed
///    behind, and a real passkey does not even evaluate the PRF for one.
///  * If [approve] produced no assertion of its own — there is no gate in front of this cosigner —
///    the source asks for the seed by itself.
abstract class SeedSource {
  Future<Uint8List> seedDuring(Future<void> Function() approve);
}

/// A fixed high-entropy seed — the e2e / headless stand-in for a real passkey PRF
/// output. NOT for production use: the seed lives in this object for as long as it does.
class FixedSeedSource implements SeedSource {
  final Uint8List _seed;

  FixedSeedSource(Uint8List seed) : _seed = Uint8List.fromList(seed) {
    if (_seed.length != 32) {
      throw ArgumentError(
          'a PRF-style seed must be 32 bytes, got ${_seed.length}');
    }
  }

  @override
  Future<Uint8List> seedDuring(Future<void> Function() approve) async {
    await approve();
    // A copy: the caller overwrites what it is given.
    return Uint8List.fromList(_seed);
  }
}
