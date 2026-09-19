import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:app_core/passkey/seed_source.dart';
import 'package:app_core/pin_blinding.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;

/// The e2e drives the share-gating crypto through [SeedSource] fakes (no device).
/// This proves the fakes feed [pin_blinding] correctly: a fixed 32-byte seed
/// (PRF stand-in) blinds + reconstructs the share, and the PIN source matches
/// [seedFromPin].
void main() {
  final share = threshold.newSecretKey();

  group('SeedSource', () {
    test('FixedSeedSource round-trips through blind/reconstruct', () async {
      final src = FixedSeedSource(
          Uint8List.fromList(List<int>.generate(32, (i) => (i * 13 + 7) & 0xff)));
      final seed = await src.deriveSeed();
      final delta = await blindShare(share, seed);
      final recovered = await reconstructShare(delta, await src.deriveSeed());
      expect(recovered.scalar, equals(share.scalar));
    });

    test('FixedSeedSource rejects a non-32-byte seed', () {
      expect(() => FixedSeedSource(Uint8List(16)), throwsArgumentError);
    });

    test('PinSeedSource matches seedFromPin and reads the PIN on demand', () async {
      var pin = '123456';
      final src = PinSeedSource(() => pin);
      expect(await src.deriveSeed(), equals(seedFromPin('123456')));
      // Reads on demand: a later PIN change is reflected (not cached).
      pin = '000000';
      expect(await src.deriveSeed(), equals(seedFromPin('000000')));
    });

    test('a wrong seed source reconstructs a different (wrong) share', () async {
      final good = FixedSeedSource(
          Uint8List.fromList(List<int>.generate(32, (i) => i & 0xff)));
      final bad = FixedSeedSource(
          Uint8List.fromList(List<int>.generate(32, (i) => (i + 1) & 0xff)));
      final delta = await blindShare(share, await good.deriveSeed());
      final wrong = await reconstructShare(delta, await bad.deriveSeed());
      expect(wrong.scalar, isNot(equals(share.scalar)));
    });
  });
}
