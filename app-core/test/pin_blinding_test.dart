import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:app_core/pin_blinding.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;

/// Headless round-trip for the share blinding (`δ = share − b`, reconstruct `share = δ + b`). No
/// DKG or device needed — the blinding is scalar arithmetic over any share, and `b` now comes from
/// the same HKDF that derives the wallet's key, one label apart.
void main() {
  final share = threshold.newSecretKey();

  group('share blinding', () {
    test('the right seed reconstructs the original share', () async {
      final seed = seedFromPin('123456');
      final delta = await blindShare(share, seed);
      expect((await reconstructShare(delta, seed)).scalar, equals(share.scalar));
    });

    test('delta alone does not reveal the share', () async {
      final delta = await blindShare(share, seedFromPin('123456'));
      expect(threshold.bytesToBigInt(delta), isNot(equals(share.scalar)),
          reason: 'δ must not equal the raw share');
    });

    test('a wrong seed reconstructs a different share, never the real one', () async {
      final delta = await blindShare(share, seedFromPin('123456'));
      final wrong = await reconstructShare(delta, seedFromPin('000000'));
      expect(wrong.scalar, isNot(equals(share.scalar)));
    });

    test('the same seed yields the same delta', () async {
      expect(await blindShare(share, seedFromPin('42')),
          equals(await blindShare(share, seedFromPin('42'))));
    });

    test('a high-entropy (PRF-style) 32-byte seed round-trips too', () async {
      final prfSeed =
          Uint8List.fromList(List<int>.generate(32, (i) => (i * 31 + 5) & 0xff));
      final delta = await blindShare(share, prfSeed);
      expect((await reconstructShare(delta, prfSeed)).scalar, equals(share.scalar));
    });
  });
}
