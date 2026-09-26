import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:app_core/passkey/seed_source.dart';

/// The hand-off a [SeedSource] makes: a seed is asked for *around* the approval of the operation
/// that needs it, belongs to whoever asked, and is kept by nobody else. The headless suites drive
/// the wallet through [FixedSeedSource]; this holds it to the contract a real passkey keeps.
void main() {
  final fixed = Uint8List.fromList(List<int>.generate(32, (i) => (i * 13 + 7) & 0xff));

  group('FixedSeedSource', () {
    test('runs the approval exactly once, and before the seed is handed over', () async {
      final events = <String>[];
      final seed = await FixedSeedSource(fixed).seedDuring(() async => events.add('approved'));
      events.add('seed');
      expect(events, ['approved', 'seed']);
      expect(seed, fixed);
    });

    test('an approval that fails is the caller\'s failure, and yields no seed', () async {
      await expectLater(
        FixedSeedSource(fixed).seedDuring(() async => throw StateError('dismissed')),
        throwsStateError,
      );
    });

    test('hands over a copy the caller may overwrite', () async {
      final source = FixedSeedSource(fixed);
      final first = await source.seedDuring(() async {});
      first.fillRange(0, first.length, 0);
      // The wallet overwrites what it is given; the next operation must still get the seed.
      expect(await source.seedDuring(() async {}), fixed);
    });

    test('is not aliased to the bytes it was built from', () async {
      final mine = Uint8List.fromList(fixed);
      final source = FixedSeedSource(mine);
      mine.fillRange(0, mine.length, 0);
      expect(await source.seedDuring(() async {}), fixed);
    });

    test('rejects a non-32-byte seed', () {
      expect(() => FixedSeedSource(Uint8List(16)), throwsArgumentError);
    });
  });
}
