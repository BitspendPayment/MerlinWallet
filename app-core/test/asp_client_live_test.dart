/// The ASP client against a real arkd.
///
/// Skipped unless one is reachable — `make arkd-up` provides it on 127.0.0.1:7070. These assert the
/// two things a transliteration can get wrong and a unit test cannot catch: that the generated
/// stubs match the server's actual service, and that the field mapping survives a round trip.
library;

import 'package:app_core/asp/asp_client.dart';
import 'package:test/test.dart';

const _host = '127.0.0.1';
const _port = 7070;

Future<bool> _reachable() async {
  final c = AspClient.connect(_host, _port);
  try {
    await c.getInfo();
    return true;
  } catch (_) {
    return false;
  } finally {
    await c.shutdown();
  }
}

void main() {
  late bool up;
  setUpAll(() async => up = await _reachable());

  test('getInfo returns parameters an address can be derived from', () async {
    if (!up) {
      markTestSkipped('no ASP on $_host:$_port — run `make arkd-up`');
      return;
    }
    final c = AspClient.connect(_host, _port);
    addTearDown(c.shutdown);

    final info = await c.getInfo();
    expect(info.signerPubkey, isNotEmpty,
        reason: 'every VTXO script is derived from the signer key');
    expect(info.signerPubkey.length, anyOf(64, 66),
        reason: 'an x-only or compressed pubkey in hex');
    expect(info.network, isNotEmpty);
    expect(info.unilateralExitDelay, greaterThan(0));
    expect(info.boardingExitDelay, greaterThan(0),
        reason: 'a wallet holds both delays, so both must be real');
  });

  test('getInfo caches, and refresh re-asks', () async {
    if (!up) {
      markTestSkipped('no ASP on $_host:$_port');
      return;
    }
    final c = AspClient.connect(_host, _port);
    addTearDown(c.shutdown);

    final first = await c.getInfo();
    expect(identical(await c.getInfo(), first), isTrue, reason: 'cached between sends');
    expect(identical(await c.getInfo(refresh: true), first), isFalse,
        reason: 'refresh must actually re-ask');
  });

  test('an empty query is answered locally, not sent', () async {
    if (!up) {
      markTestSkipped('no ASP on $_host:$_port');
      return;
    }
    final c = AspClient.connect(_host, _port);
    addTearDown(c.shutdown);

    expect(await c.getVtxosByScripts(const []), isEmpty);
    expect(await c.getVtxosByOutpoints(const []), isEmpty);
  });

  test('an unknown script has no VTXOs, and that is not an error', () async {
    if (!up) {
      markTestSkipped('no ASP on $_host:$_port');
      return;
    }
    final c = AspClient.connect(_host, _port);
    addTearDown(c.shutdown);

    // A well-formed P2TR scriptPubKey nobody has paid.
    final vtxos = await c.getVtxosByScripts(['5120${'ab' * 32}']);
    expect(vtxos, isEmpty);
  });

  test('a refusal arrives as AspException, naming the call', () async {
    final c = AspClient.connect(_host, 1);
    addTearDown(c.shutdown);
    await expectLater(
      c.getInfo(),
      throwsA(isA<AspException>().having((e) => e.call, 'call', 'GetInfo')),
    );
  });
}
