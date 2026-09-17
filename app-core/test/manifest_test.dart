import 'dart:convert';

import 'package:app_core/enclave/manifest.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

final _pcr0 = 'a' * 96;
final _pcr16 = 'b' * 96;

void main() {
  test('an emulated enclave publishes its host, relying party and trust root', () {
    final m = DeploymentManifest.fromJson({
      'host': 'mutiny.vtxos.network',
      'pcr0': _pcr0,
      'pcr16': _pcr16,
      'trust_root': base64.encode([0x30, 0x82, 0x01]),
      'rp_id': 'vtxos.com',
      'commit': 'abc1234',
    });
    expect(m.host, 'mutiny.vtxos.network');
    expect(m.trustRoot, [0x30, 0x82, 0x01]);
    expect(m.rpId, 'vtxos.com');
    expect(m.pcr16, _pcr16);
  });

  test('a Nitro manifest carries no root, so the app pins AWS\'s', () {
    final m = DeploymentManifest.fromJson({'pcr0': _pcr0, 'pcr16': _pcr16});
    expect(m.trustRoot, isNull);
    expect(m.host, isEmpty);
    expect(m.rpId, isEmpty);
  });

  test('an empty trust root is no trust root', () {
    expect(DeploymentManifest.fromJson({'pcr0': _pcr0, 'trust_root': ''}).trustRoot, isNull);
  });

  test('fetched from a URL, and a failed fetch says where', () async {
    final url = Uri.parse('https://example.test/pins/deployment.json');
    final ok = MockClient((r) async => http.Response(jsonEncode({'pcr0': _pcr0, 'pcr16': _pcr16}), 200));
    expect((await fetchManifestFrom(url, client: ok)).pcr0, _pcr0);

    final missing = MockClient((r) async => http.Response('', 404));
    await expectLater(fetchManifestFrom(url, client: missing),
        throwsA(predicate((e) => '$e'.contains('example.test') && '$e'.contains('404'))));
  });
}
