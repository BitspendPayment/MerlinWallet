/// The Dart binding to the Rust verifier, against the real dev-enclave document the Rust tests use
/// (`crates/enclave-client/tests/fixtures`). What this adds over those is the marshalling: every
/// argument crosses FFI in the right slot, and a refusal comes back as an [AttestationException]
/// naming the check.
library;

import 'dart:io';

import 'package:app_core/enclave/attestation.dart';
import 'package:convert/convert.dart';
import 'package:test/test.dart';

void main() {
  final fixtures = '${Directory.current.parent.path}/crates/enclave-client/tests/fixtures';
  List<int> read(String name) => File('$fixtures/$name').readAsBytesSync();

  final document = read('dev-document.cose');
  final servedLeaf = read('dev-served-leaf.der');
  final nonce = hex.decode(File('$fixtures/dev-nonce.hex').readAsStringSync().trim());
  EnclavePins pins({String? pcr16}) => EnclavePins(
        trustRoot: read('dev-trust-root.der'),
        pcr0: '8f2026d5a6c50479e27152c06ca86852ce0ec9528efd5f13d8bee969f128076adf1c720ead49d5629724fe2562a1cd99',
        pcr16: pcr16 ??
            'e5d19028de3519c28511df1942d0bac7ba3e633707adbd3c4017d4ba8ca8e515a1b79e5b91081ec19267cf35f732f9b3',
      );
  // The dev chain is valid for 30 days from its boot; judge it at the moment it was produced.
  final producedAt = DateTime.utc(2026, 9, 16, 8, 55, 30);

  test('the captured document verifies, and says what it bound', () {
    final attested = verifyConnection(
      document: document,
      pins: pins(),
      servedCertificate: servedLeaf,
      nonce: nonce,
      now: producedAt,
    );
    expect(attested.certificateSha256, 'a9f24f8f55d4541b3dddccc4a73ee585e03e1722da0bdd00855472111114188c');
    expect(attested.guestSha256, '8c8e83402faafdaf775f7b421ede83bc1d8325eba84f97395c91783271f9d51f');
  });

  test('a refusal names the check that failed', () {
    expect(
      () => verifyConnection(
        document: document,
        pins: pins(pcr16: '00' * 48),
        servedCertificate: servedLeaf,
        nonce: nonce,
        now: producedAt,
      ),
      throwsA(isA<AttestationException>().having((e) => e.message, 'message', contains('PCR16'))),
    );
    expect(
      () => verifyConnection(
        document: document,
        pins: pins(),
        servedCertificate: [...servedLeaf, 0],
        nonce: nonce,
        now: producedAt,
      ),
      throwsA(isA<AttestationException>().having((e) => e.message, 'message', contains('certificate'))),
    );
  });
}
