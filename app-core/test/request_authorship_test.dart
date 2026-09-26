/// The payment-request digest, pinned against the cosigner.
///
/// `request_digest` in the cosigner's `payment_request.rs` computes the same bytes independently, and
/// the cosigner refuses any request whose signature does not verify over its own digest — so a single
/// byte of disagreement refuses every request, with nothing on the wire to say why. Both suites assert
/// this vector. It was also derived a third way, straight from the spec in `mpc_wallet.proto`, so it
/// checks the implementations against the spec rather than only against each other.
library;

import 'package:app_core/requests/authorship.dart';
import 'package:convert/convert.dart';
import 'package:test/test.dart';

void main() {
  test('the digest matches the vector the cosigner pins', () {
    final digest = requestDigest(
      payerGroupKey: [0x02, ...List.filled(32, 0x11)],
      requesterGroupKey: [0x03, ...List.filled(32, 0x22)],
      amountSats: 5000,
      expiresInSecs: 3600,
      notAfter: 1900000000,
      nonce: List<int>.generate(16, (i) => i),
      memo: 'invoice 1',
    );
    expect(hex.encode(digest),
        '00357a6997451fd8a7de58208fb1afb10bf0ffc809c7ca4db9ab1c7a759fab74');
  });

  test('every signed field moves the digest', () {
    Map<String, Object> base() => {
          'payer': [0x02, ...List.filled(32, 0x11)],
          'requester': [0x03, ...List.filled(32, 0x22)],
          'amount': 5000,
          'expires': 3600,
          'notAfter': 1900000000,
          'nonce': List<int>.generate(16, (i) => i),
          'memo': 'invoice 1',
        };
    String digestOf(Map<String, Object> f) => hex.encode(requestDigest(
          payerGroupKey: f['payer'] as List<int>,
          requesterGroupKey: f['requester'] as List<int>,
          amountSats: f['amount'] as int,
          expiresInSecs: f['expires'] as int,
          notAfter: f['notAfter'] as int,
          nonce: f['nonce'] as List<int>,
          memo: f['memo'] as String,
        ));
    final reference = digestOf(base());
    final changes = <String, Object>{
      'payer': [0x03, ...List.filled(32, 0x11)],
      'requester': [0x02, ...List.filled(32, 0x22)],
      'amount': 5001,
      'expires': 3601,
      'notAfter': 1900000001,
      'nonce': List<int>.generate(16, (i) => i + 1),
      'memo': 'invoice 2',
    };
    changes.forEach((field, value) {
      expect(digestOf({...base(), field: value}), isNot(reference),
          reason: '$field must be covered by the signature');
    });
  });

  test('malformed keys and nonces are refused', () {
    expect(
      () => requestDigest(
        payerGroupKey: List.filled(32, 1),
        requesterGroupKey: [0x02, ...List.filled(32, 1)],
        amountSats: 1, expiresInSecs: 0, notAfter: 0,
        nonce: List.filled(16, 0), memo: '',
      ),
      throwsArgumentError,
    );
    expect(
      () => requestDigest(
        payerGroupKey: [0x02, ...List.filled(32, 1)],
        requesterGroupKey: [0x02, ...List.filled(32, 1)],
        amountSats: 1, expiresInSecs: 0, notAfter: 0,
        nonce: List.filled(8, 0), memo: '',
      ),
      throwsArgumentError,
    );
  });
}
