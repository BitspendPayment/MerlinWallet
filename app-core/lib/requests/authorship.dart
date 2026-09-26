/// Proving who wrote a payment request.
///
/// A request cannot be sent to somebody else's cosigner: enclave-runtime resolves the tenant from the
/// caller's own token and strips any tenant header a client sends, so every connection lands in the
/// caller's own instance. So a request travels out of band — a QR code, a link — and the PAYER's app
/// submits it to the payer's own cosigner. The runtime authenticates that payer, which says nothing
/// about who asked. This does: a BIP-340 signature by the requester's **group** key, which only the
/// requester and their own cosigner together can produce.
///
/// The digest is mirrored byte for byte by `request_digest` in the cosigner's `payment_request.rs`,
/// and a fixed vector in both test suites keeps them agreeing.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// Domain separation. A payment-request signature must never be usable as anything else — least of
/// all a transaction sighash, which is also a 32-byte message signed by this very key.
const String requestDomain = 'merlin/payment-request/v1';

/// The longest a request may stay valid, matching the cosigner's refusal.
const Duration maxRequestValidity = Duration(hours: 24);

/// What the requester signs.
///
/// ```text
/// sha256( domain ‖ payer ‖ requester ‖ amount ‖ expires_in ‖ not_after ‖ nonce ‖ sha256(memo) )
/// ```
///
/// Integers as 8-byte big-endian. The memo goes in hashed so the digest has a fixed shape and a memo
/// cannot be crafted to look like the fields after it.
Uint8List requestDigest({
  required List<int> payerGroupKey,
  required List<int> requesterGroupKey,
  required int amountSats,
  required int expiresInSecs,
  required int notAfter,
  required List<int> nonce,
  required String memo,
}) {
  if (payerGroupKey.length != 33 || requesterGroupKey.length != 33) {
    throw ArgumentError('group keys are 33-byte compressed points');
  }
  if (nonce.length != 16) {
    throw ArgumentError('a request nonce is 16 bytes');
  }
  final ints = ByteData(24)
    ..setUint64(0, amountSats, Endian.big)
    ..setInt64(8, expiresInSecs, Endian.big)
    ..setInt64(16, notAfter, Endian.big);
  final buf = BytesBuilder(copy: false)
    ..add(utf8.encode(requestDomain))
    ..add(payerGroupKey)
    ..add(requesterGroupKey)
    ..add(ints.buffer.asUint8List())
    ..add(nonce)
    ..add(sha256.convert(utf8.encode(memo)).bytes);
  return Uint8List.fromList(sha256.convert(buf.toBytes()).bytes);
}
