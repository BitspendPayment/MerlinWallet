/// Knowing the enclave on the other end is the one that was pinned.
///
/// enclave-runtime attaches an attestation document to every `/auth/*` response, in
/// `x-enclave-attestation`, over the nonce the request carried. The document is an AWS Nitro
/// COSE_Sign1 whose `user_data` names two things: the TLS certificate the connection served, and
/// the guest component behind it. Verifying one establishes, together:
///
///  * **the hardware and the image** — the chain reaches the pinned root, and PCR0 is the image;
///  * **the code** — PCR16 is the guest component, measured by that image before it served;
///  * **this connection** — the certificate this socket was served is the one bound inside;
///  * **now** — the nonce is ours and the timestamp is recent.
///
/// Guest responses carry no document. What carries the proof over to them is the certificate: the
/// gate remembers the one it attested, and the cosigner's channel refuses a socket serving any
/// other — see `PinnedTransportConnector`.
///
/// The cryptography is Rust, in `crates/enclave-client`, reached over FFI.
library;

import 'dart:convert';
import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'native_library.dart';

/// The AWS Nitro Enclaves root, G1 — the production trust anchor.
///
/// <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>, DER SHA-256
/// `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`.
const String awsNitroRootG1Pem = '''-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----''';

/// What a client pins about an enclave.
class EnclavePins {
  EnclavePins({
    required this.trustRoot,
    required this.pcr0,
    required this.pcr16,
    this.maxAge = const Duration(minutes: 5),
  });

  /// Against production: the AWS root.
  EnclavePins.aws({required String pcr0, required String pcr16, Duration maxAge = const Duration(minutes: 5)})
      : this(trustRoot: utf8.encode(awsNitroRootG1Pem), pcr0: pcr0, pcr16: pcr16, maxAge: maxAge);

  /// DER or PEM of the root the document's chain must reach. A dev enclave mints its own each boot.
  final List<int> trustRoot;

  /// The runtime image, 96 hex characters.
  final String pcr0;

  /// The guest component, 96 hex characters — what `nitro-attest --measure` prints for it. An
  /// identity only together with [pcr0]: the runtime is what writes this register.
  final String pcr16;

  /// How old a document may be. It is produced on the response it arrives with, so this only has
  /// to absorb clock skew.
  final Duration maxAge;
}

/// A connection the enclave's document vouched for.
class AttestedConnection {
  AttestedConnection({
    required this.certificateSha256,
    required this.guestSha256,
    required this.timestamp,
  });

  /// Hex SHA-256 of the leaf certificate — the one later connections must also be served.
  final String certificateSha256;

  /// Hex SHA-256 of the guest component serving.
  final String guestSha256;

  final DateTime timestamp;
}

/// The document did not vouch for this connection. The message says which check failed.
class AttestationException implements Exception {
  AttestationException(this.message);
  final String message;
  @override
  String toString() => 'attestation refused: $message';
}

/// Verifies a document for a connection. A function so a test can stand one in; production uses
/// [verifyConnection].
typedef ConnectionVerifier = AttestedConnection Function({
  required List<int> document,
  required EnclavePins pins,
  required List<int> servedCertificate,
  required List<int> nonce,
  DateTime? now,
});

typedef _VerifyNative = Pointer<Utf8> Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Uint64, Uint64);
typedef _VerifyDart = Pointer<Utf8> Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Uint8>, int, int, int);
typedef _FreeNative = Void Function(Pointer<Utf8>);
typedef _FreeDart = void Function(Pointer<Utf8>);

late final _verify =
    nativeLib.lookupFunction<_VerifyNative, _VerifyDart>('enclave_verify_connection');
late final _free = nativeLib.lookupFunction<_FreeNative, _FreeDart>('enclave_string_free');

/// Verify [document] — decoded from `x-enclave-attestation` — against [pins], for a connection that
/// served [servedCertificate] (DER, read off the socket) in answer to [nonce] (decoded
/// `x-enclave-nonce`). Throws [AttestationException] if any check fails.
AttestedConnection verifyConnection({
  required List<int> document,
  required EnclavePins pins,
  required List<int> servedCertificate,
  required List<int> nonce,
  DateTime? now,
}) {
  final arena = Arena();
  try {
    Pointer<Uint8> bytes(List<int> b) {
      final p = arena<Uint8>(b.isEmpty ? 1 : b.length);
      p.asTypedList(b.length).setAll(0, b);
      return p;
    }

    final out = _verify(
      bytes(document),
      document.length,
      bytes(pins.trustRoot),
      pins.trustRoot.length,
      pins.pcr0.toNativeUtf8(allocator: arena),
      pins.pcr16.toNativeUtf8(allocator: arena),
      bytes(servedCertificate),
      servedCertificate.length,
      bytes(nonce),
      nonce.length,
      (now ?? DateTime.now()).millisecondsSinceEpoch,
      pins.maxAge.inSeconds,
    );
    final json = jsonDecode(out.toDartString()) as Map<String, dynamic>;
    _free(out);

    if (json['ok'] != true) {
      throw AttestationException(json['error'] as String? ?? 'unknown failure');
    }
    return AttestedConnection(
      certificateSha256: json['certificate_sha256'] as String,
      guestSha256: json['guest_sha256'] as String,
      timestamp: DateTime.fromMillisecondsSinceEpoch((json['timestamp_ms'] as num).toInt()),
    );
  } finally {
    arena.releaseAll();
  }
}
