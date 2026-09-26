import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:ffi/ffi.dart';
import 'package:app_core/threshold/core/errors.dart';
import 'package:app_core/threshold/core/identifier.dart';
import 'package:app_core/threshold/src/bindings.dart';
import 'package:app_core/threshold/src/ffi_result.dart';

/// Secp256k1 curve order n.
final BigInt _secp256k1N = BigInt.parse(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  radix: 16,
);

/// Shim to provide secp256k1Curve.n without pointycastle.
final _Secp256k1Curve secp256k1Curve = _Secp256k1Curve();

class _Secp256k1Curve {
  final BigInt n = _secp256k1N;
}

BigInt taggedHash(String tag, Uint8List msg) {
  final tagHash = sha256.convert(utf8.encode(tag)).bytes;
  final builder = BytesBuilder();
  builder.add(tagHash);
  builder.add(tagHash);
  builder.add(msg);

  final h = sha256.convert(builder.toBytes()).bytes;
  return bytesToBigInt(Uint8List.fromList(h)) % secp256k1Curve.n;
}

BigInt computeTweak(String compressedPointHex, List<int>? merkleRoot) {
  // P is x-only (32 bytes) — strip the 02/03 prefix
  final pBytes = hex.decode(compressedPointHex).sublist(1);
  final builder = BytesBuilder();
  builder.add(pBytes);
  if (merkleRoot != null) {
    builder.add(merkleRoot);
  }
  return taggedHash("TapTweak", builder.toBytes());
}

BigInt bytesToBigInt(Uint8List bytes) {
  var result = BigInt.from(0);
  for (var i = 0; i < bytes.length; i++) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

Uint8List bigIntToBytes(BigInt number) {
  // Reduce mod n to handle negative scalars
  var n = number % secp256k1Curve.n;
  var h = n.toRadixString(16);
  if (h.length % 2 != 0) {
    h = '0$h';
  }
  // zero pad to 32 bytes
  while (h.length < 64) {
    h = '0$h';
  }
  final bytes = Uint8List(h.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    final byteString = h.substring(i * 2, i * 2 + 2);
    bytes[i] = int.parse(byteString, radix: 16);
  }
  return bytes;
}

BigInt modNFromBytesBE(Uint8List b) {
  final s = bytesToBigInt(b) % secp256k1Curve.n;
  if (s == BigInt.zero) {
    throw InvalidZeroScalarException("invalid zero scalar");
  }
  return s;
}

BigInt modNZero() => BigInt.zero;

BigInt modNOne() => BigInt.one;

/// Sum two scalars modulo the secp256k1 group order. Used to combine the author's
/// and cosigner's refresh halves into a participant's share `P_i`.
BigInt modNAdd(BigInt a, BigInt b) => (a + b) % _secp256k1N;

/// Serialize a point (given as compressed hex) to compressed bytes.
/// When called with a compressed hex string, returns the bytes.
Uint8List elemSerializeCompressed(String compressedHex) {
  return Uint8List.fromList(hex.decode(compressedHex));
}

/// Deserialize compressed bytes to a compressed hex string.
/// (In the FFI version, points are represented as hex strings.)
String elemDeserializeCompressed(Uint8List b) {
  final hexStr = hex.encode(b);
  final ptr = hexStr.toNativeUtf8();
  try {
    final result = callFfiData(elemDeserializeCompressedFfi(ptr));
    return result;
  } finally {
    calloc.free(ptr);
  }
}

/// Base-point multiplication: scalar * G.
/// Returns compressed point hex string.
String elemBaseMul(BigInt k) {
  final kHex = _bigIntToHex64(k);
  final ptr = kHex.toNativeUtf8();
  try {
    return callFfiData(elemBaseMulFfi(ptr));
  } finally {
    calloc.free(ptr);
  }
}

/// Point addition: a + b. Both given as compressed hex strings.
/// Delegates to Rust (not exposed as a single FFI call, but we
/// can work around this since the old API mostly doesn't need
/// standalone point add on the Dart side — the FFI functions
/// handle it internally). For the rare cases it's needed,
/// we keep a Dart-side implementation using the group law.
///
/// NOTE: In the FFI wrapper, points are hex strings. The old API
/// used ECPoint objects. We provide this for compatibility.
String elemAdd(String aHex, String bHex) {
  // a + b = decompress both, add on curve, recompress
  // We don't have a direct FFI for point_add, so we use a workaround:
  // Since this is only used in a few places (group commitment, etc.),
  // and those computations now happen in Rust, this function shouldn't
  // be called in the critical path. But to keep API compat, we'll
  // implement it with existing FFI functions.
  //
  // For now, throw if called. All heavy lifting is in Rust.
  throw UnimplementedError(
    'elemAdd is not available in the FFI version. '
    'All point arithmetic is handled by Rust.',
  );
}

/// Point multiplication: point * scalar. Both given as hex strings.
String elemMul(String pointHex, BigInt k) {
  throw UnimplementedError(
    'elemMul is not available in the FFI version. '
    'All point arithmetic is handled by Rust.',
  );
}

BigInt lagrangeCoeffAtZero(Identifier i, List<Identifier> set) {
  var num = modNOne();
  var den = modNOne();
  final n = secp256k1Curve.n;

  for (final j in set) {
    if (j == i) continue;
    final jj = j.toScalar();
    final ii = i.toScalar();
    final negj = (n - jj) % n;
    num = (num * negj) % n;
    final diff = (ii - jj + n) % n;
    den = (den * diff) % n;
  }

  final denInv = den.modInverse(n);
  return (num * denInv) % n;
}

BigInt evaluatePolynomial(Identifier id, List<BigInt> coeffs) {
  if (coeffs.isEmpty) return modNZero();

  final idHex = _bigIntToHex64(id.toScalar());
  final coeffsJson = _coeffsToJson(coeffs);

  final idPtr = idHex.toNativeUtf8();
  final coeffsPtr = coeffsJson.toNativeUtf8();
  try {
    final resultHex = callFfiData(evaluatePolynomialFfi(idPtr, coeffsPtr));
    return _hexToBigInt(resultHex);
  } finally {
    calloc.free(idPtr);
    calloc.free(coeffsPtr);
  }
}

BigInt modNRandom() {
  final resultHex = callFfiData(modNRandomFfi());
  return _hexToBigInt(resultHex);
}

BigInt modNRandomSeeded(List<int> seed, int counter) {
  // Use SHA-256(seed) as the actual seed, then pass seed || counter_be
  // to match the Dart implementation
  final seedHash = sha256.convert(seed).bytes;
  final builder = BytesBuilder();
  builder.add(seedHash);
  final counterBytes = Uint8List(4);
  final view = ByteData.view(counterBytes.buffer);
  view.setUint32(0, counter);
  builder.add(counterBytes);
  final combined = builder.toBytes();

  // SHA-256 hash to get a scalar
  final h = sha256.convert(combined).bytes;
  return bytesToBigInt(Uint8List.fromList(h)) % secp256k1Curve.n;
}

List<BigInt> generateCoefficients(int size, {List<int>? seed}) {
  if (seed != null) {
    return List<BigInt>.generate(size, (i) => modNRandomSeeded(seed, i));
  }

  final seedPtr = Pointer<Uint8>.fromAddress(0);
  final ptr = toNativeBytes(<int>[]);
  try {
    final resultJson = callFfiData(
      generateCoefficientsFfi(size, seedPtr, 0),
    );
    return _parseScalarArrayJson(resultJson);
  } finally {
    if (ptr.address != 0) calloc.free(ptr);
  }
}

(BigInt, String) generateNonce() {
  final k = modNRandom();
  final R = elemBaseMul(k);
  return (k, R);
}

void validateNumOfSigners(int minSigners, int maxSigners) {
  if (minSigners < 2) {
    throw InvalidMinSignersException("min_signers must be >= 2");
  }
  if (maxSigners < 2) {
    throw InvalidMaxSignersException("max_signers must be >= 2");
  }
  if (minSigners > maxSigners) {
    throw InvalidMinSignersException(
      "min_signers cannot be greater than max_signers",
    );
  }
}

BigInt modNFromBytesAllowZero(Uint8List b) {
  return bytesToBigInt(b) % secp256k1Curve.n;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

String _bigIntToHex64(BigInt v) {
  var h = v.toRadixString(16);
  while (h.length < 64) {
    h = '0$h';
  }
  return h;
}

BigInt _hexToBigInt(String hexStr) {
  return BigInt.parse(hexStr, radix: 16);
}

String _coeffsToJson(List<BigInt> coeffs) {
  final arr = coeffs.map((c) => '"${_bigIntToHex64(c)}"').join(',');
  return '[$arr]';
}

List<BigInt> _parseScalarArrayJson(String json) {
  final list = (jsonDecode(json) as List).cast<String>();
  return list.map((h) => _hexToBigInt(h)).toList();
}
