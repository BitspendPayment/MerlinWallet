import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:ffi/ffi.dart';
import 'package:app_core/threshold/core/commitment.dart';
import 'package:app_core/threshold/core/identifier.dart';
import 'package:app_core/threshold/core/share.dart';
import 'package:app_core/threshold/core/utils.dart';
import 'package:app_core/threshold/src/bindings.dart';
import 'package:app_core/threshold/src/ffi_result.dart';

class DKGSignature {
  /// Compressed point hex.
  final String R;
  final BigInt Z;

  DKGSignature(this.R, this.Z);

  factory DKGSignature.fromJson(Map<String, dynamic> json) {
    final R = json['R'] as String;
    final Z = bytesToBigInt(Uint8List.fromList(hex.decode(json['Z'])));
    return DKGSignature(R, Z);
  }

  Map<String, dynamic> toJson() => {
        'R': R,
        'Z': hex.encode(bigIntToBytes(Z)),
      };
}

class Round1Package {
  final VerifiableSecretSharingCommitment commitment;
  final DKGSignature proofOfKnowledge;
  final VerifyingKey verifyingKey;

  Round1Package(this.commitment, this.proofOfKnowledge, this.verifyingKey);

  factory Round1Package.fromJson(Map<String, dynamic> json) {
    return Round1Package(
      VerifiableSecretSharingCommitment.fromJson(json['commitment']),
      DKGSignature.fromJson(json['proofOfKnowledge']),
      VerifyingKey.fromJson(json['verifyingKey']),
    );
  }

  Map<String, dynamic> toJson() => {
        'commitment': commitment.toJson(),
        'proofOfKnowledge': proofOfKnowledge.toJson(),
        'verifyingKey': verifyingKey.toJson(),
      };
}

class Challenge {
  final BigInt C;
  Challenge(this.C);
}

class Round1SecretPackage {
  final Identifier identifier;
  final List<BigInt> coefficients;
  final VerifiableSecretSharingCommitment commitment;
  final int minSigners;
  final int maxSigners;
  /// Opaque FFI handle (if created via FFI).
  final Pointer<Void>? _handle;

  Round1SecretPackage(
    this.identifier,
    this.coefficients,
    this.commitment,
    this.minSigners,
    this.maxSigners, [
    this._handle,
  ]);

  Pointer<Void> get handle {
    final h = _handle;
    if (h == null || h.address == 0) {
      throw StateError('Round1SecretPackage has no FFI handle');
    }
    return h;
  }
}

class Round2Package {
  final SecretShare secretShare;

  Round2Package(this.secretShare);

  factory Round2Package.fromJson(Map<String, dynamic> json) {
    return Round2Package(
      bytesToBigInt(Uint8List.fromList(hex.decode(json['secretShare']))),
    );
  }

  Map<String, dynamic> toJson() => {
        'secretShare': hex.encode(bigIntToBytes(secretShare)),
      };
}

class Round2SecretPackage {
  final Identifier identifier;
  final VerifiableSecretSharingCommitment commitment;
  final BigInt secretShare;
  final int minSigners;
  final int maxSigners;
  /// Opaque FFI handle (if created via FFI).
  final Pointer<Void>? _handle;

  Round2SecretPackage(
    this.identifier,
    this.commitment,
    this.secretShare,
    this.minSigners,
    this.maxSigners, [
    this._handle,
  ]);

  Pointer<Void> get handle {
    final h = _handle;
    if (h == null || h.address == 0) {
      throw StateError('Round2SecretPackage has no FFI handle');
    }
    return h;
  }
}

class KeyPackage {
  final Identifier identifier;
  final SecretShare secretShare;
  final String verifyingShare; // compressed hex
  final VerifyingKey verifyingKey;
  final int minSigners;

  KeyPackage(
    this.identifier,
    this.secretShare,
    this.verifyingShare,
    this.verifyingKey,
    this.minSigners,
  );

  factory KeyPackage.fromJson(Map<String, dynamic> json) {
    return KeyPackage(
      Identifier.deserialize(
        Uint8List.fromList(hex.decode(json['identifier'])),
      ),
      bytesToBigInt(Uint8List.fromList(hex.decode(json['secretShare']))),
      json['verifyingShare'] as String,
      VerifyingKey(E: json['verifyingKey'] as String),
      json['minSigners'],
    );
  }

  Map<String, dynamic> toJson() => {
        'identifier': hex.encode(identifier.serialize()),
        'secretShare': hex.encode(bigIntToBytes(secretShare)),
        'verifyingShare': verifyingShare,
        'verifyingKey': verifyingKey.E,
        'minSigners': minSigners,
      };

  bool get hasEvenY {
    return verifyingKey.hasEvenY;
  }

  KeyPackage intoEvenY({bool? isEven}) {
    final kpJson = jsonEncode(toJson());
    final ptr = kpJson.toNativeUtf8();
    try {
      final resultJson = callFfiData(keyPackageIntoEvenYFfi(ptr));
      final parsed = jsonDecode(resultJson) as Map<String, dynamic>;
      return KeyPackage.fromJson(parsed);
    } finally {
      calloc.free(ptr);
    }
  }

  KeyPackage tweak(List<int>? merkleRoot) {
    final kpJson = jsonEncode(toJson());
    final kpPtr = kpJson.toNativeUtf8();
    Pointer<Uint8> mrPtr;
    int mrLen;
    if (merkleRoot != null && merkleRoot.isNotEmpty) {
      mrPtr = toNativeBytes(merkleRoot);
      mrLen = merkleRoot.length;
    } else {
      mrPtr = Pointer<Uint8>.fromAddress(0);
      mrLen = 0;
    }
    try {
      final resultJson = callFfiData(keyPackageTweakFfi(kpPtr, mrPtr, mrLen));
      final parsed = jsonDecode(resultJson) as Map<String, dynamic>;
      return KeyPackage.fromJson(parsed);
    } finally {
      calloc.free(kpPtr);
      if (mrLen > 0) calloc.free(mrPtr);
    }
  }
}

class PublicKeyPackage {
  final Map<Identifier, String> verifyingShares; // id -> compressed hex
  final VerifyingKey verifyingKey;

  PublicKeyPackage(this.verifyingShares, this.verifyingKey);

  factory PublicKeyPackage.fromJson(Map<String, dynamic> json) {
    final verifyingSharesJson =
        Map<String, dynamic>.from(json['verifyingShares'] as Map);
    final verifyingShares = verifyingSharesJson.map((key, value) {
      final id = Identifier.deserialize(
        Uint8List.fromList(hex.decode(key)),
      );
      return MapEntry(id, value.toString());
    });
    final verifyingKey = VerifyingKey(
      E: json['verifyingKey'].toString(),
    );
    return PublicKeyPackage(verifyingShares, verifyingKey);
  }

  Map<String, dynamic> toJson() {
    final shares = verifyingShares.map(
      (key, value) => MapEntry(
        hex.encode(key.serialize()),
        value,
      ),
    );
    return {
      'verifyingShares': shares,
      'verifyingKey': verifyingKey.E,
    };
  }

  bool get hasEvenY {
    return verifyingKey.hasEvenY;
  }

  PublicKeyPackage intoEvenY({bool? isEven}) {
    final pkpJson = jsonEncode(toJson());
    final ptr = pkpJson.toNativeUtf8();
    try {
      final resultJson = callFfiData(pubKeyPackageIntoEvenYFfi(ptr));
      final parsed = jsonDecode(resultJson) as Map<String, dynamic>;
      return PublicKeyPackage.fromJson(parsed);
    } finally {
      calloc.free(ptr);
    }
  }

  PublicKeyPackage tweak(List<int>? merkleRoot) {
    final pkpJson = jsonEncode(toJson());
    final pkpPtr = pkpJson.toNativeUtf8();
    Pointer<Uint8> mrPtr;
    int mrLen;
    if (merkleRoot != null && merkleRoot.isNotEmpty) {
      mrPtr = toNativeBytes(merkleRoot);
      mrLen = merkleRoot.length;
    } else {
      mrPtr = Pointer<Uint8>.fromAddress(0);
      mrLen = 0;
    }
    try {
      final resultJson =
          callFfiData(pubKeyPackageTweakFfi(pkpPtr, mrPtr, mrLen));
      final parsed = jsonDecode(resultJson) as Map<String, dynamic>;
      return PublicKeyPackage.fromJson(parsed);
    } finally {
      calloc.free(pkpPtr);
      if (mrLen > 0) calloc.free(mrPtr);
    }
  }
}

class SecretKey {
  final BigInt scalar;
  SecretKey(this.scalar);
}

SecretShare secretShareFromCoefficients(List<BigInt> coeffs, Identifier peer) {
  return evaluatePolynomial(peer, coeffs);
}

SecretKey newSecretKey() {
  return SecretKey(modNRandom());
}

// ---------------------------------------------------------------------------
// DKG Part 1
// ---------------------------------------------------------------------------

(Round1SecretPackage, Round1Package) dkgPart1(
  int maxSigners,
  int minSigners,
  SecretKey secretKey,
  List<BigInt> coefficients,
) {
  final secretHex = _bigIntToHex64(secretKey.scalar);
  final coeffsJson = _coeffsToJson(coefficients);

  final secretPtr = secretHex.toNativeUtf8();
  final coeffsPtr = coeffsJson.toNativeUtf8();
  try {
    final (data, handle) = callFfi(
      dkgPart1Ffi(maxSigners, minSigners, secretPtr, coeffsPtr),
    );

    final r1Pkg = Round1Package.fromJson(
      jsonDecode(data) as Map<String, dynamic>,
    );

    // Build the Round1SecretPackage with the opaque handle
    final vk = r1Pkg.commitment.toVerifyingKey();
    final vkBytes = elemSerializeCompressed(vk.E);
    final identifier = Identifier.derive(vkBytes);

    final allCoeffs = <BigInt>[secretKey.scalar, ...coefficients];

    final r1Secret = Round1SecretPackage(
      identifier,
      allCoeffs,
      r1Pkg.commitment,
      minSigners,
      maxSigners,
      handle,
    );

    return (r1Secret, r1Pkg);
  } finally {
    calloc.free(secretPtr);
    calloc.free(coeffsPtr);
  }
}

// ---------------------------------------------------------------------------
// DKG Part 2
// ---------------------------------------------------------------------------

(Round2SecretPackage, Map<Identifier, Round2Package>) dkgPart2(
  Round1SecretPackage secretPkg,
  Map<Identifier, Round1Package> round1Pkgs, {
  List<Identifier> receiverIdentifiers = const [],
}) {
  final r1PkgsJson = _encodeR1PkgsJson(round1Pkgs);
  final receiverIdsJson = _encodeIdentifierListJson(receiverIdentifiers);

  final r1PkgsPtr = r1PkgsJson.toNativeUtf8();
  final receiverIdsPtr = receiverIdsJson.toNativeUtf8();
  try {
    final (data, handle) = callFfi(
      dkgPart2Ffi(secretPkg.handle, r1PkgsPtr, receiverIdsPtr),
    );

    final r2PkgsMap = _decodeR2PkgsJson(data);

    // Compute self-share for Round2SecretPackage
    final fii = evaluatePolynomial(secretPkg.identifier, secretPkg.coefficients);

    final r2Secret = Round2SecretPackage(
      secretPkg.identifier,
      secretPkg.commitment,
      fii,
      secretPkg.minSigners,
      secretPkg.maxSigners,
      handle,
    );

    return (r2Secret, r2PkgsMap);
  } finally {
    calloc.free(r1PkgsPtr);
    calloc.free(receiverIdsPtr);
  }
}

// ---------------------------------------------------------------------------
// DKG Part 3
// ---------------------------------------------------------------------------

(KeyPackage, PublicKeyPackage) dkgPart3(
  Round1SecretPackage r1Secret,
  Round2SecretPackage r2Secret,
  Map<Identifier, Round1Package> round1Pkgs,
  Map<Identifier, Round2Package> round2Pkgs, {
  List<Identifier> receiverIdentifiers = const [],
}) {
  final r1PkgsJson = _encodeR1PkgsJson(round1Pkgs);
  final r2PkgsJson = _encodeR2PkgsJson(round2Pkgs);
  final receiverIdsJson = _encodeIdentifierListJson(receiverIdentifiers);

  final r1PkgsPtr = r1PkgsJson.toNativeUtf8();
  final r2PkgsPtr = r2PkgsJson.toNativeUtf8();
  final receiverIdsPtr = receiverIdsJson.toNativeUtf8();
  try {
    final data = callFfiData(
      dkgPart3Ffi(
        r1Secret.handle,
        r2Secret.handle,
        r1PkgsPtr,
        r2PkgsPtr,
        receiverIdsPtr,
      ),
    );

    final parsed = jsonDecode(data) as Map<String, dynamic>;
    final kp = KeyPackage.fromJson(
      parsed['key_package'] as Map<String, dynamic>,
    );
    final pkp = PublicKeyPackage.fromJson(
      parsed['public_key_package'] as Map<String, dynamic>,
    );

    return (kp, pkp);
  } finally {
    calloc.free(r1PkgsPtr);
    calloc.free(r2PkgsPtr);
    calloc.free(receiverIdsPtr);
  }
}

// ---------------------------------------------------------------------------
// DKG Part 3 Receive (passive)
// ---------------------------------------------------------------------------

(KeyPackage, PublicKeyPackage) dkgPart3Receive(
  Identifier myIdentifier,
  Map<Identifier, Round1Package> dealerRound1Pkgs,
  Map<Identifier, Round2Package> sharesForMe,
  int minSigners,
  int maxSigners,
  List<Identifier> allParticipantIdentifiers,
) {
  final myIdHex = _bigIntToHex64(myIdentifier.toScalar());
  final dealerR1Json = _encodeR1PkgsJson(dealerRound1Pkgs);
  final sharesJson = _encodeR2PkgsJson(sharesForMe);
  final allIdsJson = _encodeIdentifierListJson(allParticipantIdentifiers);

  final myIdPtr = myIdHex.toNativeUtf8();
  final dealerR1Ptr = dealerR1Json.toNativeUtf8();
  final sharesPtr = sharesJson.toNativeUtf8();
  final allIdsPtr = allIdsJson.toNativeUtf8();
  try {
    final data = callFfiData(
      dkgPart3ReceiveFfi(
        myIdPtr,
        dealerR1Ptr,
        sharesPtr,
        minSigners,
        maxSigners,
        allIdsPtr,
      ),
    );

    final parsed = jsonDecode(data) as Map<String, dynamic>;
    final kp = KeyPackage.fromJson(
      parsed['key_package'] as Map<String, dynamic>,
    );
    final pkp = PublicKeyPackage.fromJson(
      parsed['public_key_package'] as Map<String, dynamic>,
    );

    return (kp, pkp);
  } finally {
    calloc.free(myIdPtr);
    calloc.free(dealerR1Ptr);
    calloc.free(sharesPtr);
    calloc.free(allIdsPtr);
  }
}

// ---------------------------------------------------------------------------
// PKP helpers
// ---------------------------------------------------------------------------

PublicKeyPackage pkpFromDkgCommitments(
  Map<Identifier, VerifiableSecretSharingCommitment> commits,
) {
  // This requires point arithmetic (sum commitments + evaluate).
  // All call sites go through Rust DKG functions. If called directly,
  // we'd need to serialize and call through FFI.
  throw UnimplementedError(
    'pkpFromDkgCommitments — use dkgPart3 or dkgPart3Receive instead.',
  );
}

PublicKeyPackage pkpFromCommitment(
  List<Identifier> ids,
  VerifiableSecretSharingCommitment commit,
) {
  throw UnimplementedError(
    'pkpFromCommitment — use dkgPart3 or dkgPart3Receive instead.',
  );
}

// ---------------------------------------------------------------------------
// Key Refresh
// ---------------------------------------------------------------------------

(Round1SecretPackage, Round1Package) dkgRefreshPart1(
  Identifier identifier,
  int maxSigners,
  int minSigners, {
  List<int>? seed,
}) {
  final idHex = _bigIntToHex64(identifier.toScalar());
  final idPtr = idHex.toNativeUtf8();

  Pointer<Uint8> seedPtr;
  int seedLen;
  if (seed != null && seed.isNotEmpty) {
    seedPtr = toNativeBytes(seed);
    seedLen = seed.length;
  } else {
    seedPtr = Pointer<Uint8>.fromAddress(0);
    seedLen = 0;
  }

  try {
    final (data, handle) = callFfi(
      dkgRefreshPart1Ffi(idPtr, maxSigners, minSigners, seedPtr, seedLen),
    );

    final parsed = jsonDecode(data) as Map<String, dynamic>;
    final r1Pkg = Round1Package.fromJson(
      parsed['round1Package'] as Map<String, dynamic>,
    );

    // Extract coefficients returned by FFI (full polynomial including zero constant term)
    final coeffsRaw = parsed['coefficients'] as List;
    final coefficients = coeffsRaw
        .map((e) => bytesToBigInt(Uint8List.fromList(hex.decode(e as String))))
        .toList();

    final r1Secret = Round1SecretPackage(
      identifier,
      coefficients,
      r1Pkg.commitment,
      minSigners,
      maxSigners,
      handle,
    );

    return (r1Secret, r1Pkg);
  } finally {
    calloc.free(idPtr);
    if (seedLen > 0) calloc.free(seedPtr);
  }
}

(Round2SecretPackage, Map<Identifier, Round2Package>) dkgRefreshPart2(
  Round1SecretPackage secretPkg,
  Map<Identifier, Round1Package> round1Pkgs,
) {
  final r1PkgsJson = _encodeR1PkgsJson(round1Pkgs);
  final r1PkgsPtr = r1PkgsJson.toNativeUtf8();
  try {
    final (data, handle) = callFfi(
      dkgRefreshPart2Ffi(secretPkg.handle, r1PkgsPtr),
    );

    final r2PkgsMap = _decodeR2PkgsJson(data);

    final r2Secret = Round2SecretPackage(
      secretPkg.identifier,
      secretPkg.commitment,
      BigInt.zero, // managed by Rust
      secretPkg.minSigners,
      secretPkg.maxSigners,
      handle,
    );

    return (r2Secret, r2PkgsMap);
  } finally {
    calloc.free(r1PkgsPtr);
  }
}

(KeyPackage, PublicKeyPackage) dkgRefreshPart3(
  Round2SecretPackage r2Secret,
  Map<Identifier, Round1Package> round1Pkgs,
  Map<Identifier, Round2Package> round2Pkgs,
  PublicKeyPackage oldPKP,
  KeyPackage oldKP,
) {
  final r1PkgsJson = _encodeR1PkgsJson(round1Pkgs);
  final r2PkgsJson = _encodeR2PkgsJson(round2Pkgs);
  final oldPkpJson = jsonEncode(oldPKP.toJson());
  final oldKpJson = jsonEncode(oldKP.toJson());

  final r1PkgsPtr = r1PkgsJson.toNativeUtf8();
  final r2PkgsPtr = r2PkgsJson.toNativeUtf8();
  final oldPkpPtr = oldPkpJson.toNativeUtf8();
  final oldKpPtr = oldKpJson.toNativeUtf8();
  try {
    final data = callFfiData(
      dkgRefreshPart3Ffi(
        r2Secret.handle,
        r1PkgsPtr,
        r2PkgsPtr,
        oldPkpPtr,
        oldKpPtr,
      ),
    );

    final parsed = jsonDecode(data) as Map<String, dynamic>;
    final kp = KeyPackage.fromJson(
      parsed['key_package'] as Map<String, dynamic>,
    );
    final pkp = PublicKeyPackage.fromJson(
      parsed['public_key_package'] as Map<String, dynamic>,
    );

    return (kp, pkp);
  } finally {
    calloc.free(r1PkgsPtr);
    calloc.free(r2PkgsPtr);
    calloc.free(oldPkpPtr);
    calloc.free(oldKpPtr);
  }
}

/// eVTXO reshare round 1: deal a fresh NON-zero polynomial under the dealer's
/// EXISTING identifier. The polynomial lives in the returned FFI handle; round 2
/// uses the regular [dkgPart2].
/// Reshare round 1 from a polynomial the caller already has.
///
/// The variant below draws its own constant term and expands coefficients from a seed. This one
/// takes both, because a wallet's escrow delta is derived from its passkey through the same HKDF as
/// the rest of its key material — which is what lets another device reproduce it.
(Round1SecretPackage, Round1Package) dkgResharePart1From(
  Identifier identifier,
  int maxSigners,
  int minSigners,
  SecretKey secret,
  List<BigInt> coefficients,
) {
  final idHex = _bigIntToHex64(identifier.toScalar());
  final idPtr = idHex.toNativeUtf8();
  final secretPtr = _bigIntToHex64(secret.scalar).toNativeUtf8();
  final coeffsPtr = _coeffsToJson(coefficients).toNativeUtf8();
  try {
    final (data, handle) = callFfi(
      dkgResharePart1FromFfi(idPtr, maxSigners, minSigners, secretPtr, coeffsPtr),
    );
    // The package itself, not wrapped in anything — `serialize_round1_pkg` returns exactly what
    // `dkgPart1` parses here. (The seeded sibling below unwraps a `round1Package` key that the FFI
    // has never produced, which is one way to tell nothing has ever called it.)
    final r1Pkg = Round1Package.fromJson(jsonDecode(data) as Map<String, dynamic>);
    final r1Secret = Round1SecretPackage(
      identifier,
      const <BigInt>[], // the coefficients live in the FFI handle
      r1Pkg.commitment,
      minSigners,
      maxSigners,
      handle,
    );
    return (r1Secret, r1Pkg);
  } finally {
    calloc.free(idPtr);
    calloc.free(secretPtr);
    calloc.free(coeffsPtr);
  }
}

(Round1SecretPackage, Round1Package) dkgResharePart1(
  Identifier identifier,
  int maxSigners,
  int minSigners, {
  List<int>? seed,
}) {
  final idHex = _bigIntToHex64(identifier.toScalar());
  final idPtr = idHex.toNativeUtf8();

  Pointer<Uint8> seedPtr;
  int seedLen;
  if (seed != null && seed.isNotEmpty) {
    seedPtr = toNativeBytes(seed);
    seedLen = seed.length;
  } else {
    seedPtr = Pointer<Uint8>.fromAddress(0);
    seedLen = 0;
  }

  try {
    final (data, handle) = callFfi(
      dkgResharePart1Ffi(idPtr, maxSigners, minSigners, seedPtr, seedLen),
    );
    final parsed = jsonDecode(data) as Map<String, dynamic>;
    final r1Pkg = Round1Package.fromJson(
      parsed['round1Package'] as Map<String, dynamic>,
    );
    final r1Secret = Round1SecretPackage(
      identifier,
      <BigInt>[], // coefficients live in the FFI handle; not needed Dart-side
      r1Pkg.commitment,
      minSigners,
      maxSigners,
      handle,
    );
    return (r1Secret, r1Pkg);
  } finally {
    calloc.free(idPtr);
    if (seedLen > 0) calloc.free(seedPtr);
  }
}

/// eVTXO reshare finalizer for a pure receiver (the wallet): combine the
/// dealers' shares with the old share into a new 2-of-2 `V′` key package + PKP.
/// `receiverIdentifiers` is the NEW shareholder set ({wallet, cosigner}).
(KeyPackage, PublicKeyPackage) dkgResharePart3Receive(
  Identifier myIdentifier,
  Map<Identifier, Round1Package> dealerRound1Pkgs,
  Map<Identifier, Round2Package> sharesForMe,
  PublicKeyPackage oldPkp,
  KeyPackage oldKp,
  List<Identifier> receiverIdentifiers,
  int minSigners,
) {
  final myIdHex = _bigIntToHex64(myIdentifier.toScalar());
  final dealerR1Json = _encodeR1PkgsJson(dealerRound1Pkgs);
  final sharesJson = _encodeR2PkgsJson(sharesForMe);
  final receiverIdsJson = _encodeIdentifierListJson(receiverIdentifiers);
  final oldPkpJson = jsonEncode(oldPkp.toJson());
  final oldKpJson = jsonEncode(oldKp.toJson());

  final myIdPtr = myIdHex.toNativeUtf8();
  final dealerR1Ptr = dealerR1Json.toNativeUtf8();
  final sharesPtr = sharesJson.toNativeUtf8();
  final oldPkpPtr = oldPkpJson.toNativeUtf8();
  final oldKpPtr = oldKpJson.toNativeUtf8();
  final receiverIdsPtr = receiverIdsJson.toNativeUtf8();
  try {
    final data = callFfiData(
      dkgResharePart3ReceiveFfi(
        myIdPtr,
        dealerR1Ptr,
        sharesPtr,
        oldPkpPtr,
        oldKpPtr,
        receiverIdsPtr,
        minSigners,
      ),
    );

    final parsed = jsonDecode(data) as Map<String, dynamic>;
    final kp = KeyPackage.fromJson(
      parsed['key_package'] as Map<String, dynamic>,
    );
    final pkp = PublicKeyPackage.fromJson(
      parsed['public_key_package'] as Map<String, dynamic>,
    );

    return (kp, pkp);
  } finally {
    calloc.free(myIdPtr);
    calloc.free(dealerR1Ptr);
    calloc.free(sharesPtr);
    calloc.free(oldPkpPtr);
    calloc.free(oldKpPtr);
    calloc.free(receiverIdsPtr);
  }
}

/// eVTXO reshare finalizer for a DEALER (the author): combine this dealer's own
/// dealing ([r2Secret] handle) with the peer dealers' [round1Pkgs] and the shares
/// dealt to this dealer ([round2Pkgs]), plus the old share, into the new 2-of-2
/// `V′` key package + PKP. `receiverIdentifiers` is the NEW shareholder set
/// ({author, cosigner}). Mirrors [dkgResharePart3Receive] for the dealing side.
(KeyPackage, PublicKeyPackage) dkgResharePart3(
  Round2SecretPackage r2Secret,
  Map<Identifier, Round1Package> round1Pkgs,
  Map<Identifier, Round2Package> round2Pkgs,
  PublicKeyPackage oldPkp,
  KeyPackage oldKp,
  List<Identifier> receiverIdentifiers,
) {
  final round1Json = _encodeR1PkgsJson(round1Pkgs);
  final round2Json = _encodeR2PkgsJson(round2Pkgs);
  final receiverIdsJson = _encodeIdentifierListJson(receiverIdentifiers);
  final oldPkpJson = jsonEncode(oldPkp.toJson());
  final oldKpJson = jsonEncode(oldKp.toJson());

  final round1Ptr = round1Json.toNativeUtf8();
  final round2Ptr = round2Json.toNativeUtf8();
  final oldPkpPtr = oldPkpJson.toNativeUtf8();
  final oldKpPtr = oldKpJson.toNativeUtf8();
  final receiverIdsPtr = receiverIdsJson.toNativeUtf8();
  try {
    final data = callFfiData(
      dkgResharePart3Ffi(
        r2Secret.handle,
        round1Ptr,
        round2Ptr,
        oldPkpPtr,
        oldKpPtr,
        receiverIdsPtr,
      ),
    );

    final parsed = jsonDecode(data) as Map<String, dynamic>;
    final kp = KeyPackage.fromJson(
      parsed['key_package'] as Map<String, dynamic>,
    );
    final pkp = PublicKeyPackage.fromJson(
      parsed['public_key_package'] as Map<String, dynamic>,
    );

    return (kp, pkp);
  } finally {
    calloc.free(round1Ptr);
    calloc.free(round2Ptr);
    calloc.free(oldPkpPtr);
    calloc.free(oldKpPtr);
    calloc.free(receiverIdsPtr);
  }
}

/// Per-participant key-preserving REFRESH of [holderKp]'s `V′` share onto a new
/// participant identifier. The author calls this with its own `V′` key package
/// ([idSet] = the current `V′` shareholder ids {author, cosigner}; [cosignerId] =
/// the cosigner's id; [slope] a fresh random scalar). Returns
/// `(atParticipant, atCosigner)`: the author's half evaluated at the participant's
/// id and at the cosigner's id. The participant sums the author's + cosigner's
/// `atParticipant` into `P_i`; the cosigner sums the `atCosigner` halves into `C_i`.
(BigInt, BigInt) refreshShareToId(
  KeyPackage holderKp,
  List<Identifier> idSet,
  Identifier participantId,
  Identifier cosignerId,
  BigInt slope,
) {
  final kpJson = jsonEncode(holderKp.toJson());
  final idSetJson = _encodeIdentifierListJson(idSet);
  final partHex = _bigIntToHex64(participantId.toScalar());
  final cosHex = _bigIntToHex64(cosignerId.toScalar());
  final slopeHex = _bigIntToHex64(slope);

  final kpPtr = kpJson.toNativeUtf8();
  final idSetPtr = idSetJson.toNativeUtf8();
  final partPtr = partHex.toNativeUtf8();
  final cosPtr = cosHex.toNativeUtf8();
  final slopePtr = slopeHex.toNativeUtf8();
  try {
    final data = callFfiData(
      refreshShareToIdFfi(kpPtr, idSetPtr, partPtr, cosPtr, slopePtr),
    );
    final parsed = jsonDecode(data) as Map<String, dynamic>;
    final atP = bytesToBigInt(
        Uint8List.fromList(hex.decode(parsed['at_participant'] as String)));
    final atC = bytesToBigInt(
        Uint8List.fromList(hex.decode(parsed['at_cosigner'] as String)));
    return (atP, atC);
  } finally {
    calloc.free(kpPtr);
    calloc.free(idSetPtr);
    calloc.free(partPtr);
    calloc.free(cosPtr);
    calloc.free(slopePtr);
  }
}

// ---------------------------------------------------------------------------
// Internal JSON helpers
// ---------------------------------------------------------------------------

String _bigIntToHex64(BigInt v) {
  var h = v.toRadixString(16);
  while (h.length < 64) {
    h = '0$h';
  }
  return h;
}

String _coeffsToJson(List<BigInt> coeffs) {
  final arr = coeffs.map((c) => '"${_bigIntToHex64(c)}"').join(',');
  return '[$arr]';
}

String _encodeR1PkgsJson(Map<Identifier, Round1Package> pkgs) {
  final map = <String, dynamic>{};
  for (final entry in pkgs.entries) {
    final idHex = hex.encode(entry.key.serialize());
    map[idHex] = entry.value.toJson();
  }
  return jsonEncode(map);
}

String _encodeR2PkgsJson(Map<Identifier, Round2Package> pkgs) {
  final map = <String, dynamic>{};
  for (final entry in pkgs.entries) {
    final idHex = hex.encode(entry.key.serialize());
    map[idHex] = entry.value.toJson();
  }
  return jsonEncode(map);
}

String _encodeIdentifierListJson(List<Identifier> ids) {
  final list = ids.map((id) => hex.encode(id.serialize())).toList();
  return jsonEncode(list);
}

Map<Identifier, Round2Package> _decodeR2PkgsJson(String json) {
  final parsed = jsonDecode(json) as Map<String, dynamic>;
  final result = <Identifier, Round2Package>{};
  for (final entry in parsed.entries) {
    final id = Identifier.deserialize(
      Uint8List.fromList(hex.decode(entry.key)),
    );
    result[id] = Round2Package.fromJson(
      entry.value as Map<String, dynamic>,
    );
  }
  return result;
}
