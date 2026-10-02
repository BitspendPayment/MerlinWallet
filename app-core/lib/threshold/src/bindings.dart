/// Raw dart:ffi bindings to libthreshold_ffi.
library;

import 'dart:ffi';
import 'package:ffi/ffi.dart';

import 'ffi_result.dart';
import 'native_library.dart';

// ---------------------------------------------------------------------------
// DKG bindings
// ---------------------------------------------------------------------------

typedef _DkgPart1Native = Pointer<FfiResult> Function(
    Uint32, Uint32, Pointer<Utf8>, Pointer<Utf8>);
typedef _DkgPart1Dart = Pointer<FfiResult> Function(
    int, int, Pointer<Utf8>, Pointer<Utf8>);
final dkgPart1Ffi =
    nativeLib.lookupFunction<_DkgPart1Native, _DkgPart1Dart>('threshold_dkg_part1');

typedef _DkgPart2Native = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef _DkgPart2Dart = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
final dkgPart2Ffi =
    nativeLib.lookupFunction<_DkgPart2Native, _DkgPart2Dart>('threshold_dkg_part2');

typedef _DkgPart3Native = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef _DkgPart3Dart = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
final dkgPart3Ffi =
    nativeLib.lookupFunction<_DkgPart3Native, _DkgPart3Dart>('threshold_dkg_part3');

typedef _DkgPart3ReceiveNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Uint32, Uint32, Pointer<Utf8>);
typedef _DkgPart3ReceiveDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, int, int, Pointer<Utf8>);
final dkgPart3ReceiveFfi = nativeLib
    .lookupFunction<_DkgPart3ReceiveNative, _DkgPart3ReceiveDart>(
        'threshold_dkg_part3_receive');

typedef _DkgRefreshPart1Native = Pointer<FfiResult> Function(
    Pointer<Utf8>, Uint32, Uint32, Pointer<Uint8>, Uint32);
typedef _DkgRefreshPart1Dart = Pointer<FfiResult> Function(
    Pointer<Utf8>, int, int, Pointer<Uint8>, int);
final dkgRefreshPart1Ffi = nativeLib
    .lookupFunction<_DkgRefreshPart1Native, _DkgRefreshPart1Dart>(
        'threshold_dkg_refresh_part1');

typedef _DkgRefreshPart2Native = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Utf8>);
typedef _DkgRefreshPart2Dart = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Utf8>);
final dkgRefreshPart2Ffi = nativeLib
    .lookupFunction<_DkgRefreshPart2Native, _DkgRefreshPart2Dart>(
        'threshold_dkg_refresh_part2');

typedef _DkgRefreshPart3Native = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef _DkgRefreshPart3Dart = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
final dkgRefreshPart3Ffi = nativeLib
    .lookupFunction<_DkgRefreshPart3Native, _DkgRefreshPart3Dart>(
        'threshold_dkg_refresh_part3');

// eVTXO reshare round 1: deal under an explicit identifier (same signature as
// refresh_part1: id, max, min, seed_ptr, seed_len).
typedef _DkgResharePart1Native = Pointer<FfiResult> Function(
    Pointer<Utf8>, Uint32, Uint32, Pointer<Uint8>, Uint32);
typedef _DkgResharePart1Dart = Pointer<FfiResult> Function(
    Pointer<Utf8>, int, int, Pointer<Uint8>, int);
final dkgResharePart1Ffi = nativeLib
    .lookupFunction<_DkgResharePart1Native, _DkgResharePart1Dart>(
        'threshold_dkg_reshare_part1');

// Reshare round 1 from an EXPLICIT polynomial — same shape as `dkg_part1`, because a wallet's
// escrow delta comes from its passkey rather than from an RNG or a seed expander.
typedef _DkgResharePart1FromNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Uint32, Uint32, Pointer<Utf8>, Pointer<Utf8>);
typedef _DkgResharePart1FromDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, int, int, Pointer<Utf8>, Pointer<Utf8>);
final dkgResharePart1FromFfi = nativeLib
    .lookupFunction<_DkgResharePart1FromNative, _DkgResharePart1FromDart>(
        'threshold_dkg_reshare_part1_from');

// eVTXO reshare finalizer for a DEALER (the author): r2_secret handle, peer
// round1 pkgs, shares dealt to me, old PKP, old KP, receiver ids.
typedef _DkgResharePart3Native = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>);
typedef _DkgResharePart3Dart = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>);
final dkgResharePart3Ffi = nativeLib
    .lookupFunction<_DkgResharePart3Native, _DkgResharePart3Dart>(
        'threshold_dkg_reshare_part3');

// eVTXO reshare finalizer for a pure receiver (the wallet).
typedef _DkgResharePart3ReceiveNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>, Uint32);
typedef _DkgResharePart3ReceiveDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>, int);
final dkgResharePart3ReceiveFfi = nativeLib
    .lookupFunction<_DkgResharePart3ReceiveNative, _DkgResharePart3ReceiveDart>(
        'threshold_dkg_reshare_part3_receive');

// Per-participant key-preserving refresh of a V′ share onto a new participant
// identifier (multi-user onboarding). Args: holder_kp_json, id_set_json,
// participant_id_hex, cosigner_id_hex, slope_hex.
typedef _RefreshShareToIdNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef _RefreshShareToIdDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
final refreshShareToIdFfi = nativeLib
    .lookupFunction<_RefreshShareToIdNative, _RefreshShareToIdDart>(
        'threshold_refresh_share_to_id');

// ---------------------------------------------------------------------------
// Signing bindings
// ---------------------------------------------------------------------------

typedef _NewNonceNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _NewNonceDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final newNonceFfi =
    nativeLib.lookupFunction<_NewNonceNative, _NewNonceDart>('threshold_new_nonce');

typedef _FrostSignNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Void>, Pointer<Utf8>);
typedef _FrostSignDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Void>, Pointer<Utf8>);
final frostSignFfi =
    nativeLib.lookupFunction<_FrostSignNative, _FrostSignDart>('threshold_frost_sign');

typedef _FrostAggregateNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef _FrostAggregateDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
final frostAggregateFfi = nativeLib
    .lookupFunction<_FrostAggregateNative, _FrostAggregateDart>(
        'threshold_frost_aggregate');

// ---------------------------------------------------------------------------
// Auth bindings
// ---------------------------------------------------------------------------

typedef _AuthSignerCreateNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _AuthSignerCreateDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final authSignerCreateFfi = nativeLib
    .lookupFunction<_AuthSignerCreateNative, _AuthSignerCreateDart>(
        'threshold_auth_signer_create');

typedef _AuthSignerSignNative = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Uint8>, Uint32);
typedef _AuthSignerSignDart = Pointer<FfiResult> Function(
    Pointer<Void>, Pointer<Uint8>, int);
final authSignerSignFfi = nativeLib
    .lookupFunction<_AuthSignerSignNative, _AuthSignerSignDart>(
        'threshold_auth_signer_sign');

typedef _AuthSignerPkNative = Pointer<FfiResult> Function(Pointer<Void>);
typedef _AuthSignerPkDart = Pointer<FfiResult> Function(Pointer<Void>);
final authSignerPublicKeyFfi = nativeLib
    .lookupFunction<_AuthSignerPkNative, _AuthSignerPkDart>(
        'threshold_auth_signer_public_key');

typedef _VerifySchnorrNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Uint8>, Uint32, Pointer<Utf8>);
typedef _VerifySchnorrDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Utf8>);
final verifySchnorrFfi = nativeLib
    .lookupFunction<_VerifySchnorrNative, _VerifySchnorrDart>(
        'threshold_verify_schnorr_signature');

// ---------------------------------------------------------------------------
// Utility bindings
// ---------------------------------------------------------------------------

typedef _IdDeriveNative = Pointer<FfiResult> Function(Pointer<Uint8>, Uint32);
typedef _IdDeriveDart = Pointer<FfiResult> Function(Pointer<Uint8>, int);
final identifierDeriveFfi = nativeLib
    .lookupFunction<_IdDeriveNative, _IdDeriveDart>('threshold_identifier_derive');

typedef _IdFromBigintNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _IdFromBigintDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final identifierFromBigintFfi = nativeLib
    .lookupFunction<_IdFromBigintNative, _IdFromBigintDart>(
        'threshold_identifier_from_bigint');

typedef _GenCoeffsNative = Pointer<FfiResult> Function(
    Uint32, Pointer<Uint8>, Uint32);
typedef _GenCoeffsDart = Pointer<FfiResult> Function(int, Pointer<Uint8>, int);
final generateCoefficientsFfi = nativeLib
    .lookupFunction<_GenCoeffsNative, _GenCoeffsDart>(
        'threshold_generate_coefficients');

typedef _EvalPolyNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>);
typedef _EvalPolyDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>);
final evaluatePolynomialFfi = nativeLib
    .lookupFunction<_EvalPolyNative, _EvalPolyDart>(
        'threshold_evaluate_polynomial');

typedef _ModNRandomNative = Pointer<FfiResult> Function();
typedef _ModNRandomDart = Pointer<FfiResult> Function();
final modNRandomFfi = nativeLib
    .lookupFunction<_ModNRandomNative, _ModNRandomDart>('threshold_mod_n_random');

typedef _ElemBaseMulNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _ElemBaseMulDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final elemBaseMulFfi = nativeLib
    .lookupFunction<_ElemBaseMulNative, _ElemBaseMulDart>(
        'threshold_elem_base_mul');

typedef _ElemCompressNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _ElemCompressDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final elemSerializeCompressedFfi = nativeLib
    .lookupFunction<_ElemCompressNative, _ElemCompressDart>(
        'threshold_elem_serialize_compressed');

typedef _ElemDecompressNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _ElemDecompressDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final elemDeserializeCompressedFfi = nativeLib
    .lookupFunction<_ElemDecompressNative, _ElemDecompressDart>(
        'threshold_elem_deserialize_compressed');

// ---------------------------------------------------------------------------
// Keys bindings
// ---------------------------------------------------------------------------

typedef _KpTweakNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Uint8>, Uint32);
typedef _KpTweakDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Uint8>, int);
final keyPackageTweakFfi = nativeLib
    .lookupFunction<_KpTweakNative, _KpTweakDart>('threshold_key_package_tweak');

typedef _PkpTweakNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Uint8>, Uint32);
typedef _PkpTweakDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Uint8>, int);
final pubKeyPackageTweakFfi = nativeLib
    .lookupFunction<_PkpTweakNative, _PkpTweakDart>(
        'threshold_pub_key_package_tweak');

typedef _KpEvenYNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _KpEvenYDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final keyPackageIntoEvenYFfi = nativeLib
    .lookupFunction<_KpEvenYNative, _KpEvenYDart>(
        'threshold_key_package_into_even_y');

typedef _PkpEvenYNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _PkpEvenYDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final pubKeyPackageIntoEvenYFfi = nativeLib
    .lookupFunction<_PkpEvenYNative, _PkpEvenYDart>(
        'threshold_pub_key_package_into_even_y');

// ---------------------------------------------------------------------------
// Helper: allocate native string, call, free
// ---------------------------------------------------------------------------

/// Allocates a native Utf8 string from a Dart string.
/// Caller must free the result with calloc.free().
Pointer<Utf8> toNativeUtf8(String s) => s.toNativeUtf8();

/// Allocates native bytes from a Dart list.
Pointer<Uint8> toNativeBytes(List<int> bytes) {
  final ptr = calloc<Uint8>(bytes.length);
  for (var i = 0; i < bytes.length; i++) {
    ptr[i] = bytes[i];
  }
  return ptr;
}
