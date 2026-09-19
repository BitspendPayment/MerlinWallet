/// Raw dart:ffi bindings to libark_ffi.
library;

import 'dart:ffi';
import 'package:ffi/ffi.dart';

import 'ffi_result.dart';
import 'native_library.dart';

// ---------------------------------------------------------------------------
// Ark protocol bindings
// ---------------------------------------------------------------------------

typedef _ArkVtxoSpkNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Uint32);
typedef _ArkVtxoSpkDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, int);
final arkDefaultVtxoScriptPubkeyFfi = nativeLib
    .lookupFunction<_ArkVtxoSpkNative, _ArkVtxoSpkDart>(
        'ark_default_vtxo_script_pubkey');

// Address derivation. Three symbols with the same shape: (owner_pk, asp_pk, exit_delay, network).
//
// These came back from the cosigner over `GetArkAddress`/`GetBoardingAddress` until it stopped
// doing anything the caller could do itself. The Rust side has a parity test against
// `ark::client::address`, which is what makes deriving here safe rather than a second guess at a
// consensus-critical taptree.
typedef _ArkAddrNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Uint32, Pointer<Utf8>);
typedef _ArkAddrDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, int, Pointer<Utf8>);

final arkAddressFfi =
    nativeLib.lookupFunction<_ArkAddrNative, _ArkAddrDart>('ark_address');
final arkBoardingAddressFfi =
    nativeLib.lookupFunction<_ArkAddrNative, _ArkAddrDart>('ark_boarding_address');
final arkVtxoScriptPubkeyHexFfi = nativeLib
    .lookupFunction<_ArkAddrNative, _ArkAddrDart>('ark_vtxo_script_pubkey_hex');

typedef _ArkForfeitNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Uint32);
typedef _ArkForfeitDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, int);
final arkForfeitSpendInfoFfi = nativeLib
    .lookupFunction<_ArkForfeitNative, _ArkForfeitDart>(
        'ark_forfeit_spend_info');

typedef _ArkExitNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, Uint32);
typedef _ArkExitDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>, int);
final arkExitSpendInfoFfi = nativeLib
    .lookupFunction<_ArkExitNative, _ArkExitDart>(
        'ark_exit_spend_info');

typedef _ArkMultisigNative = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>);
typedef _ArkMultisigDart = Pointer<FfiResult> Function(
    Pointer<Utf8>, Pointer<Utf8>);
final arkMultisigScriptFfi = nativeLib
    .lookupFunction<_ArkMultisigNative, _ArkMultisigDart>(
        'ark_multisig_script');

typedef _ArkCsvNative = Pointer<FfiResult> Function(Uint32, Pointer<Utf8>);
typedef _ArkCsvDart = Pointer<FfiResult> Function(int, Pointer<Utf8>);
final arkCsvSigScriptFfi = nativeLib
    .lookupFunction<_ArkCsvNative, _ArkCsvDart>('ark_csv_sig_script');

typedef _ArkTapleafHashNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _ArkTapleafHashDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final arkTapleafHashFfi = nativeLib
    .lookupFunction<_ArkTapleafHashNative, _ArkTapleafHashDart>(
        'ark_tapleaf_hash');

// ---------------------------------------------------------------------------
// Ark Send bindings
// ---------------------------------------------------------------------------

typedef _ArkBuildSendTxNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _ArkBuildSendTxDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final arkBuildSendTxFfi = nativeLib
    .lookupFunction<_ArkBuildSendTxNative, _ArkBuildSendTxDart>(
        'ark_build_send_tx');

typedef _ArkInsertSendSigsNative = Pointer<FfiResult> Function(
    Uint64, Pointer<Utf8>);
typedef _ArkInsertSendSigsDart = Pointer<FfiResult> Function(
    int, Pointer<Utf8>);
final arkInsertSendSignaturesFfi = nativeLib
    .lookupFunction<_ArkInsertSendSigsNative, _ArkInsertSendSigsDart>(
        'ark_insert_send_signatures');

typedef _ArkGetChangeVtxoNative = Pointer<FfiResult> Function(Uint64);
typedef _ArkGetChangeVtxoDart = Pointer<FfiResult> Function(int);
final arkGetChangeVtxoFfi = nativeLib
    .lookupFunction<_ArkGetChangeVtxoNative, _ArkGetChangeVtxoDart>(
        'ark_get_change_vtxo');

typedef _ArkFreeSendSessionNative = Void Function(Uint64);
typedef _ArkFreeSendSessionDart = void Function(int);
final arkFreeSendSessionFfi = nativeLib
    .lookupFunction<_ArkFreeSendSessionNative, _ArkFreeSendSessionDart>(
        'ark_free_send_session');

// ---------------------------------------------------------------------------
// eVTXO cooperative-spend bindings
// ---------------------------------------------------------------------------

typedef _ArkBuildEvtxoSpendNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _ArkBuildEvtxoSpendDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final arkBuildEvtxoSpendFfi = nativeLib
    .lookupFunction<_ArkBuildEvtxoSpendNative, _ArkBuildEvtxoSpendDart>(
        'ark_build_evtxo_spend');

typedef _ArkFinalizeEvtxoSpendNative = Pointer<FfiResult> Function(
    Uint64, Pointer<Utf8>, Pointer<Utf8>);
typedef _ArkFinalizeEvtxoSpendDart = Pointer<FfiResult> Function(
    int, Pointer<Utf8>, Pointer<Utf8>);
final arkFinalizeEvtxoSpendFfi = nativeLib
    .lookupFunction<_ArkFinalizeEvtxoSpendNative, _ArkFinalizeEvtxoSpendDart>(
        'ark_finalize_evtxo_spend');

typedef _ArkFreeEvtxoSpendNative = Void Function(Uint64);
typedef _ArkFreeEvtxoSpendDart = void Function(int);
final arkFreeEvtxoSpendFfi = nativeLib
    .lookupFunction<_ArkFreeEvtxoSpendNative, _ArkFreeEvtxoSpendDart>(
        'ark_free_evtxo_spend');

typedef _ArkEvtxoArkAddressNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _ArkEvtxoArkAddressDart = Pointer<FfiResult> Function(Pointer<Utf8>);
final arkEvtxoArkAddressFfi = nativeLib
    .lookupFunction<_ArkEvtxoArkAddressNative, _ArkEvtxoArkAddressDart>(
        'ark_evtxo_ark_address');

// ---------------------------------------------------------------------------
// The unilateral exit
// ---------------------------------------------------------------------------
//
// JSON in, JSON out — see `ffi/src/ark/exit.rs`. The wallet builds the same exit transactions the
// cosigner builds, so that it can check the sighashes it is asked to sign before signing them.
// `ark_exit_spend_info` above is a different, older thing: it derives from a taptree real VTXOs do
// not use, and is on its way out.

typedef _ArkJsonNative = Pointer<FfiResult> Function(Pointer<Utf8>);
typedef _ArkJsonDart = Pointer<FfiResult> Function(Pointer<Utf8>);

final arkVtxoExitSpendInfoFfi = nativeLib
    .lookupFunction<_ArkJsonNative, _ArkJsonDart>('ark_vtxo_exit_spend_info');
final arkBuildExitTxFfi =
    nativeLib.lookupFunction<_ArkJsonNative, _ArkJsonDart>('ark_build_exit_tx');
final arkFinalizeExitTxFfi =
    nativeLib.lookupFunction<_ArkJsonNative, _ArkJsonDart>('ark_finalize_exit_tx');
final arkVerifyExitTxFfi =
    nativeLib.lookupFunction<_ArkJsonNative, _ArkJsonDart>('ark_verify_exit_tx');

typedef _ArkSpkNative = Pointer<FfiResult> Function(Pointer<Utf8>, Pointer<Utf8>);
typedef _ArkSpkDart = Pointer<FfiResult> Function(Pointer<Utf8>, Pointer<Utf8>);
final arkOnchainScriptPubkeyFfi = nativeLib
    .lookupFunction<_ArkSpkNative, _ArkSpkDart>('ark_onchain_script_pubkey');
