/// Ark protocol helpers — VTXO address derivation, spend info, and scripts.
///
/// Calls into the `threshold` Rust library via FFI for all taproot/script
/// computations, keeping it as the single source of truth.
library;

import 'dart:convert';
import 'package:ffi/ffi.dart';
import 'package:bitcoin_base/bitcoin_base.dart';

import 'src/bindings.dart';
import 'src/ffi_result.dart';

/// Where this wallet receives off-chain.
///
/// The cosigner used to derive this and hand it back over `GetArkAddress` — an RPC that took a key
/// the caller already held and ran ark-core over it. The Rust side has a parity test against
/// `ark::client::address`, which is what makes deriving here safe rather than a second guess at a
/// consensus-critical taptree.
///
/// [ownerXOnlyHex] is this wallet's group key, x-only. [aspPubkeyHex] may be x-only or compressed —
/// the ASP publishes the compressed form.
String arkAddress({
  required String ownerXOnlyHex,
  required String aspPubkeyHex,
  required int exitDelay,
  required String network,
}) =>
    _deriveAddress(arkAddressFfi, ownerXOnlyHex, aspPubkeyHex, exitDelay, network);

/// Where this wallet receives on-chain, to be boarded into Ark.
String boardingAddress({
  required String ownerXOnlyHex,
  required String aspPubkeyHex,
  required int exitDelay,
  required String network,
}) =>
    _deriveAddress(
        arkBoardingAddressFfi, ownerXOnlyHex, aspPubkeyHex, exitDelay, network);

/// The scriptPubKey this wallet's VTXOs sit under, for querying the indexer.
///
/// A wallet has TWO — one per exit delay. A boarded VTXO keeps the boarding delay while received
/// and refreshed ones use the unilateral delay, so they sit under different scripts, and asking for
/// one makes the other bucket invisible.
String vtxoScriptPubkeyHex({
  required String ownerXOnlyHex,
  required String aspPubkeyHex,
  required int exitDelay,
  required String network,
}) =>
    _deriveAddress(
        arkVtxoScriptPubkeyHexFfi, ownerXOnlyHex, aspPubkeyHex, exitDelay, network);

String _deriveAddress(
  dynamic fn,
  String ownerXOnlyHex,
  String aspPubkeyHex,
  int exitDelay,
  String network,
) {
  final ownerPtr = ownerXOnlyHex.toNativeUtf8();
  final aspPtr = aspPubkeyHex.toNativeUtf8();
  final netPtr = network.toNativeUtf8();
  try {
    return callFfiData(fn(ownerPtr, aspPtr, exitDelay, netPtr));
  } finally {
    calloc.free(ownerPtr);
    calloc.free(aspPtr);
    calloc.free(netPtr);
  }
}

/// Spend info for a taproot script-path leaf.
class SpendInfo {
  /// Raw script bytes (hex-encoded).
  final String scriptHex;

  /// Serialized control block (hex-encoded).
  final String controlBlockHex;

  const SpendInfo({required this.scriptHex, required this.controlBlockHex});
}

/// Represents an Ark VTXO with a default two-leaf taproot tree:
///   Leaf 0 (forfeit):  <server_pk> OP_CHECKSIGVERIFY <owner_pk> OP_CHECKSIG
///   Leaf 1 (exit):     <owner_pk> OP_CHECKSIGVERIFY <sequence> OP_CSV OP_DROP
class ArkVtxo {
  /// Server x-only public key (64-char hex).
  final String serverXOnlyHex;

  /// Owner x-only public key (64-char hex).
  final String ownerXOnlyHex;

  /// CSV exit delay (number of blocks).
  final int exitDelay;

  const ArkVtxo({
    required this.serverXOnlyHex,
    required this.ownerXOnlyHex,
    required this.exitDelay,
  });

  /// Compute the VTXO script pubkey (hex-encoded, 34 bytes = OP_1 <32-byte x-only key>).
  String scriptPubkeyHex() {
    final serverPtr = serverXOnlyHex.toNativeUtf8();
    final ownerPtr = ownerXOnlyHex.toNativeUtf8();
    try {
      return callFfiData(
        arkDefaultVtxoScriptPubkeyFfi(serverPtr, ownerPtr, exitDelay),
      );
    } finally {
      calloc.free(serverPtr);
      calloc.free(ownerPtr);
    }
  }

  /// Get forfeit (cooperative) spend info: script + control block.
  SpendInfo forfeitSpendInfo() {
    final serverPtr = serverXOnlyHex.toNativeUtf8();
    final ownerPtr = ownerXOnlyHex.toNativeUtf8();
    try {
      final json = callFfiData(
        arkForfeitSpendInfoFfi(serverPtr, ownerPtr, exitDelay),
      );
      final map = jsonDecode(json) as Map<String, dynamic>;
      return SpendInfo(
        scriptHex: map['script_hex'] as String,
        controlBlockHex: map['control_block_hex'] as String,
      );
    } finally {
      calloc.free(serverPtr);
      calloc.free(ownerPtr);
    }
  }

  /// Get exit (unilateral) spend info: script + control block.
  SpendInfo exitSpendInfo() {
    final serverPtr = serverXOnlyHex.toNativeUtf8();
    final ownerPtr = ownerXOnlyHex.toNativeUtf8();
    try {
      final json = callFfiData(
        arkExitSpendInfoFfi(serverPtr, ownerPtr, exitDelay),
      );
      final map = jsonDecode(json) as Map<String, dynamic>;
      return SpendInfo(
        scriptHex: map['script_hex'] as String,
        controlBlockHex: map['control_block_hex'] as String,
      );
    } finally {
      calloc.free(serverPtr);
      calloc.free(ownerPtr);
    }
  }

  /// Derive the bech32m P2TR address for this VTXO.
  String deriveAddress({required BasedUtxoNetwork network}) {
    final spkHex = scriptPubkeyHex();
    // scriptPubkey is: 0x51 0x20 <32-byte x-only key>
    // The x-only key starts at byte 2 (offset 4 in hex)
    final xOnlyHex = spkHex.substring(4);
    final address = P2trAddress.fromProgram(program: xOnlyHex);
    return address.toAddress(network);
  }
}

/// Build a forfeit/cooperative multisig script (hex-encoded).
String arkMultisigScript(String serverXOnlyHex, String ownerXOnlyHex) {
  final serverPtr = serverXOnlyHex.toNativeUtf8();
  final ownerPtr = ownerXOnlyHex.toNativeUtf8();
  try {
    return callFfiData(arkMultisigScriptFfi(serverPtr, ownerPtr));
  } finally {
    calloc.free(serverPtr);
    calloc.free(ownerPtr);
  }
}

/// Build a CSV + signature exit script (hex-encoded).
String arkCsvSigScript(int exitDelay, String ownerXOnlyHex) {
  final ownerPtr = ownerXOnlyHex.toNativeUtf8();
  try {
    return callFfiData(arkCsvSigScriptFfi(exitDelay, ownerPtr));
  } finally {
    calloc.free(ownerPtr);
  }
}

/// Compute the TapLeaf hash of a script (hex-encoded, 32 bytes).
String arkTapleafHash(String scriptHex) {
  final scriptPtr = scriptHex.toNativeUtf8();
  try {
    return callFfiData(arkTapleafHashFfi(scriptPtr));
  } finally {
    calloc.free(scriptPtr);
  }
}
