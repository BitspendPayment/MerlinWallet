/// The unilateral exit, on the wallet's side.
///
/// A VTXO can be spent two ways: with the ASP's help, or alone after a relative timelock. The
/// second way is what remains when the ASP or this wallet's cosigner stops answering — except that
/// the "alone" is a 2-of-2, so the signature has to be obtained while the cosigner is still here.
/// That is what a seal does: it hands back one signed exit per VTXO, and the wallet keeps them.
///
/// What this file is for is the check before the signature. The cosigner builds the exits and asks
/// the wallet to sign their sighashes; the wallet builds the same exits from what it independently
/// knows — its own VTXOs, its own exit address, the ASP's delays — and signs only if every sighash
/// matches. Same Rust underneath (`ark::exit`), so a mismatch means the cosigner asked for
/// something else, not that two implementations drifted.
library;

import 'dart:convert';

import 'package:ffi/ffi.dart';

import 'src/bindings.dart';
import 'src/ffi_result.dart';

/// An exit transaction before it has a signature.
class ExitSpend {
  ExitSpend({
    required this.sighash,
    required this.unsignedTx,
    required this.script,
    required this.controlBlock,
    required this.sequence,
  });

  /// What the 2-of-2 signs: BIP-341, script-path, over the exit leaf.
  final String sighash;
  final String unsignedTx;

  /// The exit leaf and its control block, for the witness.
  final String script;
  final String controlBlock;

  /// The nSequence the spend carries — the VTXO's exit delay, BIP-68 encoded. It is also how long
  /// after the VTXO's own transaction confirms this can be mined.
  final int sequence;
}

/// Build the exit of one VTXO, paying everything to [destinationScriptPubkeyHex].
///
/// No fee: the transaction carries an anchor instead, so whoever wants it confirmed attaches a
/// child that pays for both. A fee fixed today would be a guess about the fee market of whatever
/// day this is finally needed, and by then nobody can re-sign it.
ExitSpend buildExitTx({
  required String ownerXOnlyHex,
  required String aspPubkeyHex,
  required String network,
  required String txid,
  required int vout,
  required int amountSats,
  required int exitDelay,
  required String destinationScriptPubkeyHex,
}) {
  final json = _callJson(arkBuildExitTxFfi, {
    'owner_pk': ownerXOnlyHex,
    'asp_pk': aspPubkeyHex,
    'network': network,
    'txid': txid,
    'vout': vout,
    'amount_sats': amountSats,
    'exit_delay': exitDelay,
    'destination_script_pubkey': destinationScriptPubkeyHex,
  });
  return ExitSpend(
    sighash: json['sighash'] as String,
    unsignedTx: json['unsigned_tx'] as String,
    script: json['script'] as String,
    controlBlock: json['control_block'] as String,
    sequence: json['sequence'] as int,
  );
}

/// The signed transaction, hex, ready for anyone to broadcast.
///
/// The wallet does not normally need this — the cosigner returns finished transactions — but it is
/// what makes them checkable: finalizing the wallet's own build with the returned signature must
/// give back the very bytes the cosigner sent.
String finalizeExitTx({
  required ExitSpend spend,
  required String signatureHex,
}) =>
    _callJson(arkFinalizeExitTxFfi, {
      'unsigned_tx': spend.unsignedTx,
      'script': spend.script,
      'control_block': spend.controlBlock,
      'signature': signatureHex,
    }, raw: true)['raw'] as String;

/// The exit leaf, its control block, the scriptPubKey the VTXO sits under, and the nSequence.
Map<String, dynamic> exitSpendInfo({
  required String ownerXOnlyHex,
  required String aspPubkeyHex,
  required int exitDelay,
  required String network,
}) =>
    _callJson(arkVtxoExitSpendInfoFfi, {
      'owner_pk': ownerXOnlyHex,
      'asp_pk': aspPubkeyHex,
      'exit_delay': exitDelay,
      'network': network,
    });

/// The scriptPubKey of an ordinary on-chain address, for [network].
///
/// Throws when the address is malformed or belongs to another network — which is the point: an
/// exit address is checked when the user types it, not on the day it is needed.
String onchainScriptPubkey({required String address, required String network}) {
  final addressPtr = address.toNativeUtf8();
  final networkPtr = network.toNativeUtf8();
  try {
    return callFfiData(arkOnchainScriptPubkeyFfi(addressPtr, networkPtr));
  } finally {
    calloc.free(addressPtr);
    calloc.free(networkPtr);
  }
}

Map<String, dynamic> _callJson(dynamic fn, Map<String, dynamic> params, {bool raw = false}) {
  final ptr = jsonEncode(params).toNativeUtf8();
  try {
    final data = callFfiData(fn(ptr));
    return raw ? {'raw': data} : jsonDecode(data) as Map<String, dynamic>;
  } finally {
    calloc.free(ptr);
  }
}

/// Check an exit the cosigner returned against the one this wallet built and signed, and return
/// its txid.
///
/// Throws unless it is the same transaction, carrying a signature by [ownerXOnlyHex] — the 2-of-2's
/// key — over [spend]'s sighash. An exit that pays somewhere else, or one signed over something
/// else, is refused here rather than stored and discovered useless.
///
/// The txid falls out of the same parse, which is why it is taken from here rather than from
/// whatever the cosigner claimed it to be.
String verifyExitTx({
  required ExitSpend spend,
  required String ownerXOnlyHex,
  required String rawTxHex,
}) =>
    _callJson(arkVerifyExitTxFfi, {
      'unsigned_tx': spend.unsignedTx,
      'sighash': spend.sighash,
      'script': spend.script,
      'control_block': spend.controlBlock,
      'owner_pk': ownerXOnlyHex,
      'raw_tx': rawTxHex,
    }, raw: true)['raw'] as String;
