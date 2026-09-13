/// An off-chain send, as one bidirectional session with the wallet talking to the ASP.
///
/// Four exchanges. The cosigner builds the transaction and hands back sighashes; the wallet
/// FROST-signs them; the cosigner hands back what to `SubmitTx`; the wallet submits and returns
/// what the ASP said; the cosigner turns that into what to `FinalizeTx`; the wallet finalizes and
/// says so, and only then does the cosigner record the send.
///
/// That last ordering is the point of the fourth exchange. The cosigner used to call `SubmitTx` and
/// `FinalizeTx` itself; it has no socket now, so the wallet makes both calls — and the cosigner
/// waits to be told the ASP accepted before sealing anything, so an interrupted send leaves neither
/// a half-signed transaction nor a recorded spend that never happened.
library;

import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:protocol/protocol.dart' as pb;

import '../asp/asp_client.dart';
import '../cosigner/connection.dart';
import '../threshold/frost/ceremony.dart';
import 'sign_session.dart';
import '../threshold_types.dart' as threshold;

class SendSession {
  SendSession(this._conn, this._asp);
  final CosignerConnection _conn;
  final AspClient _asp;

  /// Send [amountSats] to [recipientArkAddress]. Returns the ark txid.
  ///
  /// [vtxos] is what this wallet holds, from the indexer. The cosigner validates every one against
  /// the scriptPubKey it derives from its own owner key before selecting from them, so naming a
  /// VTXO here cannot widen what the wallet owns.
  Future<String> send({
    required String recipientArkAddress,
    required int amountSats,
    required List<IndexerVtxo> vtxos,
    required ArkInfo info,
    required threshold.KeyPackage keyPkg,
    required threshold.PublicKeyPackage groupPubKey,
    required List<int> userId,
    required List<int> signature,
    required int timestampMs,
  }) async {
    final duplex = _conn.openSend();
    try {
      duplex.send(cs.SendClientMsg(
        sessionId: '',
        seq: Int64(0),
        open: cs.SendOpen(
          userId: userId,
          signature: signature,
          timestampMs: Int64(timestampMs),
          recipientArkAddress: recipientArkAddress,
          amount: Int64(amountSats),
          arkInfo: arkInfoToProto(info),
          vtxos: vtxosToProto(vtxos),
        ),
      ));

      // --- Sign what it built ---------------------------------------------------------------
      final sighashes = await duplex.next('the sighashes');
      if (!sighashes.hasSighashes()) {
        throw CosignerException('expected the sighashes, got ${sighashes.whichBody()}');
      }
      final signed = await signEach(
        _conn,
        sighashes.sighashes.messagesToSign,
        keyPkg: keyPkg,
        groupPubKey: groupPubKey,
        userId: userId,
        signature: signature,
        timestampMs: timestampMs,
        scriptPathSpend: sighashes.sighashes.scriptPathSpend,
      );
      duplex.send(cs.SendClientMsg(
        sessionId: '',
        seq: Int64(1),
        signed: cs.SendSigned(signedMessages: signed),
      ));

      // --- Submit it to the ASP --------------------------------------------------------------
      final submit = await duplex.next('what to submit');
      if (!submit.hasSubmit()) {
        throw CosignerException('expected what to submit, got ${submit.whichBody()}');
      }
      final submitted = await _asp.submitTx(
        submit.submit.arkTxB64,
        submit.submit.checkpointTxs,
      );
      duplex.send(cs.SendClientMsg(
        sessionId: '',
        seq: Int64(2),
        submitted: cs.SendSubmitted(
          arkTxid: submitted.arkTxid,
          signedCheckpointTxs: submitted.signedCheckpointTxs,
        ),
      ));

      // --- Finalize it ------------------------------------------------------------------------
      final finalize = await duplex.next('what to finalize');
      if (!finalize.hasFinalize()) {
        throw CosignerException('expected what to finalize, got ${finalize.whichBody()}');
      }
      await _asp.finalizeTx(
        finalize.finalize.arkTxid,
        finalize.finalize.finalCheckpointTxs,
      );
      duplex.send(cs.SendClientMsg(
        sessionId: '',
        seq: Int64(3),
        finalized: cs.SendFinalized(),
      ));

      final complete = await duplex.next('the result');
      if (!complete.hasComplete()) {
        throw CosignerException('expected the result, got ${complete.whichBody()}');
      }
      return complete.complete.arkTxid;
    } finally {
      await duplex.close();
    }
  }
}

/// FROST-sign each sighash the cosigner handed back, in order.
///
/// One nested `Sign` session per sighash, and they are sequential on purpose: each consumes a
/// single-use nonce, and the cosigner takes its lock per message rather than across a round, so
/// these interleave with the outer session safely.
Future<List<List<int>>> signEach(
  CosignerConnection conn,
  List<List<int>> sighashes, {
  required threshold.KeyPackage keyPkg,
  required threshold.PublicKeyPackage groupPubKey,
  required List<int> userId,
  required List<int> signature,
  required int timestampMs,
  required bool scriptPathSpend,
}) async {
  final signer = SignSession(conn);
  final out = <List<int>>[];
  for (final sighash in sighashes) {
    final sig = await signer.sign(
      message: Uint8List.fromList(sighash),
      keyPkg: keyPkg,
      groupPubKey: groupPubKey,
      userId: userId,
      signature: signature,
      timestampMs: timestampMs,
      // A script-path spend takes no taproot tweak; a key-path one does. The cosigner says which.
      applyTweak: !scriptPathSpend,
    );
    out.add(schnorr64(sig));
  }
  return out;
}

/// The ASP parameters, on the wire.
pb.ArkInfo arkInfoToProto(ArkInfo i) => pb.ArkInfo(
      signerPubkey: i.signerPubkey,
      forfeitPubkey: i.forfeitPubkey,
      forfeitAddress: i.forfeitAddress,
      checkpointTapscript: i.checkpointTapscript,
      network: i.network,
      sessionDuration: Int64(i.sessionDuration),
      unilateralExitDelay: Int64(i.unilateralExitDelay),
      boardingExitDelay: Int64(i.boardingExitDelay),
      vtxoMinAmount: Int64(i.vtxoMinAmount),
      dust: Int64(i.dust),
    );

/// What this wallet holds, on the wire. The cosigner re-derives ownership; this only says what
/// exists.
List<cs.VtxoInput> vtxosToProto(List<IndexerVtxo> vtxos) => [
      for (final v in vtxos)
        cs.VtxoInput(
          txid: v.txid,
          vout: v.vout,
          amountSats: Int64(v.amountSats),
          // Resolved by `AspClient.getOwnedVtxos` from the script the VTXO came under — the
          // indexer does not report it.
          exitDelay: v.exitDelay,
        ),
    ];
