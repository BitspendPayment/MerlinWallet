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


import 'package:fixnum/fixnum.dart';
import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:protocol/protocol.dart' as pb;

import '../asp/asp_client.dart';
import '../cosigner/connection.dart';
import 'in_band_round.dart';
import 'delegate.dart';
import '../threshold_types.dart' as threshold;

/// What a send produced.
class SendResult {
  SendResult(this.arkTxid, this.delegate);
  final String arkTxid;

  /// The delegate sealed over the wallet's set after the send, when [SendSession.send] was asked to
  /// and could. See `delegate.dart`.
  final DelegateStatus? delegate;
}

class SendSession {
  SendSession(this._conn, this._asp);
  final CosignerConnection _conn;
  final AspClient _asp;

  /// Send [amountSats] to [recipientArkAddress].
  ///
  /// With [readHeld], once the send completes the wallet's set is re-read until the indexer
  /// reflects it and a delegate is sealed over it, on this stream — see `delegate.dart`.
  ///
  /// [vtxos] is what this wallet holds, from the indexer. The cosigner validates every one against
  /// the scriptPubKey it derives from its own owner key before selecting from them, so naming a
  /// VTXO here cannot widen what the wallet owns.
  Future<SendResult> send({
    required String recipientArkAddress,
    required int amountSats,
    required List<IndexerVtxo> vtxos,
    required ArkInfo info,
    required threshold.KeyPackage keyPkg,
    required threshold.PublicKeyPackage groupPubKey,
    Future<List<IndexerVtxo>> Function()? readHeld,
  }) async {
    final duplex = _conn.openSend();
    try {
      duplex.send(cs.SendClientMsg(
        sessionId: '',
        seq: Int64(0),
        open: cs.SendOpen(
          recipientArkAddress: recipientArkAddress,
          amount: Int64(amountSats),
          arkInfo: arkInfoToProto(info),
          vtxos: vtxosToProto(vtxos),
        ),
      ));

      // --- Sign what it built, on this stream ------------------------------------------------
      //
      // In-band, not a nested `Sign` per sighash: this stream holds the tenant for its whole life,
      // so a second call would wait for it forever. See `in_band_round.dart`.
      final sighashes = await duplex.next('the sighashes');
      if (!sighashes.hasSighashes()) {
        throw CosignerException('expected the sighashes, got ${sighashes.whichBody()}');
      }
      final h = sighashes.sighashes;
      duplex.send(cs.SendClientMsg(
        sessionId: '',
        seq: Int64(1),
        signed: cs.SendSigned(
          rounds: answerRound(
            sighashes: h.messagesToSign,
            cosignerCommitments: h.cosignerCommitments,
            cosignerIdentifier: h.cosignerIdentifier,
            scriptPathSpend: h.scriptPathSpend,
            keyPkg: keyPkg,
            groupPubKey: groupPubKey,
          ),
        ),
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
      final arkTxid = complete.complete.arkTxid;

      // --- Seal a delegate over what is held now, before closing -----------------------------
      final delegate = readHeld == null
          ? null
          : await sealAfter<cs.SendClientMsg, cs.SendServerMsg>(
              duplex: duplex,
              // A send spends every input it was given; what remains is its change, and whatever
              // arrived meanwhile.
              held: heldOnceIndexed(readHeld, gone: {for (final v in vtxos) '${v.txid}:${v.vout}'}),
              info: info,
              keyPkg: keyPkg,
              groupPubKey: groupPubKey,
              seal: (s) => cs.SendClientMsg(sessionId: '', seq: Int64(4), seal: s),
              sighashesOf: (r) => r.hasSighashes()
                  ? (
                      sighashes: r.sighashes.messagesToSign,
                      commitments: r.sighashes.cosignerCommitments,
                      identifier: r.sighashes.cosignerIdentifier,
                      scriptPathSpend: r.sighashes.scriptPathSpend,
                    )
                  : null,
              signed: (rounds) =>
                  cs.SendClientMsg(sessionId: '', seq: Int64(5), signed: cs.SendSigned(rounds: rounds)),
              sealedOf: (r) => r.hasSealed() ? r.sealed : null,
            );
      return SendResult(arkTxid, delegate);
    } finally {
      await duplex.close();
    }
  }
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
          expiresAt: Int64(v.expiresAt),
        ),
    ];
