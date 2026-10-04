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
import '../passkey/operation_secrets.dart';
import 'in_band_round.dart';
import 'delegate.dart';
import '../threshold_types.dart' as threshold;

/// What a send produced.
class SendResult {
  SendResult(this.arkTxid, this.delegate);
  final String arkTxid;

  /// The delegate renewed over the wallet's set after the send, when [SendSession.send] was asked
  /// to and could. See `delegate.dart`.
  final DelegateStatus? delegate;
}

class SendSession {
  SendSession(this._conn, this._asp);
  final CosignerConnection _conn;
  final AspClient _asp;

  /// Send [amountSats] to [recipientArkAddress].
  ///
  /// With [readHeld], once the send completes the wallet's set is re-read until the indexer
  /// reflects it and the delegate is renewed over it, on this stream — see `delegate.dart`.
  ///
  /// [vtxos] is what this wallet holds, from the indexer. The cosigner validates every one against
  /// the scriptPubKey it derives from its own owner key before selecting from them, so naming a
  /// VTXO here cannot widen what the wallet owns.
  Future<SendResult> send({
    required String recipientArkAddress,
    required int amountSats,
    required List<IndexerVtxo> vtxos,
    required ArkInfo info,
    required List<int> identifier,
    required KeyResolver resolve,
    required threshold.PublicKeyPackage groupPubKey,
    CancelSignal? cancel,
    Future<List<IndexerVtxo>> Function()? readHeld,
    String deviceToken = '',
    String exitScriptPubkeyHex = '',
    String ownerXOnlyHex = '',
  }) async {
    final duplex = _conn.openSend();
    try {
      return await drive<cs.SendClientMsg, cs.SendServerMsg>(
        duplex: duplex,
        carry: (msg) => msg,
        uncarry: (msg) => msg,
        recipientArkAddress: recipientArkAddress,
        amountSats: amountSats,
        vtxos: vtxos,
        info: info,
        identifier: identifier,
        resolve: resolve,
        groupPubKey: groupPubKey,
        cancel: cancel,
        readHeld: readHeld,
        deviceToken: deviceToken,
        exitScriptPubkeyHex: exitScriptPubkeyHex,
        ownerXOnlyHex: ownerXOnlyHex,
      );
    } finally {
      await duplex.close();
    }
  }

  /// A send's rounds, on whichever stream carries them: `Send` itself, or `Escrow` funding the
  /// escrow it has just minted (see `EscrowSession`). [carry] puts a `Send` stream's message in the
  /// stream's own, and [uncarry] takes one back out. The stream is the caller's to open and close.
  ///
  /// [recipientArkAddress] is empty for an escrow's funding: the cosigner pays the escrow it
  /// minted, at the address it derives, and refuses a funding send that names one.
  Future<SendResult> drive<Q, R>({
    required Duplex<Q, R> duplex,
    required Q Function(cs.SendClientMsg) carry,
    required cs.SendServerMsg Function(R) uncarry,
    required String recipientArkAddress,
    required int amountSats,
    required List<IndexerVtxo> vtxos,
    required ArkInfo info,
    required List<int> identifier,
    required KeyResolver resolve,
    required threshold.PublicKeyPackage groupPubKey,
    CancelSignal? cancel,
    Future<List<IndexerVtxo>> Function()? readHeld,
    String deviceToken = '',
    String exitScriptPubkeyHex = '',
    String ownerXOnlyHex = '',
  }) async {
    // Every wait on the ASP or the indexer goes through this: the share is a local of this frame
    // from the first sighashes on, and a cancel has to be able to unwind it — see `CancelSignal`.
    Future<T> guarded<T>(Future<T> work) => cancel?.guard(work) ?? work;
    Future<cs.SendServerMsg> next(String expecting) async => uncarry(await duplex.next(expecting));

    duplex.send(carry(cs.SendClientMsg(
      sessionId: '',
      seq: Int64(0),
      open: cs.SendOpen(
        recipientArkAddress: recipientArkAddress,
        amount: Int64(amountSats),
        arkInfo: arkInfoToProto(info),
        vtxos: vtxosToProto(vtxos),
        identifier: identifier,
      ),
    )));

    // --- Sign what it built, on this stream ------------------------------------------------
    //
    // In-band, not a nested `Sign` per sighash: this stream holds the tenant for its whole life,
    // so a second call would wait for it forever. See `in_band_round.dart`.
    final sighashes = await next('the sighashes');
    if (!sighashes.hasSighashes()) {
      throw CosignerException('expected the sighashes, got ${sighashes.whichBody()}');
    }
    final h = sighashes.sighashes;
    // The first sighashes of the stream: they bring the half of the share the cosigner dealt,
    // and this is where the share comes to exist. A trailing delegate renewal reuses it.
    final keyPkg = resolve(h.walletDealtShare);
    duplex.send(carry(cs.SendClientMsg(
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
    )));

    // --- Submit it to the ASP --------------------------------------------------------------
    final submit = await next('what to submit');
    if (!submit.hasSubmit()) {
      throw CosignerException('expected what to submit, got ${submit.whichBody()}');
    }
    final submitted = await guarded(_asp.submitTx(
      submit.submit.arkTxB64,
      submit.submit.checkpointTxs,
    ));
    duplex.send(carry(cs.SendClientMsg(
      sessionId: '',
      seq: Int64(2),
      submitted: cs.SendSubmitted(
        arkTxid: submitted.arkTxid,
        signedCheckpointTxs: submitted.signedCheckpointTxs,
      ),
    )));

    // --- Finalize it ------------------------------------------------------------------------
    final finalize = await next('what to finalize');
    if (!finalize.hasFinalize()) {
      throw CosignerException('expected what to finalize, got ${finalize.whichBody()}');
    }
    await guarded(_asp.finalizeTx(
      finalize.finalize.arkTxid,
      finalize.finalize.finalCheckpointTxs,
    ));
    duplex.send(carry(cs.SendClientMsg(
      sessionId: '',
      seq: Int64(3),
      finalized: cs.SendFinalized(),
    )));

    final complete = await next('the result');
    if (!complete.hasComplete()) {
      throw CosignerException('expected the result, got ${complete.whichBody()}');
    }
    final arkTxid = complete.complete.arkTxid;

    // --- Renew the delegate over what is held now, before closing --------------------------
    final delegate = readHeld == null
        ? null
        : await renewDelegateAfter<Q, R>(
            duplex: duplex,
            // A send spends every input it was given; what remains is its change, and whatever
            // arrived meanwhile.
            held: guarded(
                heldOnceIndexed(readHeld, gone: {for (final v in vtxos) '${v.txid}:${v.vout}'})),
            info: info,
            resolve: resolve,
            groupPubKey: groupPubKey,
            request: (s) =>
                carry(cs.SendClientMsg(sessionId: '', seq: Int64(4), renewDelegate: s)),
            deviceToken: deviceToken,
            exitScriptPubkeyHex: exitScriptPubkeyHex,
            ownerXOnlyHex: ownerXOnlyHex,
            sighashesOf: (msg) {
              final r = uncarry(msg);
              return r.hasSighashes()
                  ? (
                      sighashes: r.sighashes.messagesToSign,
                      exitMessages: r.sighashes.exitMessages,
                      commitments: r.sighashes.cosignerCommitments,
                      identifier: r.sighashes.cosignerIdentifier,
                      scriptPathSpend: r.sighashes.scriptPathSpend,
                      dealtShare: r.sighashes.walletDealtShare,
                    )
                  : null;
            },
            signed: (rounds) => carry(cs.SendClientMsg(
                sessionId: '', seq: Int64(5), signed: cs.SendSigned(rounds: rounds))),
            renewedOf: (msg) {
              final r = uncarry(msg);
              return r.hasDelegateRenewed() ? r.delegateRenewed : null;
            },
          );
    return SendResult(arkTxid, delegate);
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
