/// Renewing, with the wallet driving the ASP round.
///
/// The cosigner used to hold the ASP connection for this: it registered the intent, opened the
/// event stream, and reacted to each event itself, which made it the Ark client as well as the
/// signer. It has no socket now, so the loop inverts — the wallet relays each event and the
/// cosigner answers with what to send the ASP next.
///
/// One RPC covers both shapes: a boarding output settles when [boardingUtxo] is given, a
/// self-refresh of the held VTXOs when it is not.
///
/// **Every server message must be answered.** The cosigner reads after every yield, so a driver
/// that skips a reply deadlocks the round rather than failing it.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:async/async.dart';
import 'package:fixnum/fixnum.dart';
import 'package:protocol/ark_v1.dart' as ark;
import 'package:protocol/cosigner_v1.dart' as cs;

import '../asp/asp_client.dart';
import '../cosigner/connection.dart';
import '../passkey/operation_secrets.dart';
import '../threshold_types.dart' as threshold;
import 'in_band_round.dart';
import 'send_session.dart';
import 'delegate.dart';
import 'exit_plan.dart';

/// What a renewal produced.
class RenewResult {
  RenewResult({
    required this.commitmentTxid,
    required this.vtxoTxid,
    required this.vtxoVout,
    required this.amountSats,
    required this.exitDelay,
    this.delegate,
  });
  final String commitmentTxid;
  final String vtxoTxid;
  final int vtxoVout;
  final int amountSats;
  final int exitDelay;

  /// The delegate renewed over the wallet's set after the renewal, when asked for and possible. See
  /// `delegate.dart`.
  final DelegateStatus? delegate;
}

/// Progress, for a UI that has to show something while a batch round runs. Renewing waits on the
/// ASP's own schedule, which is minutes, not milliseconds.
enum RenewPhase { registering, waitingForBatch, signingTree, finalizing, done }

class RenewSession {
  RenewSession(this._conn, this._asp);
  final CosignerConnection _conn;
  final AspClient _asp;

  /// Renew the delegate over [vtxos] — the wallet's whole current set — without refreshing
  /// anything now. For funds that arrived by a receive; a send or a renewal renews it on its way
  /// out.
  Future<DelegateStatus> renewDelegate({
    required ArkInfo info,
    required List<int> identifier,
    required KeyResolver resolve,
    required threshold.PublicKeyPackage groupPubKey,
    required List<IndexerVtxo> vtxos,
    String deviceToken = '',
    String exitScriptPubkeyHex = '',
    String ownerXOnlyHex = '',
  }) async {
    final duplex = _conn.openRenew();
    try {
      duplex.send(cs.RenewClientMsg(
        sessionId: '',
        seq: Int64(0),
        open: cs.RenewOpen(
          arkInfo: arkInfoToProto(info),
          vtxos: vtxosToProto(vtxos),
          delegateOnly: true,
          deviceToken: deviceToken,
          exitScriptPubkey: hexBytes(exitScriptPubkeyHex),
          identifier: identifier,
        ),
      ));
      return await answerDelegateRenewal<cs.RenewClientMsg, cs.RenewServerMsg>(
        duplex: duplex,
        resolve: resolve,
        groupPubKey: groupPubKey,
        sighashesOf: _sighashesOf,
        signed: (rounds) =>
            cs.RenewClientMsg(sessionId: '', seq: Int64(1), signed: cs.RenewSigned(rounds: rounds)),
        renewedOf: (r) => r.hasDelegateRenewed() ? r.delegateRenewed : null,
        exits: exitScriptPubkeyHex.isEmpty
            ? null
            : ExitPlan(
                ownerXOnlyHex: ownerXOnlyHex,
                info: info,
                destinationScriptPubkeyHex: exitScriptPubkeyHex,
                vtxos: vtxos,
              ),
      );
    } finally {
      await duplex.close();
    }
  }

  static ({
    List<List<int>> sighashes,
    List<List<int>> exitMessages,
    List<cs.Commitment> commitments,
    String identifier,
    bool scriptPathSpend,
    List<int> dealtShare,
  })? _sighashesOf(cs.RenewServerMsg r) => r.hasSighashes()
      ? (
          sighashes: r.sighashes.messagesToSign,
          exitMessages: r.sighashes.exitMessages,
          commitments: r.sighashes.cosignerCommitments,
          identifier: r.sighashes.cosignerIdentifier,
          scriptPathSpend: r.sighashes.scriptPathSpend,
          dealtShare: r.sighashes.walletDealtShare,
        )
      : null;

  /// Renew. Returns when the batch finalizes.
  Future<RenewResult> renew({
    required ArkInfo info,
    required List<int> identifier,
    required KeyResolver resolve,
    required threshold.PublicKeyPackage groupPubKey,
    cs.BoardingUtxo? boardingUtxo,
    List<IndexerVtxo> vtxos = const [],
    CancelSignal? cancel,
    void Function(RenewPhase)? onProgress,
    Future<List<IndexerVtxo>> Function()? readHeld,
    String deviceToken = '',
    String exitScriptPubkeyHex = '',
    String ownerXOnlyHex = '',
  }) async {
    final duplex = _conn.openRenew();
    StreamQueue<ark.GetEventStreamResponse>? events;
    var seq = 0;

    void report(RenewPhase p) => onProgress?.call(p);

    // Most of a renewal is waiting on the ASP — its batch schedule is minutes — and from the intent
    // proof on, this operation is holding the wallet's share while it waits. Closing the cosigner's
    // stream interrupts none of that, so every ASP and indexer wait goes through this: see
    // `CancelSignal`. An ASP that goes quiet must not be able to keep a share in memory.
    Future<T> guarded<T>(Future<T> work) => cancel?.guard(work) ?? work;

    try {
      report(RenewPhase.registering);
      duplex.send(cs.RenewClientMsg(
        sessionId: '',
        seq: Int64(seq++),
        open: cs.RenewOpen(
          boardingUtxo: boardingUtxo,
          arkInfo: arkInfoToProto(info),
          vtxos: vtxosToProto(vtxos),
          identifier: identifier,
        ),
      ));

      while (true) {
        final msg = await duplex.next('the next step');

        switch (msg.whichBody()) {
          // FROST signatures, on the intent proof first and the commitment transaction later —
          // in-band, on this stream. A nested `Sign` would wait forever for the tenant this stream
          // is holding. See `in_band_round.dart`.
          case cs.RenewServerMsg_Body.sighashes:
            final h = msg.sighashes;
            // The first of these brings the half of the share the cosigner dealt, and the share
            // is rebuilt then. The later ones bring nothing and sign with the same one.
            final keyPkg = resolve(h.walletDealtShare);
            duplex.send(cs.RenewClientMsg(
              sessionId: '',
              seq: Int64(seq++),
              signed: cs.RenewSigned(
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

          // Register the intent, then subscribe — in that order, because the topics ride with the
          // proof. Subscribe BEFORE replying: a `StreamQueue` buffers from the moment it opens, so
          // everything after this point is captured even while the cosigner is still thinking.
          case cs.RenewServerMsg_Body.register:
            final intentId = await guarded(_asp.registerIntent(
              msg.register.proof,
              msg.register.message,
            ));
            events = StreamQueue(_asp.getEventStream(msg.register.topics));
            report(RenewPhase.waitingForBatch);
            duplex.send(cs.RenewClientMsg(
              sessionId: '',
              seq: Int64(seq++),
              registered: cs.IntentRegistered(intentId: intentId),
            ));

          // One ASP call on the cosigner's behalf, then the next event.
          case cs.RenewServerMsg_Body.submit:
            await guarded(_submit(msg.submit, report));
            duplex.send(await guarded(_relayNext(events, seq++)));

          // The event produced nothing. Relay the next one.
          case cs.RenewServerMsg_Body.idle:
            duplex.send(await guarded(_relayNext(events, seq++)));

          case cs.RenewServerMsg_Body.complete:
            // The round is over; stop listening to the ASP before waiting on the indexer.
            await events?.cancel(immediate: true);
            events = null;
            final c = msg.complete;
            // Renew the delegate over what is held now, before closing. A refresh spent every VTXO
            // it was given; a boarding settle spent none. Either way the new VTXO has to be
            // indexed.
            final delegate = readHeld == null
                ? null
                : await renewDelegateAfter<cs.RenewClientMsg, cs.RenewServerMsg>(
                    duplex: duplex,
                    held: guarded(heldOnceIndexed(
                      readHeld,
                      // A batch round's output reaches the indexer later than a send's change, and
                      // giving up early is what used to leave a refreshed wallet un-armed — the
                      // owner refreshed, and still had to renew it again by hand.
                      timeout: const Duration(seconds: 45),
                      gone: {for (final v in vtxos) '${v.txid}:${v.vout}'},
                      // Only a boarding settle reports its new outpoint reliably; a refresh can fall
                      // back to the commitment txid, which is not one.
                      arrived: boardingUtxo == null || c.vtxoTxid.isEmpty
                          ? null
                          : '${c.vtxoTxid}:${c.vtxoVout}',
                    )),
                    info: info,
                    resolve: resolve,
                    groupPubKey: groupPubKey,
                    request: (s) =>
                        cs.RenewClientMsg(sessionId: '', seq: Int64(seq++), renewDelegate: s),
                    deviceToken: deviceToken,
                    exitScriptPubkeyHex: exitScriptPubkeyHex,
                    ownerXOnlyHex: ownerXOnlyHex,
                    sighashesOf: _sighashesOf,
                    signed: (rounds) => cs.RenewClientMsg(
                        sessionId: '', seq: Int64(seq++), signed: cs.RenewSigned(rounds: rounds)),
                    renewedOf: (r) => r.hasDelegateRenewed() ? r.delegateRenewed : null,
                  );
            report(RenewPhase.done);
            return RenewResult(
              commitmentTxid: c.commitmentTxid,
              vtxoTxid: c.vtxoTxid,
              vtxoVout: c.vtxoVout,
              amountSats: c.amountSats.toInt(),
              exitDelay: c.exitDelay,
              delegate: delegate,
            );

          case cs.RenewServerMsg_Body.delegateRenewed:
            throw CosignerException('the cosigner renewed a delegate nobody asked for yet');

          case cs.RenewServerMsg_Body.notSet:
            throw CosignerException('the cosigner sent an empty renew message');
        }
      }
    } finally {
      await events?.cancel(immediate: true);
      await duplex.close();
    }
  }

  Future<void> _submit(cs.AspSubmit submit, void Function(RenewPhase) report) async {
    switch (submit.whichCall()) {
      case cs.AspSubmit_Call.confirmRegistration:
        await _asp.confirmRegistration(submit.confirmRegistration.intentId);
      case cs.AspSubmit_Call.treeNonces:
        report(RenewPhase.signingTree);
        await _asp.submitTreeNonces(
          submit.treeNonces.batchId,
          submit.treeNonces.pubkey,
          submit.treeNonces.nonces,
        );
      case cs.AspSubmit_Call.treeSignatures:
        await _asp.submitTreeSignatures(
          submit.treeSignatures.batchId,
          submit.treeSignatures.pubkey,
          submit.treeSignatures.signatures,
        );
      case cs.AspSubmit_Call.forfeitTxs:
        report(RenewPhase.finalizing);
        // Two fields, not one list: the ASP takes the forfeits and the signed commitment
        // separately, and packing them together made a one-element list ambiguous.
        await _asp.submitSignedForfeitTxs(
          forfeitTxs: submit.forfeitTxs.signedForfeitTxs,
          commitmentTx: submit.forfeitTxs.signedCommitmentTx,
        );
      case cs.AspSubmit_Call.notSet:
        throw CosignerException('the cosigner asked for an empty ASP call');
    }
  }

  /// The next ASP event, wrapped for the cosigner.
  ///
  /// `encoded` is the whole `GetEventStreamResponse`, not the inner event: the cosigner decodes it
  /// with prost on the other side, and a partial message would fail there rather than here.
  Future<cs.RenewClientMsg> _relayNext(
    StreamQueue<ark.GetEventStreamResponse>? events,
    int seq,
  ) async {
    if (events == null) {
      throw CosignerException(
        'the cosigner asked for an ASP event before the intent was registered',
      );
    }
    if (!await events.hasNext) {
      throw CosignerException('the ASP event stream ended mid-batch');
    }
    final resp = await events.next;
    return cs.RenewClientMsg(
      sessionId: '',
      seq: Int64(seq),
      event: cs.AspEvent(encoded: Uint8List.fromList(resp.writeToBuffer())),
    );
  }
}
