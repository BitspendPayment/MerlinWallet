/// Settling, with the wallet driving the ASP round.
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
import '../threshold_types.dart' as threshold;
import 'in_band_round.dart';
import 'send_session.dart';
import 'delegate.dart';

/// What a settle produced.
class SettleResult {
  SettleResult({
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

  /// The delegate sealed over the wallet's set after the settle, when asked for and possible. See
  /// `delegate.dart`.
  final DelegateStatus? delegate;
}

/// Progress, for a UI that has to show something while a batch round runs. Settling waits on the
/// ASP's own schedule, which is minutes, not milliseconds.
enum SettlePhase { registering, waitingForBatch, signingTree, finalizing, done }

class SettleSession {
  SettleSession(this._conn, this._asp);
  final CosignerConnection _conn;
  final AspClient _asp;

  /// Seal a delegate over [vtxos] — the wallet's whole current set — without refreshing anything
  /// now. For funds that arrived by a receive; a send or a settle seals on its way out.
  Future<DelegateStatus> seal({
    required ArkInfo info,
    required threshold.KeyPackage keyPkg,
    required threshold.PublicKeyPackage groupPubKey,
    required List<IndexerVtxo> vtxos,
  }) async {
    final duplex = _conn.openSettle();
    try {
      duplex.send(cs.SettleClientMsg(
        sessionId: '',
        seq: Int64(0),
        open: cs.SettleOpen(arkInfo: arkInfoToProto(info), vtxos: vtxosToProto(vtxos), sealOnly: true),
      ));
      return await answerSeal<cs.SettleClientMsg, cs.SettleServerMsg>(
        duplex: duplex,
        keyPkg: keyPkg,
        groupPubKey: groupPubKey,
        sighashesOf: _sighashesOf,
        signed: (rounds) =>
            cs.SettleClientMsg(sessionId: '', seq: Int64(1), signed: cs.SettleSigned(rounds: rounds)),
        sealedOf: (r) => r.hasSealed() ? r.sealed : null,
      );
    } finally {
      await duplex.close();
    }
  }

  static ({
    List<List<int>> sighashes,
    List<cs.Commitment> commitments,
    String identifier,
    bool scriptPathSpend,
  })? _sighashesOf(cs.SettleServerMsg r) => r.hasSighashes()
      ? (
          sighashes: r.sighashes.messagesToSign,
          commitments: r.sighashes.cosignerCommitments,
          identifier: r.sighashes.cosignerIdentifier,
          scriptPathSpend: r.sighashes.scriptPathSpend,
        )
      : null;

  /// Settle. Returns when the batch finalizes.
  Future<SettleResult> settle({
    required ArkInfo info,
    required threshold.KeyPackage keyPkg,
    required threshold.PublicKeyPackage groupPubKey,
    cs.BoardingUtxo? boardingUtxo,
    List<IndexerVtxo> vtxos = const [],
    void Function(SettlePhase)? onProgress,
    Future<List<IndexerVtxo>> Function()? readHeld,
  }) async {
    final duplex = _conn.openSettle();
    StreamQueue<ark.GetEventStreamResponse>? events;
    var seq = 0;

    void report(SettlePhase p) => onProgress?.call(p);

    try {
      report(SettlePhase.registering);
      duplex.send(cs.SettleClientMsg(
        sessionId: '',
        seq: Int64(seq++),
        open: cs.SettleOpen(
          boardingUtxo: boardingUtxo,
          arkInfo: arkInfoToProto(info),
          vtxos: vtxosToProto(vtxos),
        ),
      ));

      while (true) {
        final msg = await duplex.next('the next step');

        switch (msg.whichBody()) {
          // FROST signatures, on the intent proof first and the commitment transaction later —
          // in-band, on this stream. A nested `Sign` would wait forever for the tenant this stream
          // is holding. See `in_band_round.dart`.
          case cs.SettleServerMsg_Body.sighashes:
            final h = msg.sighashes;
            duplex.send(cs.SettleClientMsg(
              sessionId: '',
              seq: Int64(seq++),
              signed: cs.SettleSigned(
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
          case cs.SettleServerMsg_Body.register:
            final intentId = await _asp.registerIntent(
              msg.register.proof,
              msg.register.message,
            );
            events = StreamQueue(_asp.getEventStream(msg.register.topics));
            report(SettlePhase.waitingForBatch);
            duplex.send(cs.SettleClientMsg(
              sessionId: '',
              seq: Int64(seq++),
              registered: cs.IntentRegistered(intentId: intentId),
            ));

          // One ASP call on the cosigner's behalf, then the next event.
          case cs.SettleServerMsg_Body.submit:
            await _submit(msg.submit, report);
            duplex.send(await _relayNext(events, seq++));

          // The event produced nothing. Relay the next one.
          case cs.SettleServerMsg_Body.idle:
            duplex.send(await _relayNext(events, seq++));

          case cs.SettleServerMsg_Body.complete:
            // The round is over; stop listening to the ASP before waiting on the indexer.
            await events?.cancel(immediate: true);
            events = null;
            final c = msg.complete;
            // Seal a delegate over what is held now, before closing. A refresh spent every VTXO it
            // was given; a boarding settle spent none. Either way the new VTXO has to be indexed.
            final delegate = readHeld == null
                ? null
                : await sealAfter<cs.SettleClientMsg, cs.SettleServerMsg>(
                    duplex: duplex,
                    held: heldOnceIndexed(
                      readHeld,
                      gone: {for (final v in vtxos) '${v.txid}:${v.vout}'},
                      // Only a boarding settle reports its new outpoint reliably; a refresh can fall
                      // back to the commitment txid, which is not one.
                      arrived: boardingUtxo == null || c.vtxoTxid.isEmpty
                          ? null
                          : '${c.vtxoTxid}:${c.vtxoVout}',
                    ),
                    info: info,
                    keyPkg: keyPkg,
                    groupPubKey: groupPubKey,
                    seal: (s) => cs.SettleClientMsg(sessionId: '', seq: Int64(seq++), seal: s),
                    sighashesOf: _sighashesOf,
                    signed: (rounds) => cs.SettleClientMsg(
                        sessionId: '', seq: Int64(seq++), signed: cs.SettleSigned(rounds: rounds)),
                    sealedOf: (r) => r.hasSealed() ? r.sealed : null,
                  );
            report(SettlePhase.done);
            return SettleResult(
              commitmentTxid: c.commitmentTxid,
              vtxoTxid: c.vtxoTxid,
              vtxoVout: c.vtxoVout,
              amountSats: c.amountSats.toInt(),
              exitDelay: c.exitDelay,
              delegate: delegate,
            );

          case cs.SettleServerMsg_Body.sealed:
            throw CosignerException('the cosigner sealed a delegate nobody asked for yet');

          case cs.SettleServerMsg_Body.notSet:
            throw CosignerException('the cosigner sent an empty settle message');
        }
      }
    } finally {
      await events?.cancel(immediate: true);
      await duplex.close();
    }
  }

  Future<void> _submit(cs.AspSubmit submit, void Function(SettlePhase) report) async {
    switch (submit.whichCall()) {
      case cs.AspSubmit_Call.confirmRegistration:
        await _asp.confirmRegistration(submit.confirmRegistration.intentId);
      case cs.AspSubmit_Call.treeNonces:
        report(SettlePhase.signingTree);
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
        report(SettlePhase.finalizing);
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
  Future<cs.SettleClientMsg> _relayNext(
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
    return cs.SettleClientMsg(
      sessionId: '',
      seq: Int64(seq),
      event: cs.AspEvent(encoded: Uint8List.fromList(resp.writeToBuffer())),
    );
  }
}
