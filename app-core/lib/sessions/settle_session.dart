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
import 'send_session.dart';

/// What a settle produced.
class SettleResult {
  SettleResult({
    required this.commitmentTxid,
    required this.vtxoTxid,
    required this.vtxoVout,
    required this.amountSats,
    required this.exitDelay,
  });
  final String commitmentTxid;
  final String vtxoTxid;
  final int vtxoVout;
  final int amountSats;
  final int exitDelay;
}

/// Progress, for a UI that has to show something while a batch round runs. Settling waits on the
/// ASP's own schedule, which is minutes, not milliseconds.
enum SettlePhase { registering, waitingForBatch, signingTree, finalizing, done }

class SettleSession {
  SettleSession(this._conn, this._asp);
  final CosignerConnection _conn;
  final AspClient _asp;

  /// Settle. Returns when the batch finalizes.
  Future<SettleResult> settle({
    required ArkInfo info,
    required threshold.KeyPackage keyPkg,
    required threshold.PublicKeyPackage groupPubKey,
    required List<int> userId,
    required List<int> signature,
    required int timestampMs,
    cs.BoardingUtxo? boardingUtxo,
    List<IndexerVtxo> vtxos = const [],
    void Function(SettlePhase)? onProgress,
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
          userId: userId,
          signature: signature,
          timestampMs: Int64(timestampMs),
          boardingUtxo: boardingUtxo,
          arkInfo: arkInfoToProto(info),
          vtxos: vtxosToProto(vtxos),
        ),
      ));

      while (true) {
        final msg = await duplex.next('the next step');

        switch (msg.whichBody()) {
          // FROST signatures, on the intent proof first and the commitment transaction later.
          case cs.SettleServerMsg_Body.sighashes:
            final signed = await signEach(
              _conn,
              msg.sighashes.messagesToSign,
              keyPkg: keyPkg,
              groupPubKey: groupPubKey,
              userId: userId,
              signature: signature,
              timestampMs: timestampMs,
              scriptPathSpend: msg.sighashes.scriptPathSpend,
            );
            duplex.send(cs.SettleClientMsg(
              sessionId: '',
              seq: Int64(seq++),
              signed: cs.SettleSigned(signedMessages: signed),
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
            report(SettlePhase.done);
            return SettleResult(
              commitmentTxid: msg.complete.commitmentTxid,
              vtxoTxid: msg.complete.vtxoTxid,
              vtxoVout: msg.complete.vtxoVout,
              amountSats: msg.complete.amountSats.toInt(),
              exitDelay: msg.complete.exitDelay,
            );

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
