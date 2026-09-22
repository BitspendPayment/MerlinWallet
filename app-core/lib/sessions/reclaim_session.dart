/// Taking back what is left of an escrow, once its deal is over.
///
/// The other pairing over the same key. An escrow key is signed by `{wallet, cosigner}` and by
/// `{service, cosigner}`, and this is the first of them — so it needs the owner here, with their
/// passkey, and it needs the cosigner to agree that the deal is over.
///
/// ```text
///   open  ── escrow, the VTXOs it holds, what the ASP is
///   ◀── sighashes + the cosigner's commitments + the two halves of this wallet's escrow share
///   signed ── this wallet's commitments and shares
///   ◀── the transactions to submit
///   submitted ── what the ASP said
///   ◀── what to finalize
///   finalized ──
///   ◀── the txid
/// ```
///
/// The same four steps a send takes, because it is one — of the escrow's key rather than this
/// wallet's. What differs is the share: it is rebuilt here from three terms, two of which arrive on
/// this stream and one of which comes from the passkey and never leaves the device.
///
/// **Where the money goes is not sent.** The cosigner derives this wallet's own Ark address from
/// the key it already holds. It is reported back so the owner can see it, and there is no field to
/// put a different one in.
library;

import 'package:protocol/cosigner_v1.dart' as cs;

import '../asp/asp_client.dart';
import '../cosigner/connection.dart';
import '../threshold_types.dart' as threshold;
import 'in_band_round.dart';
import 'send_session.dart' show arkInfoToProto, vtxosToProto;

/// What a reclaim did, and where it went.
class ReclaimResult {
  const ReclaimResult({
    required this.arkTxid,
    required this.toArkAddress,
    required this.amountSats,
  });

  /// The Ark transaction that moved it.
  final String arkTxid;

  /// Where it went — this wallet's own address, as the cosigner derived it.
  final String toArkAddress;

  /// What came back, in sats.
  final int amountSats;
}

/// Rebuild this wallet's share of the ESCROW key from the two halves the cosigner holds.
typedef ResolveEscrowShare = threshold.KeyPackage Function(
  List<int> dealtShare,
  List<int> deltaShare,
);

class ReclaimSession {
  ReclaimSession(this._conn, this._asp);
  final CosignerConnection _conn;
  final AspClient _asp;

  /// Take back everything [vtxos] holds.
  ///
  /// [vtxos] is what the escrow's address holds, from the indexer. The cosigner does not index an
  /// escrow's funds, so it is named here — which is safe because a taproot sighash commits to every
  /// prevout: an input claimed wrongly makes a signature that verifies against nothing.
  Future<ReclaimResult> run({
    required String escrowKeyHex,
    required List<IndexerVtxo> vtxos,
    required ArkInfo info,
    required ResolveEscrowShare resolveEscrow,
    required threshold.PublicKeyPackage escrowPubKey,
  }) async {
    final duplex = _conn.openEscrowReclaim();
    try {
      duplex.send(cs.EscrowReclaimClientMsg(
        sessionId: '',
        seq: 0,
        open: cs.EscrowReclaimOpen(
          escrowKey: escrowKeyHex,
          vtxos: vtxosToProto(vtxos),
          arkInfo: arkInfoToProto(info),
        ),
      ));

      // --- What it built, and the halves this wallet's share is rebuilt from -----------------
      final first = await duplex.next('the sighashes');
      if (!first.hasSighashes()) {
        throw CosignerException('expected the sighashes, got ${first.whichBody()}');
      }
      final h = first.sighashes;
      // Three terms: what the cosigner dealt at DKG, its delta for this escrow, and the passkey's
      // own. The sum is checked against the verifying share the escrow published before it is used.
      final keyPkg = resolveEscrow(h.walletDealtShare, h.escrowDeltaShare);

      duplex.send(cs.EscrowReclaimClientMsg(
        sessionId: '',
        seq: 1,
        signed: cs.EscrowReclaimSigned(
          rounds: answerRound(
            sighashes: h.messagesToSign,
            cosignerCommitments: h.cosignerCommitments,
            cosignerIdentifier: h.cosignerIdentifier,
            scriptPathSpend: true,
            keyPkg: keyPkg,
            groupPubKey: escrowPubKey,
          ),
        ),
      ));

      // --- Submit it to the ASP ---------------------------------------------------------------
      final submit = await duplex.next('what to submit');
      if (!submit.hasSubmit()) {
        throw CosignerException('expected what to submit, got ${submit.whichBody()}');
      }
      final submitted = await _asp.submitTx(
        submit.submit.arkTxB64,
        submit.submit.checkpointTxs,
      );
      duplex.send(cs.EscrowReclaimClientMsg(
        sessionId: '',
        seq: 2,
        submitted: cs.SendSubmitted(
          arkTxid: submitted.arkTxid,
          signedCheckpointTxs: submitted.signedCheckpointTxs,
        ),
      ));

      // --- Finalize it --------------------------------------------------------------------------
      final finalize = await duplex.next('what to finalize');
      if (!finalize.hasFinalize()) {
        throw CosignerException('expected what to finalize, got ${finalize.whichBody()}');
      }
      await _asp.finalizeTx(
        finalize.finalize.arkTxid,
        finalize.finalize.finalCheckpointTxs,
      );
      duplex.send(cs.EscrowReclaimClientMsg(
        sessionId: '',
        seq: 3,
        finalized: cs.SendFinalized(),
      ));

      // --- And only now is the deal over --------------------------------------------------------
      final complete = await duplex.next('the outcome');
      if (!complete.hasComplete()) {
        throw CosignerException('expected the outcome, got ${complete.whichBody()}');
      }
      return ReclaimResult(
        arkTxid: complete.complete.arkTxid,
        toArkAddress: h.toArkAddress,
        amountSats: h.amountSats.toInt(),
      );
    } finally {
      await duplex.close();
    }
  }
}
