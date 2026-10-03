/// The ASP's published parameters, as the cosigner needs them.
///
/// The wallet used to get these from the cosigner over `GetArkInfo`, which relayed its own
/// `GetInfo` call. The cosigner has no ASP connection any more — the caller drives the Ark protocol
/// — so the wallet asks the ASP itself and passes what it learned into `SendOpen`/`RenewOpen`.
///
/// A value type rather than the generated `GetInfoResponse`: this is the subset the protocol
/// actually uses, and naming it separately keeps the twenty-field wire message out of every
/// signature that only wants a pubkey and two delays.
library;

import 'package:protocol/ark_v1.dart' as ark;

class ArkInfo {
  const ArkInfo({
    required this.signerPubkey,
    required this.forfeitPubkey,
    required this.forfeitAddress,
    required this.checkpointTapscript,
    required this.network,
    required this.sessionDuration,
    required this.unilateralExitDelay,
    required this.boardingExitDelay,
    required this.vtxoMinAmount,
    required this.dust,
  });

  /// The ASP's signer x-only public key (hex). Every VTXO script this wallet can spend is derived
  /// from it and the wallet's own key, so it is what makes an address ours rather than someone
  /// else's — and why the cosigner re-derives rather than trusting an address it is handed.
  final String signerPubkey;
  final String forfeitPubkey;
  final String forfeitAddress;
  final String checkpointTapscript;

  /// "bitcoin", "testnet", "signet", "regtest". The ASP's answer, not the cosigner's: address
  /// derivation has to match what the ASP validates against.
  final String network;

  final int sessionDuration;

  /// Blocks before a received or refreshed VTXO can be exited unilaterally.
  final int unilateralExitDelay;

  /// Blocks for a boarded one, which keeps its own delay. A wallet holds a mix of the two, which is
  /// why anything scanning for owned scripts has to ask for both.
  final int boardingExitDelay;

  final int vtxoMinAmount;
  final int dust;

  factory ArkInfo.fromResponse(ark.GetInfoResponse r) => ArkInfo(
        signerPubkey: r.signerPubkey,
        forfeitPubkey: r.forfeitPubkey,
        forfeitAddress: r.forfeitAddress,
        checkpointTapscript: r.checkpointTapscript,
        network: r.network,
        sessionDuration: r.sessionDuration.toInt(),
        unilateralExitDelay: r.unilateralExitDelay.toInt(),
        boardingExitDelay: r.boardingExitDelay.toInt(),
        vtxoMinAmount: r.vtxoMinAmount.toInt(),
        dust: r.dust.toInt(),
      );

  @override
  String toString() =>
      'ArkInfo($network, signer=${signerPubkey.length > 8 ? '${signerPubkey.substring(0, 8)}…' : signerPubkey}, '
      'exit=$unilateralExitDelay/$boardingExitDelay)';
}

/// One VTXO as the indexer reports it.
class IndexerVtxo {
  const IndexerVtxo({
    required this.txid,
    required this.vout,
    required this.amountSats,
    required this.script,
    required this.isSpent,
    required this.createdAt,
    required this.expiresAt,
    this.exitDelay = 0,
    this.isPreconfirmed = false,
    this.spentBy = '',
    this.settledBy = '',
    this.arkTxid = '',
    this.commitmentTxids = const [],
  });

  final String txid;
  final int vout;
  final int amountSats;
  final String script;
  final bool isSpent;
  final int createdAt;

  /// When this VTXO stops being spendable off-chain. What a delegate's renewal deadline is computed
  /// from, and the reason the wallet polls at all.
  final int expiresAt;

  /// Which of the wallet's two exit delays this VTXO sits under. 0 until resolved — see
  /// [withExitDelay].
  final int exitDelay;

  /// Made by an off-chain Ark transaction not yet in a batch. Spendable all the same.
  final bool isPreconfirmed;

  /// What spent it, when spent: the checkpoint txid ([spentBy]) and the Ark txid ([arkTxid]) of an
  /// off-chain spend, or the commitment txid ([settledBy]) of a batch that refreshed it.
  final String spentBy;
  final String settledBy;
  final String arkTxid;

  /// The batches it descends from, newest last as the indexer reports them.
  final List<String> commitmentTxids;

  String get outpoint => '$txid:$vout';

  /// The indexer does not report an exit delay — it is implied by which of the wallet's two scripts
  /// the VTXO sits under, and only the wallet knows that mapping. [AspClient.getOwnedVtxos] fills
  /// it in; a VTXO that reached the cosigner without it would be refused, because a delay outside
  /// the ASP's pair names a script the wallet cannot spend from.
  IndexerVtxo withExitDelay(int delay) => IndexerVtxo(
        txid: txid,
        vout: vout,
        amountSats: amountSats,
        script: script,
        isSpent: isSpent,
        createdAt: createdAt,
        expiresAt: expiresAt,
        exitDelay: delay,
        isPreconfirmed: isPreconfirmed,
        spentBy: spentBy,
        settledBy: settledBy,
        arkTxid: arkTxid,
        commitmentTxids: commitmentTxids,
      );
}
