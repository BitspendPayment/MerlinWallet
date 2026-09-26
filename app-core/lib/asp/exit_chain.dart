/// The whole path a unilateral exit has to take, from the chain to the money.
///
/// Ark keeps transactions off-chain. A VTXO is an output of a transaction nobody published, whose
/// input is an output of another unpublished transaction, and so on back to a **commitment
/// transaction** that *is* on-chain — the one the ASP made when it ran the batch. Spending a VTXO
/// alone therefore means publishing that whole line of descent first, in order, and only then the
/// pre-signed exit that pays the owner's own address.
///
/// The indexer will say what those transactions are (`GetVtxoChain`) and hand them over
/// (`GetVirtualTxs`). What it will not do is put them in order: each entry names what it spends, so
/// the order is a walk from the VTXO back to the commitment, reversed.
///
/// ```text
///   commitment  (already on-chain, the ASP's)
///     └─ tree…        one per level of the batch's tree
///         └─ checkpoint   only for money that moved off-chain since
///             └─ ark          the transaction that paid us
///                 └─ exit         ours, pre-signed, after the timelock
/// ```
///
/// Every hop except the last is signed by somebody else and can be fetched again at any time. The
/// last one cannot: it needs the cosigner's half, which is why it is collected in advance.
library;

/// What a transaction in the path is.
enum ChainKind {
  /// The batch transaction, already confirmed on-chain. The path stops here.
  commitment,

  /// A node of the batch's VTXO tree. Pre-signed by the round's participants.
  tree,

  /// Sits between two off-chain transactions, holding a payment until the ASP countersigned it.
  checkpoint,

  /// An off-chain payment: what a send produces.
  ark,

  /// The owner's own pre-signed spend, at the end of the path. Not something the indexer knows
  /// about — it exists only on this phone until the day it is published.
  exit,

  /// The indexer said something this wallet does not model. Shown rather than dropped.
  unknown,
}

/// One transaction in the path, as the indexer describes it.
class ChainLink {
  const ChainLink({
    required this.txid,
    required this.kind,
    required this.spends,
    this.expiresAt = 0,
  });

  final String txid;
  final ChainKind kind;

  /// The txids of the transactions whose outputs this one spends. How the path is reconstructed.
  final List<String> spends;

  final int expiresAt;
}

/// One hop of the path, in the order it must be published.
class ExitHop {
  const ExitHop({
    required this.txid,
    required this.kind,
    required this.depth,
    this.rawTx,
  });

  final String txid;
  final ChainKind kind;

  /// 0 is the commitment; the exit has the highest depth. Also the order to broadcast in.
  final int depth;

  /// The transaction itself, hex, once fetched. Null while only its shape is known — and always
  /// null for the commitment, which is on-chain already and needs no publishing.
  final String? rawTx;

  ExitHop withRawTx(String? raw) =>
      ExitHop(txid: txid, kind: kind, depth: depth, rawTx: raw);
}

/// The ordered path for one VTXO: commitment first, the pre-signed exit last.
class ExitChain {
  const ExitChain({required this.outpoint, required this.hops, this.missing = const []});

  /// `txid:vout` of the VTXO being exited.
  final String outpoint;

  /// In publishing order. The first is normally the commitment, which is already on-chain.
  final List<ExitHop> hops;

  /// Transactions the path needs that the indexer did not describe — a chain with a hole in it,
  /// which is worth showing rather than pretending the path is complete.
  final List<String> missing;

  /// What has to be published before the exit can be: everything but the commitment, which is
  /// confirmed already.
  Iterable<ExitHop> get toPublish => hops.where((h) => h.kind != ChainKind.commitment);

  bool get isComplete => missing.isEmpty && hops.isNotEmpty;

  /// Order the indexer's links into a path from the commitment down to [vtxoTxid].
  ///
  /// The walk is by `spends`, from the VTXO backwards, because that is the only direction the
  /// indexer describes. A link naming several parents (a transaction spending more than one VTXO)
  /// contributes all of them — the whole ancestry has to be on-chain, not one branch of it.
  factory ExitChain.fromLinks({
    required String outpoint,
    required String vtxoTxid,
    required List<ChainLink> links,
    Map<String, String> rawTxs = const {},
    ExitHop? exit,
  }) {
    final byTxid = {for (final l in links) l.txid: l};
    final depths = <String, int>{};
    final missing = <String>[];

    // Depth-first from the VTXO's own transaction back to the commitments. Depth counts *up* from
    // whichever ancestor is deepest, so a transaction is always published after everything it
    // spends, however many paths lead to it.
    int walk(String txid, Set<String> seen) {
      final known = depths[txid];
      if (known != null) return known;
      final link = byTxid[txid];
      if (link == null) {
        if (!missing.contains(txid)) missing.add(txid);
        return 0;
      }
      if (!seen.add(txid)) return 0; // A cycle is not a chain; stop rather than spin.
      final parents = link.kind == ChainKind.commitment ? const <String>[] : link.spends;
      var depth = 0;
      for (final parent in parents) {
        depth = depth > walk(parent, seen) + 1 ? depth : walk(parent, seen) + 1;
      }
      seen.remove(txid);
      return depths[txid] = depth;
    }

    if (byTxid.containsKey(vtxoTxid)) {
      walk(vtxoTxid, <String>{});
    } else if (links.isEmpty) {
      missing.add(vtxoTxid);
    } else {
      // The indexer answered about something else entirely; say so rather than guess.
      missing.add(vtxoTxid);
    }

    final hops = <ExitHop>[
      for (final entry in depths.entries)
        ExitHop(
          txid: entry.key,
          kind: byTxid[entry.key]!.kind,
          depth: entry.value,
          rawTx: rawTxs[entry.key],
        ),
    ]..sort((a, b) => a.depth != b.depth ? a.depth.compareTo(b.depth) : a.txid.compareTo(b.txid));

    if (exit != null) {
      hops.add(ExitHop(
        txid: exit.txid,
        kind: exit.kind,
        depth: (hops.isEmpty ? 0 : hops.last.depth) + 1,
        rawTx: exit.rawTx,
      ));
    }
    return ExitChain(outpoint: outpoint, hops: hops, missing: missing);
  }
}
