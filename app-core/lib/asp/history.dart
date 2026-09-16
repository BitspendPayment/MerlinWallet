/// The wallet's Ark transaction history, rebuilt from the indexer.
///
/// The cosigner used to keep this log, and could only ever have logged what it did itself — never a
/// receive. The indexer knows every VTXO the wallet's scripts ever held, spent or not, and each one
/// says which transaction made it and which one spent it. Group them by transaction, net what each
/// one gave the wallet against what it took, and that is the history — receives included, and with
/// no call to the cosigner, so no passkey prompt.
library;

import 'ark_info.dart';

enum ArkTransactionKind {
  /// Funds arrived off-chain from someone else.
  received,

  /// Funds left: what the transaction spent of ours, less the change it gave back.
  sent,

  /// An on-chain deposit settled into Ark.
  boarded,

  /// VTXOs refreshed in a batch round — the wallet's own funds, renewed before expiry, by the owner or
  /// by the cosigner running a sealed delegate.
  renewed,
}

class ArkTransaction {
  ArkTransaction({
    required this.txid,
    required this.kind,
    required this.amountSats,
    required this.timestamp,
    required this.settled,
  });

  /// The Ark txid of an off-chain transaction, or the commitment txid of a batch.
  final String txid;
  final ArkTransactionKind kind;

  /// Always positive; [kind] says which way it went. For [ArkTransactionKind.renewed], the amount
  /// refreshed.
  final int amountSats;

  /// When the indexer recorded what the transaction made. For a send that returned no change, when
  /// the newest input it spent was made — the indexer does not record when a VTXO was spent.
  final DateTime timestamp;

  /// Whether it is in a batch. An off-chain transaction is preconfirmed until one includes it; its
  /// VTXOs are spendable meanwhile.
  final bool settled;
}

/// Rebuild the history from every VTXO the wallet's scripts ever held — spent ones included — newest
/// first.
List<ArkTransaction> arkHistoryOf(List<IndexerVtxo> vtxos) {
  final made = <String, List<IndexerVtxo>>{};
  final spent = <String, List<IndexerVtxo>>{};

  for (final v in vtxos) {
    made.putIfAbsent(_madeBy(v), () => []).add(v);
    final by = _spentBy(v);
    if (by != null) spent.putIfAbsent(by, () => []).add(v);
  }

  final history = <(ArkTransaction, bool)>[];
  for (final txid in {...made.keys, ...spent.keys}) {
    final outs = made[txid] ?? const <IndexerVtxo>[];
    final ins = spent[txid] ?? const <IndexerVtxo>[];
    final gained = outs.fold<int>(0, (s, v) => s + v.amountSats);
    final lost = ins.fold<int>(0, (s, v) => s + v.amountSats);
    final batch = outs.isNotEmpty
        ? !outs.first.isPreconfirmed
        : ins.any((v) => v.settledBy == txid);

    final ArkTransactionKind kind;
    final int amount;
    if (ins.isEmpty) {
      kind = batch ? ArkTransactionKind.boarded : ArkTransactionKind.received;
      amount = gained;
    } else if (batch && outs.isNotEmpty) {
      // Spent ours into a batch and got a VTXO back: a refresh. A batch fee makes it slightly less.
      kind = ArkTransactionKind.renewed;
      amount = gained;
    } else if (gained > lost) {
      kind = ArkTransactionKind.received;
      amount = gained - lost;
    } else {
      kind = ArkTransactionKind.sent;
      amount = lost - gained;
    }
    if (amount == 0 && kind != ArkTransactionKind.renewed) continue;

    final times = (outs.isNotEmpty ? outs : ins).map((v) => v.createdAt);
    history.add((
      ArkTransaction(
        txid: txid,
        kind: kind,
        amountSats: amount,
        timestamp: DateTime.fromMillisecondsSinceEpoch(
            times.reduce((a, b) => a > b ? a : b) * 1000),
        settled: outs.isEmpty || !outs.any((v) => v.isPreconfirmed),
      ),
      ins.isNotEmpty
    ));
  }
  // A spend with no change is dated by its inputs, so it can tie with what made them; the spend
  // came second.
  history.sort((a, b) {
    final byTime = b.$1.timestamp.compareTo(a.$1.timestamp);
    if (byTime != 0) return byTime;
    return (b.$2 ? 1 : 0) - (a.$2 ? 1 : 0);
  });
  return [for (final (tx, _) in history) tx];
}

/// The transaction that made [v]: its own txid when off-chain, its batch's commitment otherwise.
String _madeBy(IndexerVtxo v) => v.isPreconfirmed || v.commitmentTxids.isEmpty
    ? v.txid
    : v.commitmentTxids.last;

/// The transaction that spent [v], or null while it is unspent.
String? _spentBy(IndexerVtxo v) {
  if (v.arkTxid.isNotEmpty) return v.arkTxid;
  if (v.settledBy.isNotEmpty) return v.settledBy;
  if (v.spentBy.isNotEmpty) return v.spentBy;
  return null;
}
