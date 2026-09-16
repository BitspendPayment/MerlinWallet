import 'package:app_core/asp/ark_info.dart';
import 'package:app_core/asp/history.dart';
import 'package:test/test.dart';

// Shapes taken from arkd's indexer on the dev stack: a boarded VTXO, then a send spending it that
// paid 10 000 away and returned 120 000 in change.
const _commitment = '7d75ba00';
const _send = 'e695c200';

IndexerVtxo _vtxo(
  String txid,
  int vout,
  int amount, {
  int createdAt = 1000,
  bool preconfirmed = false,
  String arkTxid = '',
  String settledBy = '',
  List<String> commitments = const [_commitment],
}) =>
    IndexerVtxo(
      txid: txid,
      vout: vout,
      amountSats: amount,
      script: '5120ab',
      isSpent: arkTxid.isNotEmpty || settledBy.isNotEmpty,
      createdAt: createdAt,
      expiresAt: createdAt + 10000,
      isPreconfirmed: preconfirmed,
      spentBy: arkTxid.isNotEmpty ? 'checkpoint' : '',
      arkTxid: arkTxid,
      settledBy: settledBy,
      commitmentTxids: commitments,
    );

void main() {
  test('a boarding, then a send with change', () {
    final history = arkHistoryOf([
      _vtxo('34fcce00', 0, 130000, arkTxid: _send),
      _vtxo(_send, 1, 120000, createdAt: 2000, preconfirmed: true),
    ]);

    expect(history.map((t) => (t.kind, t.txid, t.amountSats)), [
      (ArkTransactionKind.sent, _send, 10000),
      (ArkTransactionKind.boarded, _commitment, 130000),
    ]);
    expect(history.first.settled, isFalse);
    expect(history.last.settled, isTrue);
  });

  test("the recipient's side of the same send is a receive", () {
    final history = arkHistoryOf(
        [_vtxo(_send, 0, 10000, createdAt: 2000, preconfirmed: true)]);

    expect(history.single.kind, ArkTransactionKind.received);
    expect(history.single.txid, _send);
    expect(history.single.amountSats, 10000);
    expect(history.single.timestamp,
        DateTime.fromMillisecondsSinceEpoch(2000 * 1000));
  });

  test('a received VTXO later spent keeps its receive', () {
    final history = arkHistoryOf([
      _vtxo(_send, 0, 10000,
          createdAt: 2000, preconfirmed: true, arkTxid: 'next'),
    ]);

    expect(history.map((t) => (t.kind, t.txid, t.amountSats)), [
      (ArkTransactionKind.sent, 'next', 10000),
      (ArkTransactionKind.received, _send, 10000),
    ]);
  });

  test('a batch that refreshes the wallet is a renewal, not a receive', () {
    final history = arkHistoryOf([
      _vtxo(_send, 1, 120000,
          createdAt: 2000, preconfirmed: true, settledBy: 'batch2'),
      _vtxo('leaf', 0, 119800, createdAt: 3000, commitments: ['batch2']),
    ]);

    expect(history.map((t) => (t.kind, t.txid, t.amountSats)).first,
        (ArkTransactionKind.renewed, 'batch2', 119800));
  });

  test('spending everything with no change still dates the send', () {
    final history = arkHistoryOf(
        [_vtxo('34fcce00', 0, 5000, createdAt: 1500, arkTxid: _send)]);

    expect(history.first.kind, ArkTransactionKind.sent);
    expect(history.first.amountSats, 5000);
    expect(history.first.timestamp,
        DateTime.fromMillisecondsSinceEpoch(1500 * 1000));
  });
}
