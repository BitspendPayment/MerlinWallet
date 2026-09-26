/// Ordering the indexer's answer into a path that can actually be published.
///
/// The indexer says what each transaction spends, and nothing about order. Getting that wrong
/// would mean handing somebody a set of transactions that a node rejects for spending outputs that
/// do not exist yet — so the ordering is worth testing on its own, away from any network.
library;

import 'package:app_core/asp/exit_chain.dart';
import 'package:test/test.dart';

ChainLink link(String txid, ChainKind kind, List<String> spends) =>
    ChainLink(txid: txid, kind: kind, spends: spends);

ExitChain chainOf(List<ChainLink> links, {String vtxo = 'ark', ExitHop? exit, Map<String, String> raw = const {}}) =>
    ExitChain.fromLinks(
      outpoint: '$vtxo:0',
      vtxoTxid: vtxo,
      links: links,
      rawTxs: raw,
      exit: exit,
    );

final ourExit = ExitHop(txid: 'exit', kind: ChainKind.exit, depth: 0, rawTx: 'ff');

void main() {
  /// A settled VTXO: it sits in a batch tree, under a commitment that is already on-chain.
  test('a boarded VTXO is commitment, then tree, then the exit', () {
    final chain = chainOf(
      [
        link('leaf', ChainKind.tree, ['branch']),
        link('branch', ChainKind.tree, ['commitment']),
        link('commitment', ChainKind.commitment, []),
      ],
      vtxo: 'leaf',
      exit: ourExit,
    );

    expect(chain.hops.map((h) => h.txid), ['commitment', 'branch', 'leaf', 'exit']);
    expect(chain.hops.map((h) => h.kind).last, ChainKind.exit);
    expect(chain.isComplete, isTrue);
    // The commitment is already on-chain; everything after it has to be published.
    expect(chain.toPublish.map((h) => h.txid), ['branch', 'leaf', 'exit']);
  });

  /// Money received since the last batch: the ark transaction that paid us, and the checkpoint
  /// that held it, both have to go on-chain before the VTXO they made exists.
  test('a preconfirmed VTXO adds its checkpoint and ark transaction', () {
    final chain = chainOf(
      [
        link('ark', ChainKind.ark, ['checkpoint']),
        link('checkpoint', ChainKind.checkpoint, ['leaf']),
        link('leaf', ChainKind.tree, ['commitment']),
        link('commitment', ChainKind.commitment, []),
      ],
      exit: ourExit,
    );

    expect(chain.hops.map((h) => h.txid), ['commitment', 'leaf', 'checkpoint', 'ark', 'exit']);
    expect(chain.hops.map((h) => h.kind),
        [ChainKind.commitment, ChainKind.tree, ChainKind.checkpoint, ChainKind.ark, ChainKind.exit]);
  });

  /// A transaction spending two VTXOs has two ancestries, and both have to be on-chain before it.
  /// Ordering by the deepest parent is what guarantees that.
  test('a transaction with two parents comes after both of them', () {
    final chain = chainOf(
      [
        link('ark', ChainKind.ark, ['checkpointA', 'checkpointB']),
        link('checkpointA', ChainKind.checkpoint, ['leafA']),
        link('leafA', ChainKind.tree, ['commitmentA']),
        link('commitmentA', ChainKind.commitment, []),
        link('checkpointB', ChainKind.checkpoint, ['commitmentB']),
        link('commitmentB', ChainKind.commitment, []),
      ],
    );

    final order = chain.hops.map((h) => h.txid).toList();
    for (final parent in ['checkpointA', 'checkpointB', 'leafA', 'commitmentA', 'commitmentB']) {
      expect(order.indexOf(parent), lessThan(order.indexOf('ark')),
          reason: '$parent must be published before the transaction that spends it');
    }
    expect(order.indexOf('commitmentA'), lessThan(order.indexOf('leafA')));
  });

  /// A hole in what the indexer returned is shown, not smoothed over: a path with a missing
  /// transaction cannot be published, and saying otherwise would be the worst kind of wrong.
  test('a gap in the chain is reported', () {
    final chain = chainOf(
      [
        link('leaf', ChainKind.tree, ['branch']),
        // 'branch' itself is absent.
      ],
      vtxo: 'leaf',
    );
    expect(chain.missing, ['branch']);
    expect(chain.isComplete, isFalse);
  });

  test('an empty answer is a missing chain, not an empty one', () {
    final chain = chainOf([], vtxo: 'leaf');
    expect(chain.missing, ['leaf']);
    expect(chain.isComplete, isFalse);
    expect(chain.hops, isEmpty);
  });

  /// The transactions themselves ride along when the indexer gave them; the commitment needs none,
  /// because it is confirmed already.
  test('raw transactions are attached to the hops that need them', () {
    final chain = chainOf(
      [
        link('leaf', ChainKind.tree, ['commitment']),
        link('commitment', ChainKind.commitment, []),
      ],
      vtxo: 'leaf',
      raw: {'leaf': 'aabb'},
      exit: ourExit,
    );
    expect(chain.hops.firstWhere((h) => h.txid == 'leaf').rawTx, 'aabb');
    expect(chain.hops.firstWhere((h) => h.txid == 'commitment').rawTx, isNull);
    expect(chain.hops.last.rawTx, 'ff');
  });

  /// A malformed answer must not hang the app.
  test('a cycle does not spin forever', () {
    final chain = chainOf(
      [
        link('a', ChainKind.ark, ['b']),
        link('b', ChainKind.ark, ['a']),
      ],
      vtxo: 'a',
    );
    expect(chain.hops, isNotEmpty);
  });
}
