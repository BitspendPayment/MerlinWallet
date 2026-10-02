import 'package:app_core/client.dart';
import 'package:app_core/electrum.dart';
import 'package:bitcoin_base/bitcoin_base.dart';
import 'package:blockchain_utils/blockchain_utils.dart' hide hex;
import 'package:fixnum/fixnum.dart';
// `BoardingUtxo` lives in the cosigner's own proto now, not the shared message set.
import 'package:protocol/cosigner_v1.dart';

/// Polls the boarding address via the wallet's electrum client (the only
/// component with a chain view) until at least [minSats] is seen, returning the
/// scanned boarding UTXOs to hand to `renew()`. The cosigner no longer scans.
Future<List<BoardingUtxo>> pollBoardingUtxos(String boardingAddress, int minSats,
    {String host = '127.0.0.1', int port = 50001, int attempts = 30}) async {
  final addr = boardingAddress.startsWith('bcrt')
      ? P2trAddress.fromProgram(
          program: BytesUtils.toHexString(
              SegwitBech32Decoder.decode('bcrt', boardingAddress).item2))
      : P2trAddress.fromAddress(
          address: boardingAddress, network: BitcoinNetwork.testnet);
  final electrum = ElectrumClient(host, port);
  try {
    for (int i = 0; i < attempts; i++) {
      try {
        final utxos = await electrum.listUnspent(addr);
        final total = utxos.fold<int>(0, (s, u) => s + u.value.toInt());
        if (total >= minSats) {
          return utxos
              .map((u) => BoardingUtxo()
                ..txid = u.txHash
                ..vout = u.vout
                ..amountSats = Int64(u.value.toInt()))
              .toList();
        }
      } catch (_) {}
      await Future.delayed(const Duration(seconds: 1));
    }
  } finally {
    electrum.close();
  }
  return [];
}

/// Scans the client's own boarding address and returns the deposits to settle.
Future<List<BoardingUtxo>> scanBoardingFor(MpcClient client,
    {int minSats = 1}) async {
  final addr = await client.getBoardingAddress();
  return pollBoardingUtxos(addr, minSats);
}

/// Renew every scanned deposit into Ark, ONE PER CALL, returning the last commitment
/// txid.
///
/// The cosigner builds its boarding intent proof for a single outpoint and
/// rejects a batch of more than one, so a list cannot be handed over wholesale.
/// That matters here because these tests reuse wallet ids: a test that funds and
/// then bails out before settling (ASP unreachable) leaves its deposit behind,
/// and the next test on the same wallet would scan two.
Future<String> renewBoarding(MpcClient client, List<BoardingUtxo> utxos) async {
  if (utxos.isEmpty) throw StateError('no boarding UTXOs to settle');
  String commitment = '';
  for (final u in utxos) {
    commitment = await client.renew(boardingUtxos: [u]);
  }
  return commitment;
}
