/// Watching the chain for deposits, which is all this wallet does on-chain.
///
/// Boarding is Ark's on-ramp: money is sent to an address derived from the wallet's own key and the
/// ASP's, and a settle turns that output into a VTXO. The wallet needs to see the deposit to board
/// it, and that is the whole of its relationship with the chain — it holds no on-chain coins, spends
/// none, and keeps no UTXO set. Everything else it owns lives in Ark.
///
/// This replaced `MpcBitcoinWallet`, which was a second wallet living alongside the Ark one: its own
/// single key, its own balance, its own send and receive screens, its own Electrum sync. None of
/// that was Ark, and keeping it meant every screen had to ask which of the two wallets it meant.
library;

import 'package:bitcoin_base/bitcoin_base.dart';
import 'package:blockchain_utils/blockchain_utils.dart' show SegwitBech32Decoder;
import 'package:convert/convert.dart';
import 'package:fixnum/fixnum.dart';
import 'package:protocol/cosigner_v1.dart';

import 'electrum.dart';

/// Reads Electrum for deposits to a boarding address. Nothing here signs anything.
class BoardingScanner {
  BoardingScanner({required this.networkName, ElectrumClient? electrum})
      : electrum = electrum ??
            ElectrumClient(
              defaultElectrumEndpoint(networkName).host,
              defaultElectrumEndpoint(networkName).port,
            );

  final String networkName;
  final ElectrumClient electrum;

  BitcoinNetwork get network => parseBitcoinNetwork(networkName);

  /// **Confirmed deposits only.** The ASP validates every boarding input and rejects the whole
  /// intent if one is still in the mempool: `INVALID_PSBT_INPUT (5): failed to validate boarding
  /// input: tx <id> not confirmed`. Because one unconfirmed deposit fails the entire settle, an
  /// unfiltered scan makes boarding impossible until every deposit confirms. Use [scanPending] to
  /// show what is still waiting.
  Future<List<BoardingUtxo>> scan(String boardingAddress) =>
      _scan(boardingAddress, confirmed: true);

  /// Deposits seen on-chain but not yet confirmed, so the UI can say "waiting for a confirmation"
  /// instead of showing nothing at all.
  Future<List<BoardingUtxo>> scanPending(String boardingAddress) =>
      _scan(boardingAddress, confirmed: false);

  Future<List<BoardingUtxo>> _scan(String boardingAddress, {required bool confirmed}) async {
    final utxos = await electrum.listUnspent(_parseP2tr(boardingAddress));
    // Electrum reports height 0 for a mempool output; anything greater is mined.
    return utxos
        .where((u) => confirmed ? u.height > 0 : u.height <= 0)
        .map((u) => BoardingUtxo()
          ..txid = u.txHash
          ..vout = u.vout
          ..amountSats = Int64(u.value.toInt()))
        .toList();
  }

  void close() => electrum.close();

  BitcoinBaseAddress _parseP2tr(String address) {
    if (address.startsWith('bcrt')) {
      final decoded = SegwitBech32Decoder.decode('bcrt', address);
      return P2trAddress.fromProgram(program: hex.encode(decoded.item2));
    }
    return P2trAddress.fromAddress(address: address, network: network);
  }
}

/// The networks an ASP can report, as `bitcoin_base` names them. A mutinynet deployment says
/// "mutinynet" and means signet; regtest has no constant of its own and shares testnet's `tb` HRP,
/// with `bcrt` addresses decoded explicitly above.
BitcoinNetwork parseBitcoinNetwork(String network) {
  if (network.isEmpty) {
    throw ArgumentError(
        'parseBitcoinNetwork: empty network string — the ASP returned no network, and an address '
        'cannot be safely rendered against a guess');
  }
  switch (network) {
    case 'bitcoin':
    case 'mainnet':
      return BitcoinNetwork.mainnet;
    case 'testnet':
    case 'testnet3':
      return BitcoinNetwork.testnet;
    case 'signet':
    case 'mutinynet':
      return BitcoinNetwork.signet;
    case 'regtest':
      return BitcoinNetwork.testnet;
    default:
      throw ArgumentError(
          'parseBitcoinNetwork: unknown network "$network" — expected one of mainnet, testnet, '
          'signet, mutinynet, regtest');
  }
}

bool isRegtestNetwork(String network) => network == 'regtest';

/// Where to watch from, per network. Regtest is whatever the dev stack runs; mutinynet and signet
/// share a public server.
({String host, int port}) defaultElectrumEndpoint(String networkName) {
  switch (networkName.toLowerCase()) {
    case 'regtest':
      return (host: '127.0.0.1', port: 50001);
    case 'signet':
    case 'mutinynet':
      return (host: 'electrum.mutinynet.com', port: 50001);
    default:
      throw ArgumentError(
        'no Electrum server configured for "$networkName" — boarding needs one to see deposits',
      );
  }
}
