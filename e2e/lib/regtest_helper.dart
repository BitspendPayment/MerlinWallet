import 'dart:convert';
import 'package:http/http.dart' as http;

class RegtestHelper {
  final String rpcUrl;
  String _user = 'admin1';
  String _password = '123';

  RegtestHelper({this.rpcUrl = "http://127.0.0.1:18443"});

  String get _authHeader {
    return 'Basic ' + base64Encode(utf8.encode('$_user:$_password'));
  }

  Future<dynamic> _call(String method, [List<dynamic>? params]) async {
    final payload = {
      'jsonrpc': '1.0',
      'id': 'curltest',
      'method': method,
      'params': params ?? []
    };

    final response = await http.post(
      Uri.parse(rpcUrl),
      headers: {
        'content-type': 'text/plain',
        'authorization': _authHeader,
      },
      body: jsonEncode(payload),
    );

    if (response.statusCode != 200) {
      throw Exception('RPC Error: ${response.statusCode} - ${response.body}');
    }

    final body = jsonDecode(response.body);
    if (body['error'] != null) {
      throw Exception('RPC Error Body: ${body['error']}');
    }

    return body['result'];
  }

  /// Generates a new address for the miner/admin wallet.
  Future<String> getNewAddress({String addressType = 'bech32m'}) async {
    return await _call('getnewaddress', ["", addressType]);
  }

  Future<double> getBalance() async {
    return (await _call('getbalance')).toDouble();
  }

  /// Creates a new named wallet (if not exists).
  Future<void> createWallet(String name) async {
    try {
      await _call('createwallet', [name]);
    } catch (e) {
      if (e.toString().contains('Database already exists')) {
        try {
          await _call('loadwallet', [name]);
        } catch (e2) {
          // Ignore if already loaded
          if (!e2.toString().contains('Wallet is already loaded')) {
            rethrow;
          }
        }
      } else {
        rethrow;
      }
    }
  }

  /// Mines [blocks] blocks to [address].
  Future<List<String>> generateToAddress(int blocks, String address) async {
    final result = await _call('generatetoaddress', [blocks, address]);
    return (result as List).cast<String>();
  }

  /// Sends [amount] BTC to [address].
  Future<String> sendToAddress(String address, double amount) async {
    return await _call('sendtoaddress', [address, amount]);
  }

  /// Gets raw transaction hex (and verbose info if needed).
  Future<dynamic> getRawTransaction(String txId) async {
    return await _call('getrawtransaction', [txId, true]);
  }

  /// Gets Mempool entry.
  Future<dynamic> getMempoolEntry(String txId) async {
    return await _call('getmempoolentry', [txId]);
  }

  /// Sends raw transaction hex. Pass [maxFeeRate] (BTC/kvB) to override
  /// bitcoind's absurd-fee guard — use `0` to disable it (e.g. for a deliberately
  /// high-fee regtest spend).
  Future<String> sendRawTransaction(String hex, {double? maxFeeRate}) async {
    final params = <dynamic>[hex];
    if (maxFeeRate != null) params.add(maxFeeRate);
    return await _call('sendrawtransaction', params);
  }

  /// Returns the unspent tx output at [txId]:[vout], or null if spent/unknown.
  Future<Map<String, dynamic>?> getTxOut(String txId, int vout) async {
    final result = await _call('gettxout', [txId, vout]);
    return result == null ? null : (result as Map<String, dynamic>);
  }

  // --- What proving a unilateral exit needs ------------------------------------------------------
  //
  // An exit waits out a relative timelock and then pays no fee, so getting one mined means moving
  // the chain's clock forward and handing bitcoind the transaction directly or with the child that
  // pays for it. All of this is regtest-only by nature.

  /// Move the node's idea of now. A VTXO's exit delay is in seconds, so the median-time-past has to
  /// be pushed past it — mine a few blocks after this for the median to follow.
  Future<void> setMockTime(int unixSeconds) async {
    await _call('setmocktime', [unixSeconds]);
  }

  /// The chain's median time past, which is what a time-based `OP_CHECKSEQUENCEVERIFY` is measured
  /// against — not the latest block's timestamp.
  Future<int> medianTime() async {
    final info = await _call('getblockchaininfo');
    return (info['mediantime'] as num).toInt();
  }

  /// Mine a block containing [rawTransactions], bypassing mempool policy.
  ///
  /// This is how a zero-fee transaction gets confirmed without a fee-paying child: it proves
  /// consensus accepts it — script, timelock, signature and witness — which is a different claim
  /// from a node being willing to relay it. [submitPackage] is the claim about relay.
  Future<String> generateBlock(String address, List<String> rawTransactions) async {
    final result = await _call('generateblock', [address, rawTransactions]);
    return result['hash'] as String;
  }

  /// Submit a parent and the child that pays its fee, as one package.
  Future<Map<String, dynamic>> submitPackage(List<String> rawTransactions) async {
    return (await _call('submitpackage', [rawTransactions])) as Map<String, dynamic>;
  }

  /// Would the node accept these? Returns its reason when it would not.
  Future<List<Map<String, dynamic>>> testMempoolAccept(List<String> rawTransactions) async {
    final result = await _call('testmempoolaccept', [rawTransactions]);
    return (result as List).cast<Map<String, dynamic>>();
  }

  Future<Map<String, dynamic>> decodeRawTransaction(String hex) async {
    return (await _call('decoderawtransaction', [hex])) as Map<String, dynamic>;
  }

  Future<List<Map<String, dynamic>>> listUnspent({int minConf = 1}) async {
    final result = await _call('listunspent', [minConf]);
    return (result as List).cast<Map<String, dynamic>>();
  }

  /// Sign whatever inputs belong to the node's wallet, leaving the others alone — an anchor input
  /// needs no signature, so `complete: false` is the expected answer.
  Future<String> signWithWallet(String rawTransaction) async {
    final result = await _call('signrawtransactionwithwallet', [rawTransaction]);
    return result['hex'] as String;
  }

  /// Scans the UTXO set for an address.
  /// Note: This is an expensive call on mainnet, but fine for regtest.
  Future<List<Map<String, dynamic>>> scanUtxos(String address) async {
    final result = await _call('scantxoutset', [
      'start',
      [
        {'desc': 'addr($address)'}
      ]
    ]);
    return (result['unspents'] as List).cast<Map<String, dynamic>>();
  }
}
