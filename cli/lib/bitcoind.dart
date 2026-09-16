/// Just enough of bitcoind's RPC to fund a boarding address on regtest.
library;

import 'dart:convert';

import 'package:http/http.dart' as http;

class Bitcoind {
  Bitcoind(this.url, {required this.wallet});

  /// `http://user:pass@host:port`.
  final Uri url;
  final String wallet;

  Future<dynamic> _call(String method, [List<dynamic> params = const []]) async {
    final resp = await http.post(
      url.replace(path: '/wallet/$wallet', userInfo: ''),
      headers: {
        'content-type': 'text/plain',
        if (url.userInfo.isNotEmpty) 'authorization': 'Basic ${base64Encode(utf8.encode(url.userInfo))}',
      },
      body: jsonEncode({'jsonrpc': '1.0', 'id': 'merlin-cli', 'method': method, 'params': params}),
    );
    final body = jsonDecode(resp.body) as Map<String, dynamic>;
    if (body['error'] != null) throw StateError('bitcoind $method: ${body['error']}');
    return body['result'];
  }

  Future<String> send(String address, int sats) async =>
      await _call('sendtoaddress', [address, sats / 1e8]) as String;

  Future<void> mine([int blocks = 1]) async {
    final to = await _call('getnewaddress', ['', 'bech32m']);
    await _call('generatetoaddress', [blocks, to]);
  }

  /// Mine a block every few seconds while [body] runs.
  ///
  /// Nothing moves on regtest unless somebody mines: the boarding input needs a confirmation before
  /// arkd accepts it, and a commitment needs one before its VTXOs are spendable.
  Future<T> whileMining<T>(Future<T> Function() body) async {
    var running = true;
    Future<void> loop() async {
      while (running) {
        await Future<void>.delayed(const Duration(seconds: 3));
        if (!running) break;
        try {
          await mine();
        } catch (_) {
          // A missed block delays a round; it does not fail it.
        }
      }
    }

    final miner = loop();
    try {
      return await body();
    } finally {
      running = false;
      await miner;
    }
  }
}
