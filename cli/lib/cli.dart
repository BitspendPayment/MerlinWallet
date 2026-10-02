/// The commands, over wallets whose cosigners run inside a dev enclave.
library;

import 'dart:io';

import 'package:app_core/asp/asp_client.dart' show IndexerVtxo;
import 'package:app_core/client.dart';
import 'package:app_core/electrum.dart';
import 'package:app_core/enclave/dev_enclave.dart';
import 'package:app_core/enclave/gate.dart';
import 'package:app_core/persistence/wallet_store.dart' show IncompatibleWalletStateException;
import 'package:bitcoin_base/bitcoin_base.dart';
import 'package:blockchain_utils/blockchain_utils.dart' hide hex;
import 'package:fixnum/fixnum.dart';
import 'package:hive/hive.dart';
import 'package:protocol/cosigner_v1.dart' show BoardingUtxo;

import 'bitcoind.dart';
import 'home.dart';

const help = '''
wallets                          list wallets on this enclave (* = active)
new <name>                       enrol a passkey (a new tenant) and run DKG
use <name>                       switch the active wallet
whoami                           active wallet, its group key, and what the enclave attested
info                             ask the cosigner what network it serves

receive                          an Ark address to be paid at
boarding-address                 the on-chain address that boards into Ark
fund <sats>                      bitcoind pays the boarding address, then board
board                            settle every confirmed boarding deposit into Ark
balance                          VTXOs held, and whether a sealed delegate renews them
protect                          renew the delegate over what is held, so the cosigner refreshes it
send <ark-address|wallet> <sats> pay, off-chain

reset <name>                     delete this machine's stored state for a wallet and rebuild it
                                 from its passkey — for state an older build wrote

help, quit''';

class Cli {
  Cli({
    required this.enclave,
    required this.home,
    required this.aspHost,
    required this.aspPort,
    required this.bitcoind,
    required this.electrumHost,
    required this.electrumPort,
  });

  final DevEnclave enclave;
  final CliHome home;
  final String aspHost;
  final int aspPort;
  final Bitcoind bitcoind;
  final String electrumHost;
  final int electrumPort;

  final _open = <String, ({MpcClient client, EnclaveGate gate})>{};

  Future<void> start() async {
    Hive.init(home.hivePath);
    await MpcClient.initPersistence(path: home.hivePath);
    home.load();
  }

  Future<void> close() async {
    for (final w in _open.values) {
      await w.client.close();
      w.gate.close();
    }
    _open.clear();
  }

  /// Run one command line. Returns false to quit.
  Future<bool> run(String line) async {
    final args = _split(line);
    if (args.isEmpty) return true;
    final rest = args.sublist(1);
    switch (args.first) {
      case 'help':
        print(help);
      case 'quit' || 'exit':
        return false;
      case 'wallets':
        if (home.wallets.isEmpty) print('no wallets yet — `new <name>`');
        for (final w in home.wallets.values) {
          print('${w.name == home.active ? '*' : ' '} ${w.name}  ${w.groupKey ?? '(no key)'}');
        }
      case 'new':
        await _new(_arg(rest, 0, 'name'));
      case 'reset':
        await _reset(_arg(rest, 0, 'name'));
      case 'use':
        final name = _arg(rest, 0, 'name');
        _record(name);
        home.active = name;
        home.save();
        print('using $name');
      case 'whoami':
        final (name, w) = await _active();
        final attested = w.gate.attested ?? await w.gate.attest();
        print('wallet     $name');
        print('group key  ${w.client.groupKeyHex}');
        print('passkey    ${home.passkey(name).path}');
        print('enclave    pcr0 ${enclave.pcr0.substring(0, 16)}…  pcr16 ${enclave.pcr16.substring(0, 16)}…');
        print('attested   certificate ${attested.certificateSha256.substring(0, 16)}…  '
            'guest ${attested.guestSha256.substring(0, 16)}…  at ${attested.timestamp.toLocal()}');
      case 'info':
        final (_, w) = await _active();
        print('network ${(await w.client.getServerInfo()).bitcoinNetwork}');
      case 'receive':
        final (_, w) = await _active();
        print(await w.client.getArkAddress());
      case 'boarding-address':
        final (_, w) = await _active();
        print(await w.client.getBoardingAddress());
      case 'fund':
        final sats = _sats(rest, 0);
        final (_, w) = await _active();
        final address = await w.client.getBoardingAddress();
        print('bitcoind → $address  $sats sats: ${await bitcoind.send(address, sats)}');
        await bitcoind.mine();
        await _board(w.client, minSats: sats);
      case 'board':
        final (_, w) = await _active();
        await _board(w.client);
      case 'balance':
        final (_, w) = await _active();
        final vtxos = (await w.client.listVtxos()).where((v) => !v.isSpent).toList();
        for (final v in vtxos) {
          print('  ${v.amountSats} sats  ${v.txid}:${v.vout}  exit delay ${v.exitDelay}');
        }
        print('${_total(vtxos)} sats in ${vtxos.length} VTXO(s)');
        final delegate = w.client.delegateStatus;
        final unprotected = await w.client.unprotectedVtxos();
        if (vtxos.isEmpty) {
          // Nothing to renew.
        } else if (delegate == null || unprotected.isNotEmpty) {
          print('not protected: ${unprotected.length} VTXO(s) — `protect` to have them renewed');
        } else {
          print('protected: the cosigner renews them at ${delegate.validAt.toLocal()}');
        }
      case 'protect':
        final (_, w) = await _active();
        final renewed = await w.client.protectFunds();
        print('protected ${renewed.covered.length} VTXO(s): the cosigner renews them at '
            '${renewed.validAt.toLocal()}');
      case 'send':
        final (_, w) = await _active();
        final to = _arg(rest, 0, 'ark address or wallet');
        final sats = _sats(rest, 1);
        final address = home.wallets.containsKey(to) ? await (await _wallet(to)).client.getArkAddress() : to;
        final txid = await bitcoind.whileMining(() => w.client.sendVtxo(address, sats));
        print('sent $sats sats: $txid');
      default:
        print('unknown command ${args.first} — `help`');
    }
    return true;
  }

  Future<void> _new(String name) async {
    if (home.wallets.containsKey(name)) throw StateError('$name already exists');
    final passkey = home.passkey(name);
    print('enrolling a passkey for $name (a new tenant)…');
    await enclave.enrol(passkey);
    home.wallets[name] = WalletRecord(name);
    home.active = name;
    home.save();

    final w = await _wallet(name);
    print('running DKG…');
    await w.client.doDkg();
    home.wallets[name]!.groupKey = w.client.groupKeyHex;
    home.save();
    print('$name: ${w.client.groupKeyHex}');
  }

  /// Throw away what this machine stores about [name] and rebuild it from the passkey.
  ///
  /// What `IncompatibleWalletStateException` asks for: state from before shares were rebuilt per
  /// operation holds a blinded share in an append-only file, and there is no migration — the file
  /// goes. Nothing is lost by it. The wallet is its passkey and the cosigner's seal, and `recover`
  /// needs only those; if the cosigner answers that the wallet "was created before recovery
  /// existed", it is older than that too, and the enclave's store needs resetting with it.
  Future<void> _reset(String name) async {
    _record(name);
    await _open.remove(name)?.client.close();
    final gate = enclave.gate(home.passkey(name));
    final client =
        enclave.client(gate, aspHost: aspHost, aspPort: aspPort, storageId: home.storageId(name));
    await client.resetLocalState();
    print('deleted the stored state for $name; rebuilding it from the passkey…');
    await client.recover();
    home.wallets[name]!.groupKey = client.groupKeyHex;
    home.save();
    _open[name] = (client: client, gate: gate);
    print('$name: ${client.groupKeyHex}');
  }

  Future<void> _board(MpcClient client, {int minSats = 1}) async {
    final deposits = await _scanBoarding(await client.getBoardingAddress(), minSats);
    if (deposits.isEmpty) {
      print('no confirmed boarding deposits yet');
      return;
    }
    // One per renewal: the cosigner builds its boarding intent proof for a single outpoint.
    for (final d in deposits) {
      print('settling ${d.amountSats} sats from ${d.txid}:${d.vout}…');
      final commitment = await bitcoind.whileMining(() => client.renew(boardingUtxos: [d]));
      print('  commitment $commitment');
    }
  }

  Future<List<BoardingUtxo>> _scanBoarding(String boardingAddress, int minSats) async {
    final address = boardingAddress.startsWith('bcrt')
        ? P2trAddress.fromProgram(
            program: BytesUtils.toHexString(SegwitBech32Decoder.decode('bcrt', boardingAddress).item2))
        : P2trAddress.fromAddress(address: boardingAddress, network: BitcoinNetwork.testnet);
    final electrum = ElectrumClient(electrumHost, electrumPort);
    try {
      for (var i = 0; i < 30; i++) {
        try {
          final utxos = await electrum.listUnspent(address);
          if (utxos.fold<int>(0, (s, u) => s + u.value.toInt()) >= minSats) {
            return [
              for (final u in utxos)
                BoardingUtxo()
                  ..txid = u.txHash
                  ..vout = u.vout
                  ..amountSats = Int64(u.value.toInt()),
            ];
          }
        } catch (_) {}
        await Future<void>.delayed(const Duration(seconds: 1));
      }
      return [];
    } finally {
      electrum.close();
    }
  }

  Future<(String, ({MpcClient client, EnclaveGate gate}))> _active() async {
    final name = home.active;
    if (name == null) throw StateError('no active wallet — `new <name>` or `use <name>`');
    return (name, await _wallet(name));
  }

  Future<({MpcClient client, EnclaveGate gate})> _wallet(String name) async {
    final open = _open[name];
    if (open != null) return open;
    _record(name);
    final gate = enclave.gate(home.passkey(name));
    final client = enclave.client(gate, aspHost: aspHost, aspPort: aspPort, storageId: home.storageId(name));
    try {
      await client.restoreState();
    } on IncompatibleWalletStateException {
      await client.close();
      print('the stored state for $name is from an older build — run `reset $name`');
      rethrow;
    }
    return _open[name] = (client: client, gate: gate);
  }

  WalletRecord _record(String name) =>
      home.wallets[name] ?? (throw ArgumentError('no wallet $name on this enclave — `wallets`'));

  static String _arg(List<String> args, int i, String what) =>
      i < args.length ? args[i] : throw ArgumentError('missing <$what>');

  static int _sats(List<String> args, int i) =>
      int.tryParse(_arg(args, i, 'sats')) ?? (throw ArgumentError('<sats> must be a whole number'));

  static int _total(List<IndexerVtxo> vtxos) => vtxos.fold(0, (s, v) => s + v.amountSats);

  static List<String> _split(String line) =>
      line.trim().split(RegExp(r'\s+')).where((s) => s.isNotEmpty).toList();
}

/// Build from the environment:
///
///   MERLIN_ENCLAVE_RUN  the dev enclave's run directory (default ~/enclave-runtime/target/qemu-nitro/merlin)
///   ENCLAVE_PORT        8443
///   ASP                 127.0.0.1:7070
///   BITCOIN_RPC_URL     http://admin1:123@127.0.0.1:18443, wallet BITCOIN_RPC_WALLET (default)
///   ELECTRUM            127.0.0.1:50001
Cli fromEnvironment() {
  final env = Platform.environment;
  final run = env['MERLIN_ENCLAVE_RUN'] ?? '${DevEnclave.defaultRuntimeRepo}/target/qemu-nitro/merlin';
  if (!File('$run/trust-root.der').existsSync()) {
    throw StateError('no dev enclave at $run — boot one with dev-enclave.sh, or set MERLIN_ENCLAVE_RUN');
  }
  final enclave = DevEnclave(runDir: run, port: int.parse(env['ENCLAVE_PORT'] ?? '8443'));
  (String, int) hostPort(String? value, String fallback) {
    final parts = (value ?? fallback).split(':');
    return (parts[0], int.parse(parts[1]));
  }

  final (aspHost, aspPort) = hostPort(env['ASP'], '127.0.0.1:7070');
  final (electrumHost, electrumPort) = hostPort(env['ELECTRUM'], '127.0.0.1:50001');
  return Cli(
    enclave: enclave,
    home: CliHome.forEnclave(enclave.pins.trustRoot, storeId: enclave.storeId),
    aspHost: aspHost,
    aspPort: aspPort,
    bitcoind: Bitcoind(Uri.parse(env['BITCOIN_RPC_URL'] ?? 'http://admin1:123@127.0.0.1:18443'),
        wallet: env['BITCOIN_RPC_WALLET'] ?? 'default'),
    electrumHost: electrumHost,
    electrumPort: electrumPort,
  );
}
