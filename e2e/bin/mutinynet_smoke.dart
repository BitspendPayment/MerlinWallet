/// A smoke test against the live MutinyNet enclave host, `mutiny.vtxos.network`.
///
///   dart run bin/mutinynet_smoke.dart            # attestation, two wallets, DKG, addresses
///   MUTINYNET_FUNDER_KEY=<hex> dart run bin/mutinynet_smoke.dart   # also board, send, history
///
/// The same pins the app uses — `pins/deployment.json`, trust root included — and the same gate,
/// with a software passkey for the relying party the host's image was built with. Each run enrols
/// two new tenants; registration is open.
///
/// Needs `passkey-client` built in enclave-runtime (`cargo build --release -p enclave-runtime
/// --features testing --bin passkey-client`), which creates credentials — enrolment needs a CBOR
/// attestation object, and that tool already builds one.
library;

import 'dart:io';

import 'package:app_core/asp/history.dart';
import 'package:app_core/client.dart';
import 'package:app_core/enclave/attestation.dart';
import 'package:app_core/enclave/authenticator.dart';
import 'package:app_core/enclave/dev_enclave.dart';
import 'package:app_core/enclave/endpoint.dart';
import 'package:app_core/enclave/gate.dart';
import 'package:app_core/enclave/manifest.dart';
import 'package:e2e/boarding_poll.dart';
import 'package:e2e/mutinynet_funder.dart';
import 'package:hive/hive.dart';

const host = 'mutiny.vtxos.network';
final pinsUrl = Uri.parse('https://vtxos-mutinynet-enclave.s3.amazonaws.com/pins/deployment.json');
const aspHost = 'mutinynet.arkade.sh';
const electrumHost = 'electrum.mutinynet.com';

late final Directory work;

Future<EnclavePins> fetchPins() async {
  final m = await fetchManifestFrom(pinsUrl);
  if (m.host != host) throw StateError('pins are for ${m.host}, not $host');
  final root = m.trustRoot;
  if (root == null) throw StateError('an emulated enclave must publish its trust root');
  step('pins: pcr0 ${m.pcr0.substring(0, 16)}… pcr16 ${m.pcr16.substring(0, 16)}… '
      'commit ${m.commit}, published ${m.timestamp}');
  return EnclavePins(trustRoot: root, pcr0: m.pcr0, pcr16: m.pcr16);
}

Future<({MpcClient client, EnclaveGate gate})> wallet(String name, EnclavePins pins, String rpId) async {
  final state = File('${work.path}/$name.json');
  final root = File('${work.path}/trust-root.der')..writeAsBytesSync(pins.trustRoot);
  // An address, not a name: the tool dials a socket address. Nothing depends on the name — it pins
  // the enclave through the attestation document, as the gate does.
  final address = (await InternetAddress.lookup(host, type: InternetAddressType.IPv4)).first.address;
  final enrol = await Process.run('${DevEnclave.defaultRuntimeRepo}/target/release/passkey-client', [
    '--url', 'https://$address:443',
    '--state', state.path,
    '--trust-root', root.path,
    '--pcr0', pins.pcr0,
    '--pcr16', pins.pcr16,
    '--rp-id', rpId,
    'enrol',
  ]);
  if (enrol.exitCode != 0) throw StateError('enrolling $name: ${enrol.stderr}${enrol.stdout}');

  final gate = EnclaveGate(
    endpoint: EnclaveEndpoint.public(host),
    pins: pins,
    origin: 'https://$rpId',
    refreshPins: fetchPins,
    authenticator: SoftwareAuthenticator.fromStateJson(
      state.readAsStringSync(),
      rpId: rpId,
      onCounter: (c) => state.writeAsStringSync(
          state.readAsStringSync().replaceFirst(RegExp(r'"counter":\d+'), '"counter":$c')),
    ),
  );
  final client = MpcClient.enclave(
    gate: gate,
    aspHost: aspHost,
    aspPort: 443,
    aspSecure: true,
    storageId: 'smoke_$name',
  );
  // The wallet's key is derived from its passkey's PRF, so it needs one before any ceremony —
  // exactly as the app wires the platform passkey's. See `SoftwareAuthenticator.seedSource`.
  client.setSeedSource((gate.authenticator! as SoftwareAuthenticator).seedSource);
  return (client: client, gate: gate);
}

void step(String s) => stdout.writeln('${DateTime.now().toIso8601String().substring(11, 19)}  $s');

Future<T> eventually<T>(String what, Future<T> Function() read, bool Function(T) done,
    {Duration timeout = const Duration(minutes: 5)}) async {
  final deadline = DateTime.now().add(timeout);
  while (true) {
    final value = await read();
    if (done(value)) return value;
    if (DateTime.now().isAfter(deadline)) throw StateError('timed out waiting for $what');
    await Future<void>.delayed(const Duration(seconds: 5));
  }
}

Future<void> main() async {
  work = Directory.systemTemp.createTempSync('merlin_mutinynet_smoke_');
  Hive.init(work.path);
  await MpcClient.initPersistence(path: '${work.path}/mpc_client');

  final manifest = await fetchManifestFrom(pinsUrl);
  final rpId = manifest.rpId.isEmpty ? 'vtxos.com' : manifest.rpId;
  final pins = await fetchPins();

  final probe = EnclaveGate(endpoint: EnclaveEndpoint.public(host), pins: pins, origin: 'https://$rpId');
  final attested = await probe.attest();
  step('attested: certificate ${attested.certificateSha256.substring(0, 16)}…, '
      'guest ${attested.guestSha256.substring(0, 16)}…');
  probe.close();

  final alice = await wallet('alice', pins, rpId);
  final bob = await wallet('bob', pins, rpId);
  try {
    final info = await alice.client.getServerInfo();
    step('GetServerInfo: ${info.bitcoinNetwork}');
    if (info.bitcoinNetwork != 'mutinynet') throw StateError('expected mutinynet');

    const token = 'smoke-test-device-token-0123456789abcdef';
    final enrolled = <String>[];
    alice.client.onDeviceEnrolled = enrolled.add;
    alice.client.offerDeviceToken(token);
    await alice.client.doDkg();
    await bob.client.doDkg();
    step('DKG: alice ${alice.client.groupKeyHex!.substring(0, 16)}…, '
        'bob ${bob.client.groupKeyHex!.substring(0, 16)}…');
    step('device enrolled with the DKG: ${enrolled.contains(token)}, '
        'count ${await alice.client.deviceCount()}');

    final boarding = await alice.client.getBoardingAddress();
    step('alice ark ${await alice.client.getArkAddress()}');
    step('alice boarding $boarding');

    final funderKey = Platform.environment['MUTINYNET_FUNDER_KEY'];
    if (funderKey == null || funderKey.isEmpty) {
      step('no MUTINYNET_FUNDER_KEY: stopping before funds. PASS');
      return;
    }

    const boardSats = 20000;
    const sendSats = 5000;
    final funder = MutinyNetFunder(funderKey);
    await funder.connect();
    try {
      step('funder ${funder.address}: ${await funder.getBalanceSats()} sats');
      final txid = await funder.sendToAddress(boarding, boardSats);
      step('funded boarding: $txid; waiting for a confirmation');
      await funder.waitForConfirmation(txid, timeoutSecs: 600);
    } finally {
      await funder.close();
    }

    final deposits = await pollBoardingUtxos(boarding, boardSats, host: electrumHost, attempts: 60);
    final commitment = await settleBoarding(alice.client, deposits);
    step('boarded: commitment $commitment; delegate ${alice.client.delegateStatus?.validAt}');

    await eventually('alice\'s VTXO', alice.client.listVtxos, (v) => v.isNotEmpty);
    final arkTxid = await alice.client.sendVtxo(await bob.client.getArkAddress(), sendSats);
    step('sent $sendSats to bob: $arkTxid');

    final bobHistory = await eventually('bob to see the receive', bob.client.arkHistory,
        (List<ArkTransaction> h) => h.any((t) => t.kind == ArkTransactionKind.received));
    final aliceHistory = await alice.client.arkHistory();
    step('bob history: ${bobHistory.map((t) => '${t.kind.name} ${t.amountSats}').join(', ')}');
    step('alice history: ${aliceHistory.map((t) => '${t.kind.name} ${t.amountSats}').join(', ')}');
    step('PASS');
  } finally {
    await alice.client.close();
    await bob.client.close();
    alice.gate.close();
    bob.gate.close();
  }
}
