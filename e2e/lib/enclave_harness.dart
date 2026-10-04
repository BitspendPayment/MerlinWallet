/// Bringing up a real enclave, and wiring clients to it.
///
/// The cosigner is a Wasm component with no listener of its own, so a test cannot spawn it: it
/// needs a host, and `enclave-runtime`'s own binary refuses to serve outside an enclave because it
/// measures the guest into PCR16 before serving and that reads the Nitro Security Module. So this
/// drives `deploy/qemu-nitro/dev-enclave.sh`, which boots the real thing under QEMU.
///
/// What that buys, beyond "it runs at all":
///
///  * **Tenancy comes free.** One passkey is one tenant with its own isolated filesystem, so Alice
///    and Bob are two state files against one enclave — not two processes, and not one process
///    multiplexing on a client-side `storageId` the way the old suite did.
///  * **Wakes are observable.** Firebase is stubbed to `fcm-messages.jsonl`.
///  * **The client runs its real path.** TLS, the nonce, and a WebAuthn assertion per request.
///
/// Booting is slow — minutes, and much worse on a cold Nix build — and only one enclave can be up
/// at a time because MinIO's port and the vsock CID are fixed. So [EnclaveHarness.start] will
/// **attach to an enclave that is already running** when `MERLIN_ENCLAVE_RUN` names its run
/// directory. That is the developer loop: leave one up in another terminal and re-run the suite
/// against it.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' show Random;

import 'package:app_core/client.dart';
import 'package:app_core/enclave/dev_enclave.dart';
import 'package:app_core/enclave/gate.dart';
import 'package:hive/hive.dart';

import 'logger.dart';

String get _runtimeRepo => DevEnclave.defaultRuntimeRepo;

/// One wallet: its passkey, its tenant, its client.
class Wallet {
  Wallet(this.name, this.client, this.gate);
  final String name;
  final MpcClient client;
  final EnclaveGate gate;

  Future<void> close() async {
    await client.close();
    gate.close();
  }
}

class EnclaveHarness {
  EnclaveHarness._({
    required this.runDir,
    required this.pcr0,
    required this.pcr16,
    required this.trustRoot,
    required this.port,
    required this.attached,
    Process? process,
  }) : _process = process;

  /// `target/qemu-nitro/<name>/` — the trust root, the passkey state files, the console log and
  /// every wake the guest raised.
  final String runDir;

  /// What every client here pins: each approval verifies the enclave's attestation document against
  /// these, and the cosigner channel refuses a certificate the document did not bind.
  final String pcr0;
  final String pcr16;
  final String trustRoot;

  final int port;

  /// True when we found an enclave already up rather than booting one. Teardown leaves it alone.
  final bool attached;

  /// Distinguishes this run's wallets from every earlier run's against the same enclave.
  ///
  /// A wallet is a passkey, and a passkey is a tenant whose sealed state outlives the process. So a
  /// second run naming its wallet `alice` again would reach the first run's tenant — whose seal
  /// already holds a key — and its DKG would be refused, correctly: the cosigner will not replace a
  /// wallet's key. Fresh names per run are what fresh wallets are.
  final String runId = List<int>.generate(4, (_) => Random.secure().nextInt(256))
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  final Process? _process;

  late final DevEnclave enclave =
      DevEnclave(runDir: runDir, port: port, pcr0: pcr0, pcr16: pcr16);

  /// Every wake the guest raised, newest last. Empty until something calls `notify`.
  List<Map<String, dynamic>> wakes() {
    final f = File('$runDir/fcm-messages.jsonl');
    if (!f.existsSync()) return const [];
    return f
        .readAsLinesSync()
        .where((l) => l.trim().isNotEmpty)
        .map((l) => jsonDecode(l) as Map<String, dynamic>)
        .toList();
  }

  /// The image options this suite's enclave is built with. Measured into PCR0, all of them: a
  /// bundle has to have been packed with exactly these, and `bin/bundle_args.dart` prints them
  /// for that purpose.
  static List<String> imageOptions({
    String? serviceOrigins,
    List<String> extraEgress = const [],
    Map<String, String> extraEnv = const {},
  }) =>
      [
        // The cosigner runs sealed delegates itself, against arkd on the host — which is
        // 192.168.127.254 from inside the enclave. The margin makes a delegate come due about five
        // minutes after its VTXOs were made (regtest VTXOs live 15360s), so a test can watch one run.
        '--guest-egress', 'http://192.168.127.254:7070',
        '--guest-env', 'ASP_URL=http://192.168.127.254:7070',
        '--guest-env', 'AUTO_SETTLE_SAFETY_MARGIN_SECS=15060',
        // Each named service needs both halves of the permission: the guest has to be told the id
        // means that origin, and the image has to allow the guest to dial it. Naming one without
        // the other fails at delivery, which is the wrong place to find out.
        if (serviceOrigins != null && serviceOrigins.isNotEmpty) ...[
          '--guest-env', 'SERVICE_ORIGINS=$serviceOrigins',
          for (final entry in serviceOrigins.split(RegExp(r'[,_]')))
            // The origin is whatever follows the first separator; an origin's own `://` comes
            // later. See `ServiceRegistry` in `cosigner/src/escrow.rs` for why both spellings
            // exist.
            ...['--guest-egress', entry.replaceFirst(RegExp(r'^[0-9a-fA-F]+[:=]'), '')],
        ],
        for (final origin in extraEgress) ...['--guest-egress', origin],
        for (final entry in extraEnv.entries) ...['--guest-env', '${entry.key}=${entry.value}'],
        '--background-timeout', '600',
      ];

  /// Refuse a bundle packed with other image options than [image].
  ///
  /// `image.env` is what `dev-enclave.sh --pack` recorded: `printf %q` output, so a value is
  /// `''` when empty and otherwise has every shell-special character backslashed, and repeated
  /// options are joined with commas. Compared as sets — order is not a difference.
  static void _checkBundle(String dir, List<String> image) {
    final packed = <String, String>{};
    for (final line in File('$dir/image.env').readAsLinesSync()) {
      final m = RegExp(r'^([A-Z_][A-Z0-9_]*)=(.*)$').firstMatch(line);
      if (m == null) continue; // the `:`/`export` lines: the image tags, which a caller may override
      final raw = m.group(2)!;
      packed[m.group(1)!] = raw == "''" ? '' : raw.replaceAll('\\', '');
    }
    final egress = <String>{}, env = <String>{};
    String? timeout;
    for (var i = 0; i + 1 < image.length; i += 2) {
      switch (image[i]) {
        case '--guest-egress':
          egress.add(image[i + 1]);
        case '--guest-env':
          env.add(image[i + 1]);
        case '--background-timeout':
          timeout = image[i + 1];
      }
    }
    Set<String> packedSet(String key) =>
        (packed[key] ?? '').split(',').where((s) => s.isNotEmpty).toSet();
    final mismatches = <String>[
      if (!_sameSet(packedSet('GUEST_EGRESS_ORIGINS'), egress))
        'GUEST_EGRESS_ORIGINS=${packed['GUEST_EGRESS_ORIGINS']} (this suite needs ${egress.join(',')})',
      if (!_sameSet(packedSet('GUEST_ENV'), env))
        'GUEST_ENV=${packed['GUEST_ENV']} (this suite needs ${env.join(',')})',
      if ((packed['BACKGROUND_TIMEOUT_SECS'] ?? '') != (timeout ?? ''))
        'BACKGROUND_TIMEOUT_SECS=${packed['BACKGROUND_TIMEOUT_SECS']} (this suite needs $timeout)',
    ];
    if (mismatches.isNotEmpty) {
      throw StateError(
        'the bundle at $dir (runtime ${packed['ENCLAVE_RUNTIME_REV'] ?? '?'}) was packed with '
        'other image options than this suite boots with:\n  ${mismatches.join('\n  ')}\n'
        'Repack it with: dev-enclave.sh --pack DIR ${image.join(' ')}',
      );
    }
    Log.info('bundle: runtime ${packed['ENCLAVE_RUNTIME_REV'] ?? '?'}, image options match');
  }

  static bool _sameSet(Set<String> a, Set<String> b) =>
      a.length == b.length && a.containsAll(b);

  /// Attach to a running enclave, or boot one.
  ///
  /// [component] defaults to the release component `make cosigner-wasm` writes.
  /// [serviceOrigins] names the escrow services this image may pair with, as
  /// `<service id hex>=<origin>`. It is image configuration, measured into PCR0 — a wallet names a
  /// service *id* and never a URL — so it has to be decided before the enclave boots, which is why
  /// a test that pairs must start its service on a known port first.
  static Future<EnclaveHarness> start({
    String name = 'merlin',
    int port = 8443,
    String? component,
    String? serviceOrigins,
    /// Origins the guest may dial that are not services — a payment provider, say. A service needs
    /// both halves (a name and an egress allowance); anything the cosigner only *fetches* from
    /// needs the allowance alone.
    List<String> extraEgress = const [],
    /// Extra image environment. Measured into PCR0 like everything else here, which is the point:
    /// a credential the cosigner uses is part of what the image is.
    Map<String, String> extraEnv = const {},
    Duration timeout = const Duration(minutes: 20),
  }) async {
    final existing = Platform.environment['MERLIN_ENCLAVE_RUN'];
    if (existing != null && existing.isNotEmpty) {
      Log.info('attaching to the enclave at $existing');
      return EnclaveHarness._(
        runDir: existing,
        // Read back from the console rather than re-derived, so an attached run reports what that
        // enclave actually measured and not what this checkout would build.
        pcr0: _fromConsole(existing, RegExp(r'pcr0=([0-9a-f]{96})')),
        pcr16: _fromConsole(existing, RegExp(r'pcr16=([0-9a-f]{96})')),
        trustRoot: '$existing/trust-root.der',
        port: port,
        attached: true,
      );
    }

    final wasm = component ??
        '${Directory.current.parent.path}/cosigner/target/wasm32-wasip2/release/cosigner.wasm';
    if (!File(wasm).existsSync()) {
      throw StateError('no component at $wasm — build it first: make cosigner-wasm');
    }

    final image =
        imageOptions(serviceOrigins: serviceOrigins, extraEgress: extraEgress, extraEnv: extraEnv);
    // A bundle (`make enclave-bundle`) is booted as it was packed: image options are refused by
    // `--prebuilt`, so they are checked against what the pack recorded instead. Refusing here is
    // the point — a bundle with another margin would not fail, it would quietly skip the delegate
    // test.
    final bundle = DevEnclave.isBundle(_runtimeRepo);
    if (bundle) _checkBundle(_runtimeRepo, image);

    Log.info('booting an enclave with $wasm${bundle ? ' from the bundle at $_runtimeRepo' : ''}');
    final proc = await Process.start(
      '$_runtimeRepo/deploy/qemu-nitro/dev-enclave.sh',
      [
        '--guest', wasm, '--name', name, '--port', '$port',
        if (bundle) ...['--prebuilt', _runtimeRepo] else ...image,
      ],
      workingDirectory: _runtimeRepo,
    );

    // The script prints a summary block and then blocks forever; there is no `--detach` and no
    // readiness file, so the three values a client pins are scraped from that block.
    final ready = Completer<EnclaveHarness>();
    final seen = StringBuffer();
    String? pcr0, pcr16, trustRoot;
    void consume(String chunk) {
      seen.write(chunk);
      Log.server(chunk.trimRight());
      pcr0 ??= RegExp(r'--pcr0\s+([0-9a-f]{96})').firstMatch(seen.toString())?.group(1);
      pcr16 ??= RegExp(r'--pcr16\s+([0-9a-f]{96})').firstMatch(seen.toString())?.group(1);
      trustRoot ??= RegExp(r'--trust-root\s+(\S+)').firstMatch(seen.toString())?.group(1);
      if (!ready.isCompleted && seen.toString().contains('Ctrl-C to stop everything')) {
        ready.complete(EnclaveHarness._(
          runDir: '$_runtimeRepo/target/qemu-nitro/$name',
          pcr0: pcr0!,
          pcr16: pcr16!,
          trustRoot: trustRoot!,
          port: port,
          attached: false,
          process: proc,
        ));
      }
    }

    proc.stdout.transform(utf8.decoder).listen(consume);
    proc.stderr.transform(utf8.decoder).listen(consume);
    unawaited(proc.exitCode.then((code) {
      if (!ready.isCompleted) {
        ready.completeError(StateError('the enclave exited ($code) before serving:\n$seen'));
      }
    }));

    return ready.future.timeout(timeout);
  }

  /// A wallet, with its own passkey and therefore its own tenant and filesystem.
  ///
  /// `dev-enclave.sh` enrols `alice.json` on the way up so its printed command works; any other
  /// name is enrolled here. Registration is open — no invitation, no operator step — which is the
  /// whole reason a second wallet costs one subprocess.
  Future<Wallet> wallet(String name, {required String aspHost, required int aspPort}) async {
    await _initPersistence();
    final state = File('$runDir/$name-$runId.json');
    if (!state.existsSync()) {
      Log.info('enrolling a passkey for $name');
      await enclave.enrol(state);
    }
    final gate = enclave.gate(state);
    return Wallet(
      name,
      enclave.client(gate, aspHost: aspHost, aspPort: aspPort, storageId: 'e2e_${name}_$runId'),
      gate,
    );
  }

  /// The same passkey on a phone that has never held this wallet's key.
  ///
  /// Its enrolled credential — so the runtime resolves the same tenant and the same cosigner — with
  /// a gate of its own and an empty store. What a reinstall looks like, and the only honest way to
  /// test recovery: a client that has never run the ceremony it is recovering from.
  Future<Wallet> newDeviceFor(String name,
      {required String aspHost, required int aspPort}) async {
    await _initPersistence();
    final state = File('$runDir/$name-$runId.json');
    if (!state.existsSync()) {
      throw StateError('$name has no passkey to recover with');
    }
    final gate = enclave.gate(state);
    return Wallet(
      name,
      enclave.client(gate,
          aspHost: aspHost, aspPort: aspPort, storageId: 'e2e_${name}_device2_$runId'),
      gate,
    );
  }

  /// Hive, once per process, under a directory this run owns.
  ///
  /// Wallet state is public — who the wallet is, its delegate, its exits; no share, no dealer
  /// secret — and it is per test run, not per enclave: a fresh directory each time is what stops
  /// one run's wallet being opened against another run's tenant, whose seal knows nothing about it.
  static Directory? _hiveDir;

  /// The file [wallet]'s client state is appended to. For a test that wants to read what is
  /// actually on disk, not what the client says it wrote.
  File stateFileOf(Wallet wallet, {bool secondDevice = false}) {
    final dir = _hiveDir;
    if (dir == null) throw StateError('no wallet has been opened yet');
    final id = secondDevice ? 'e2e_${wallet.name}_device2_$runId' : 'e2e_${wallet.name}_$runId';
    return File('${dir.path}/mpc_client/${id.toLowerCase()}.hive');
  }

  static Future<void> _initPersistence() async {
    if (_hiveDir != null) return;
    final dir = Directory.systemTemp.createTempSync('merlin_e2e_');
    _hiveDir = dir;
    Hive.init(dir.path);
    await MpcClient.initPersistence(path: '${dir.path}/mpc_client');
  }

  /// Stop what we started. An attached enclave is left running — it was not ours to stop.
  ///
  /// The script tears down after itself on SIGINT, but not reliably: interrupting it can take out
  /// the QEMU container before its exit trap runs, and then MinIO, Pebble, the FCM stub, gvproxy and
  /// the vsock bridge all outlive it, still holding the fixed ports the next run needs. So after
  /// asking nicely this sweeps what the run started. Everything it creates carries the label
  /// `enclave-harness=<name>`, which is exactly what the script's own cleanup removes — this is that
  /// cleanup, for when the trap did not get to run it.
  Future<void> stop() async {
    if (attached || _process == null) return;
    Log.info('stopping the enclave');
    _process.kill(ProcessSignal.sigint);
    await _process.exitCode.timeout(const Duration(minutes: 2), onTimeout: () {
      _process.kill(ProcessSignal.sigkill);
      return -1;
    });
    await _sweep(name);
  }

  /// This run's name, from its directory.
  String get name => runDir.split('/').last;

  static Future<void> _sweep(String name) async {
    final ids = await Process.run(
        'docker', ['ps', '-aq', '--filter', 'label=enclave-harness=$name']);
    final containers =
        (ids.stdout as String).split('\n').where((l) => l.trim().isNotEmpty).toList();
    if (containers.isNotEmpty) {
      await Process.run('docker', ['rm', '-f', ...containers]);
    }
    // The helpers are host processes, not containers, and carry no label — but each names this
    // run's directory on its command line, which is specific enough to match on.
    await Process.run('pkill', ['-f', 'qemu-nitro/$name/']);
    await Process.run('pkill', ['-f', 'fcm-stub.py .*qemu-nitro/$name/']);
    await Process.run('pkill', ['-f', 'heartbeat.py 9000']);
  }

  /// The runtime writes its log with colour, and the escapes land between the field name and its
  /// value — `pcr0` and `=8f20…` are separated by a reset sequence — so a pattern that reads like
  /// the text on screen matches nothing.
  static final _ansi = RegExp(r'\x1B\[[0-9;]*[a-zA-Z]');

  static String _fromConsole(String runDir, RegExp pattern) {
    final console = File('$runDir/console.log');
    if (!console.existsSync()) {
      throw StateError('no console.log in $runDir — is that an enclave run directory?');
    }
    final m = pattern.firstMatch(console.readAsStringSync().replaceAll(_ansi, ''));
    if (m == null) {
      throw StateError('could not find ${pattern.pattern} in $runDir/console.log');
    }
    return m.group(1)!;
  }
}
