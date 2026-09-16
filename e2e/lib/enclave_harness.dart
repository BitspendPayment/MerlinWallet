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

  /// Attach to a running enclave, or boot one.
  ///
  /// [component] defaults to the release component `make cosigner-wasm` writes.
  static Future<EnclaveHarness> start({
    String name = 'merlin',
    int port = 8443,
    String? component,
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

    Log.info('booting an enclave with $wasm');
    final proc = await Process.start(
      '$_runtimeRepo/deploy/qemu-nitro/dev-enclave.sh',
      [
        '--guest', wasm, '--name', name, '--port', '$port',
        // The cosigner runs sealed delegates itself, against arkd on the host — which is
        // 192.168.127.254 from inside the enclave. The margin makes a delegate come due about five
        // minutes after its VTXOs were made (regtest VTXOs live 15360s), so a test can watch one run.
        '--guest-egress', 'http://192.168.127.254:7070',
        '--guest-env', 'ASP_URL=http://192.168.127.254:7070',
        '--guest-env', 'AUTO_SETTLE_SAFETY_MARGIN_SECS=15060',
        '--background-timeout', '600',
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

  /// Hive, once per process, under a directory this run owns.
  ///
  /// Wallet state is the client's half of the key — the FROST share, the policy, the on-chain
  /// secret — and it is per test run, not per enclave: a fresh directory each time is what stops
  /// one run's share being reused against another run's tenant, whose seal knows nothing about it.
  static Directory? _hiveDir;
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
