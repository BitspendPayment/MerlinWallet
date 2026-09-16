/// Reaching a development enclave: the one `enclave-runtime`'s `deploy/qemu-nitro/dev-enclave.sh`
/// boots under QEMU.
///
/// Everything a client needs to talk to it is in that script's run directory,
/// `target/qemu-nitro/<name>/`: Pebble's root, which signed the served certificate; the trust root
/// the attestation chains to, fresh each boot; and the console, where the runtime logs the PCRs it
/// measured. This reads them from there, so the e2e harness and the CLI wire a wallet the same way.
///
/// **Development only.** Passkeys here are software keys in plaintext JSON files, enrolled by
/// `passkey-client` — a tool the runtime only builds with its `testing` feature, because it can
/// mint assertions. A phone uses its platform authenticator instead.
library;

import 'dart:io';

import '../client.dart';
import 'attestation.dart';
import 'authenticator.dart';
import 'endpoint.dart';
import 'gate.dart';

class DevEnclave {
  DevEnclave({
    required this.runDir,
    this.port = 8443,
    String? runtimeRepo,
    String? pcr0,
    String? pcr16,
  })  : runtimeRepo = runtimeRepo ?? defaultRuntimeRepo,
        _pcr0 = pcr0,
        _pcr16 = pcr16;

  /// The name on the certificate. Baked into the enclave image and covered by PCR0.
  static const String certificateName = 'enclave.test';

  /// The WebAuthn relying party the image was built with, as the runtime logged it at boot:
  /// `enclave.test` unless `dev-enclave.sh --rp-id` chose another — which a phone needs, since it
  /// only creates passkeys for a domain that vouches for the app. Independent of [certificateName].
  late final String rpId = _fromConsole(RegExp(r'rp_id="([^"]+)"'));

  /// What an assertion claims.
  String get origin => 'https://$rpId';

  /// Where the runtime checkout lives, for `passkey-client`. `ENCLAVE_RUNTIME` overrides it, the
  /// same way the Makefile's `wit-drift` target does.
  static String get defaultRuntimeRepo =>
      Platform.environment['ENCLAVE_RUNTIME'] ?? '${Platform.environment['HOME']}/enclave-runtime';

  /// `target/qemu-nitro/<name>/`.
  final String runDir;

  /// The host port forwarded to the enclave's :443. The socket goes to 127.0.0.1 on it; the name
  /// verified is still [rpId].
  final int port;

  final String runtimeRepo;

  final String? _pcr0;
  final String? _pcr16;

  /// The image's measurement, as the runtime logged it at boot.
  late final String pcr0 = _pcr0 ?? _fromConsole(RegExp(r'pcr0=([0-9a-f]{96})'));

  /// The guest component's measurement, as the runtime logged it at boot.
  late final String pcr16 = _pcr16 ?? _fromConsole(RegExp(r'pcr16=([0-9a-f]{96})'));

  /// The root the attestation document chains to. A new one each boot.
  String get trustRoot => '$runDir/trust-root.der';

  /// A stable name for the enclave's store, when it is kept across restarts (`dev-enclave.sh
  /// --keep-store`); null when every boot starts a new one. The trust root is new every boot, so it
  /// cannot name a store that outlives one.
  String? get storeId {
    final file = File('$runDir-store/id');
    return file.existsSync() ? file.readAsStringSync().trim() : null;
  }

  /// Pebble's roots — every one that issued a certificate a kept store may still serve. Nothing
  /// public signs them.
  late final List<int> ca = File('$runDir/pebble-root.pem').readAsBytesSync();

  /// Loopback, verified as [certificateName], under Pebble's root.
  late final EnclaveEndpoint endpoint =
      EnclaveEndpoint(host: '127.0.0.1', port: port, authority: certificateName, extraRoots: ca);

  /// This boot's root and measurements. The same three values `passkey-client` is given.
  late final EnclavePins pins = EnclavePins(
    trustRoot: File(trustRoot).readAsBytesSync(),
    pcr0: pcr0,
    pcr16: pcr16,
  );

  /// Enrol a new passkey into [state], which becomes a new tenant.
  ///
  /// Shells out because enrolment needs a CBOR attestation object, and the runtime's own software
  /// authenticator already builds one. Registration is open — no invitation, no operator step.
  Future<void> enrol(File state) async {
    final result = await Process.run('$runtimeRepo/target/release/passkey-client', [
      '--url', 'https://127.0.0.1:$port',
      '--state', state.path,
      '--trust-root', trustRoot,
      '--pcr0', pcr0,
      '--pcr16', pcr16,
      '--rp-id', rpId,
      'enrol',
    ]);
    if (result.exitCode != 0) {
      throw StateError('could not enrol ${state.path}: ${result.stderr}${result.stdout}');
    }
  }

  /// A gate that attests this enclave and asserts with the passkey in [state].
  ///
  /// The counter is written back after every assertion. An authenticator that restarted at zero
  /// would present a count no higher than one already recorded, which a relying party is entitled
  /// to read as a clone.
  EnclaveGate gate(File state) => EnclaveGate(
        endpoint: endpoint,
        pins: pins,
        origin: origin,
        authenticator: SoftwareAuthenticator.fromStateJson(
          state.readAsStringSync(),
          rpId: rpId,
          onCounter: (c) => state.writeAsStringSync(
              state.readAsStringSync().replaceFirst(RegExp(r'"counter":\d+'), '"counter":$c')),
        ),
      );

  /// A wallet client whose cosigner calls all go through [gate].
  ///
  /// The ASP is a separate party, reached directly and not through the enclave.
  MpcClient client(
    EnclaveGate gate, {
    required String aspHost,
    required int aspPort,
    bool aspSecure = false,
    String? storageId,
  }) =>
      MpcClient.enclave(
        gate: gate,
        aspHost: aspHost,
        aspPort: aspPort,
        aspSecure: aspSecure,
        storageId: storageId,
      );

  /// The runtime writes its log with colour, and the escapes land between the field name and its
  /// value — `pcr0` and `=8f20…` are separated by a reset sequence — so a pattern that reads like
  /// the text on screen matches nothing.
  static final _ansi = RegExp(r'\x1B\[[0-9;]*[a-zA-Z]');

  String _fromConsole(RegExp pattern) {
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
