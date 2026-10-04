/// The one cosigner deployment this suite runs against, named in one place.
///
/// These are the cosigner's settings — the escrow services' identifiers and origins, the ASP, the
/// renewal margin, the fake Grid's credential — and they travel in the guest file: the harness
/// passes them as `--guest-env` when it boots an enclave, `dev-enclave.sh` writes them into the
/// component before uploading it, and the enclave measures them into PCR16 with the code. So any
/// dev bundle serves this suite; nothing about it is baked into the image.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:app_core/threshold_types.dart' as threshold;

import 'enclave_harness.dart';

/// Where the escrow service the tests pair with listens, on the host.
const servicePort = 7099;

/// Its identifier: a fixed label, so the image can name it before the service exists.
final threshold.Identifier serviceIdentifier =
    threshold.Identifier.derive(Uint8List.fromList('merlin-e2e-escrow-service'.codeUnits));

String get serviceIdentifierHex => _hex(serviceIdentifier.serialize());

/// Where the payout platform listens, on the host (MerlinPlatform's `--port`), and the fake Grid
/// it pays through (`fake_grid --port`).
const platformPort = 7200;
const fakeGridPort = 7300;

/// The platform's identifier. MerlinPlatform derives its own from the same label.
final threshold.Identifier platformIdentifier =
    threshold.Identifier.derive(Uint8List.fromList('merlin-platform'.codeUnits));

String get platformIdentifierHex => _hex(platformIdentifier.serialize());

/// Grid as the enclave reaches it: the fake, on the host. Every payout policy names this as its
/// provider, and it is the only origin the cosigner sends its Grid credential to.
const gridOriginFromEnclave = 'http://192.168.127.254:$fakeGridPort';

/// The fake Grid's view-only token, `id:secret`. It goes into the guest file, which is measured and
/// readable like everything else here — a fake has nothing to protect, and a real token never goes
/// into a test deployment.
const fakeGridViewToken = 'dev-view:dev-view-secret';

/// `<id>:<origin>` per service, `_` between them, with the host as the guest sees it. `:` rather
/// than `=`, and `_` rather than `,`, because `dev-enclave.sh` validates a `--guest-env` value
/// against `[A-Za-z0-9:/._-]`.
String get serviceOrigins => '$serviceIdentifierHex:http://192.168.127.254:$servicePort'
    '_$platformIdentifierHex:http://192.168.127.254:$platformPort';

/// The cosigner's settings, as [startE2eEnclave] deploys it with.
Map<String, String> get e2eSettings => {
      // The cosigner runs sealed delegates itself, against arkd on the host — 192.168.127.254 from
      // inside the enclave. The margin makes a delegate come due about five minutes after its
      // VTXOs were made (regtest VTXOs live 15360s), so a test can watch one run.
      'ASP_URL': 'http://192.168.127.254:7070',
      'AUTO_SETTLE_SAFETY_MARGIN_SECS': '15060',
      'SERVICE_ORIGINS': serviceOrigins,
      // The Grid credential, bound to the fake's origin so it is sent there and nowhere else.
      'SERVICE_CREDENTIALS_GRID': fakeGridViewToken,
      'SERVICE_CREDENTIAL_ORIGIN_GRID': gridOriginFromEnclave,
    };

/// Boot (or attach to) the one enclave every e2e test and walkthrough runs against.
Future<EnclaveHarness> startE2eEnclave() => EnclaveHarness.start(settings: e2eSettings);

String _hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Where the dev enclave that is up is described for the services that must believe it —
/// MerlinPlatform's `--enclave-pins`, in `deployment.json`'s shape. Relative to `e2e/`. One file,
/// because one enclave runs at a time.
const enclavePinsPath = '../.platform/run/enclave-pins.json';

/// Describe [harness]'s enclave to the services. After every boot: a dev enclave's root is new each
/// time, and a service reads the file again when it changes.
Future<void> writeEnclavePins(EnclaveHarness harness, {String path = enclavePinsPath}) async {
  await File(path).parent.create(recursive: true);
  final pending = File('$path.tmp');
  await pending.writeAsString(jsonEncode({
    'pcr0': harness.pcr0,
    'pcr16': harness.pcr16,
    'trust_root': base64Encode(await File(harness.trustRoot).readAsBytes()),
  }));
  await pending.rename(path);
}
