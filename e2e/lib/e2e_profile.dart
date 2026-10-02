/// The one image this suite runs against, named in one place.
///
/// Everything here is measured into the enclave's PCR0 — the escrow service's identifier and
/// origin, the ASP's, the renewal margin, the background-task budget — so it has to be decided
/// before the enclave boots, and a prebuilt bundle has to have been packed with exactly it. The
/// harness passes these options when it builds the image itself, checks a bundle's `image.env`
/// against them when it does not, and `bin/bundle_args.dart` prints them for the runtime's
/// "Publish a dev enclave" workflow. One definition, three readers, no drift.
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

/// The fake Grid's view-only token, `id:secret`. It goes into the image, which is measured and
/// readable like everything else here — a fake has nothing to protect, and a real token never goes
/// into a test image.
const fakeGridViewToken = 'dev-view:dev-view-secret';

/// `<id>:<origin>` per service, `_` between them, with the host as the guest sees it. `:` rather
/// than `=`, and `_` rather than `,`, because `dev-enclave.sh` validates a `--guest-env` value
/// against `[A-Za-z0-9:/._-]`.
String get serviceOrigins => '$serviceIdentifierHex:http://192.168.127.254:$servicePort'
    '_$platformIdentifierHex:http://192.168.127.254:$platformPort';

/// What the cosigner may reach besides the services: the fake Grid, for its evidence.
const e2eExtraEgress = [gridOriginFromEnclave];

/// The Grid credential, bound to the fake's origin so it is sent there and nowhere else.
const e2eExtraEnv = {
  'SERVICE_CREDENTIALS_GRID': fakeGridViewToken,
  'SERVICE_CREDENTIAL_ORIGIN_GRID': gridOriginFromEnclave,
};

/// The image options, exactly as [startE2eEnclave] passes them.
List<String> e2eImageOptions() => EnclaveHarness.imageOptions(
    serviceOrigins: serviceOrigins, extraEgress: e2eExtraEgress, extraEnv: e2eExtraEnv);

/// Boot (or attach to) the one enclave every e2e test and walkthrough runs against.
Future<EnclaveHarness> startE2eEnclave() => EnclaveHarness.start(
    serviceOrigins: serviceOrigins, extraEgress: e2eExtraEgress, extraEnv: e2eExtraEnv);

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
