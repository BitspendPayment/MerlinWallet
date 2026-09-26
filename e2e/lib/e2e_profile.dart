/// The one image this suite runs against, named in one place.
///
/// Everything here is measured into the enclave's PCR0 — the escrow service's identifier and
/// origin, the ASP's, the renewal margin, the background-task budget — so it has to be decided
/// before the enclave boots, and a prebuilt bundle has to have been packed with exactly it. The
/// harness passes these options when it builds the image itself, checks a bundle's `image.env`
/// against them when it does not, and `bin/bundle_args.dart` prints them for the runtime's
/// "Publish a dev enclave" workflow. One definition, three readers, no drift.
library;

import 'dart:typed_data';

import 'package:app_core/threshold_types.dart' as threshold;

import 'enclave_harness.dart';

/// Where the escrow service the tests pair with listens, on the host.
const servicePort = 7099;

/// Its identifier: a fixed label, so the image can name it before the service exists.
final threshold.Identifier serviceIdentifier =
    threshold.Identifier.derive(Uint8List.fromList('merlin-e2e-escrow-service'.codeUnits));

String get serviceIdentifierHex =>
    serviceIdentifier.serialize().map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// `<id>:<origin>`, with the host as the guest sees it. `:` rather than `=` between them because
/// `dev-enclave.sh` validates a `--guest-env` value against `[A-Za-z0-9:/._-]`.
String get serviceOrigins => '$serviceIdentifierHex:http://192.168.127.254:$servicePort';

/// The image options, exactly as [EnclaveHarness.start] passes them.
List<String> e2eImageOptions() => EnclaveHarness.imageOptions(serviceOrigins: serviceOrigins);
