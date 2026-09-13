/// The cosigner's API, `cosigner.v1`, generated from `protocol/protos/cosign_session.proto`.
///
/// A separate entry point from `protocol.dart` for the same reason `ark_v1.dart` is: the three
/// packages define messages with overlapping names. Import with a prefix:
///
/// ```dart
/// import 'package:protocol/cosigner_v1.dart' as cs;
/// ```
///
/// The message shapes the unary calls carry still live in `mpc_wallet.proto` and come from
/// `protocol.dart`; this exports the service and the four session message families.
library;

export 'src/generated/cosign_session.pb.dart';
export 'src/generated/cosign_session.pbgrpc.dart';
