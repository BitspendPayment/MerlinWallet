/// The message shapes the cosigner's unary calls carry.
///
/// No service here any more: `mpc_wallet.proto` stopped declaring one when the cosigner collapsed
/// to a single `cosigner.v1.Cosigner`. What is left is the request and response types those calls
/// use, which `cosign_session.proto` imports.
///
/// The service itself is in `cosigner_v1.dart`, and the ASP's in `ark_v1.dart`. Three entry points
/// rather than one flat re-export, because the packages define messages with overlapping names.
library;

export 'src/generated/mpc_wallet.pb.dart';
export 'src/generated/mpc_wallet.pbenum.dart';
export 'src/generated/mpc_wallet.pbjson.dart';
