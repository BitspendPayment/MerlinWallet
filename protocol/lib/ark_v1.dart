/// The ASP's own API, `ark.v1`, generated from `crates/ark/proto/ark/v1/`.
///
/// A separate entry point from `protocol.dart` on purpose. The cosigner and the ASP both define
/// messages with names like `Vtxo` and `Outpoint`, and a flat re-export would make every use of one
/// ambiguous. Import this with a prefix:
///
/// ```dart
/// import 'package:protocol/ark_v1.dart' as ark;
/// ```
///
/// Generated from the Rust crate's protos rather than a copy under `protocol/protos/`:
/// `crates/ark/build.rs` compiles from there, and a second copy is a second source of truth that
/// drifts without either side noticing.
library;

export 'src/generated/ark/v1/types.pb.dart';
export 'src/generated/ark/v1/service.pb.dart';
export 'src/generated/ark/v1/service.pbgrpc.dart';
export 'src/generated/ark/v1/indexer.pb.dart';
export 'src/generated/ark/v1/indexer.pbgrpc.dart';
