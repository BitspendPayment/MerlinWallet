/// Putting an approval on every gRPC call.
///
/// enclave-runtime binds an approval to one **method, path and query**, so a token is minted per
/// call and cannot be shared between two. gRPC is always POST and its path carries no query, so the
/// scope is the path alone.
///
/// The approval is minted **before** the call is handed to grpc-dart, not inside it. grpc-dart's own
/// hook for async metadata, `MetadataProvider`, runs after a connection is ready and before the
/// request is written, and does not recheck the connection in between: if the transport goes while
/// a mint is out — two round trips and a signature — `makeRequest` dereferences a connection that
/// is no longer there and the call fails as `UNAVAILABLE: Null check operator used on a null value`,
/// or never reaches the wire at all. With the metadata already in hand, dispatch and write happen in
/// one turn and grpc-dart's reconnect logic sees a dead transport before it tries to use one.
///
/// One token per call also means one per *stream*, not one per message: the runtime redeems at
/// open and never looks again, which is what lets a renewal run for minutes on one approval.
library;

import 'gate.dart';

/// The metadata that lets one call to [path] through.
typedef Approver = Future<Map<String, String>> Function(String path);

/// An [Approver] that asks [gate] for a fresh token each call.
Approver gateApprover(EnclaveGate gate) => (path) async {
      final token = await gate.mint(method: 'POST', path: path);
      return {
        // Required on every request, gate or no gate, and checked before routing: without it the
        // runtime answers 400 and the guest never runs.
        'x-enclave-nonce': EnclaveGate.nonce(),
        'authorization': 'Bearer ${token.token}',
      };
    };
