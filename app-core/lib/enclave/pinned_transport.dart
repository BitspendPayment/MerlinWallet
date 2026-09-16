/// The cosigner's channel, held to the certificate the gate attested.
///
/// Guest responses carry no attestation document — only `/auth/*` ones do. What makes a gRPC call
/// as trustworthy as the exchange that approved it is that it lands on a socket serving the **same
/// certificate**: the one whose hash the document bound, and so the one whose private key only the
/// attested enclave holds. The runtime refuses TLS session resumption so that every connection
/// presents it in full.
///
/// grpc-dart has no hook for "check the peer certificate of a connection that validated fine", so
/// this replaces its socket connector: dial, handshake, compare, and only then hand the socket to
/// HTTP/2. A mismatch never gets as far as writing a request.
library;

import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:grpc/grpc.dart';
import 'package:http2/transport.dart';

import 'attestation.dart';
import 'endpoint.dart';
import 'gate.dart';

class PinnedTransportConnector implements ClientTransportConnector {
  PinnedTransportConnector(this.endpoint, this.gate);

  final EnclaveEndpoint endpoint;
  final EnclaveGate gate;
  SecureSocket? _socket;

  @override
  Future<ClientTransportConnection> connect() async {
    // Every call is approved before it is dispatched, and approving attests — so this is normally
    // already set. Attesting here covers a connection opened some other way.
    final pinned = gate.attested ?? await gate.attest();

    final socket = await endpoint.connect();
    final served = socket.peerCertificate;
    final servedHash = served == null ? null : crypto.sha256.convert(served.der).toString();
    if (servedHash != pinned.certificateSha256) {
      socket.destroy();
      // A renewal looks exactly like this, and so does an interception. Re-attesting tells them
      // apart: a renewed certificate comes with a document that binds it, and the next call dials
      // against that.
      await gate.attest().catchError((Object _) => pinned);
      throw AttestationException(
        'the cosigner served certificate $servedHash, not the attested ${pinned.certificateSha256}',
      );
    }
    _socket = socket;
    return ClientTransportConnection.viaSocket(socket);
  }

  @override
  Future get done => _socket?.done ?? Future.value();

  @override
  void shutdown() => _socket?.destroy();

  @override
  String get authority => endpoint.authority;
}
