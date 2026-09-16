/// Where an enclave is, as two separate things: the address a socket goes to, and the name its
/// certificate is issued for.
///
/// They coincide in production. They do not for a dev enclave, which listens on loopback while its
/// certificate says `enclave.test` — a URL naming the address fails hostname verification, and one
/// naming the certificate does not resolve. Carrying both is what lets every connection dial one
/// and verify the other, the same separation `--url` and `--rp-id` have in `passkey-client`.
library;

import 'dart:io';

class EnclaveEndpoint {
  EnclaveEndpoint({
    required this.host,
    required this.port,
    String? authority,
    this.extraRoots,
  }) : authority = authority ?? host;

  /// Production: one name for both, on 443, under the public roots.
  EnclaveEndpoint.public(String host, {int port = 443}) : this(host: host, port: port);

  /// Where the socket goes.
  final String host;
  final int port;

  /// The name the certificate is verified against, sent as SNI and as HTTP/2's `:authority`.
  final String authority;

  /// A PEM root to trust in addition to the system's — Pebble's, for a dev enclave. Added to, not
  /// replacing, the system store, so this is not a pin; the attested certificate is.
  final List<int>? extraRoots;

  /// The base URL for `/auth/*`, by name.
  String get baseUrl => port == 443 ? 'https://$authority' : 'https://$authority:$port';

  SecurityContext securityContext() {
    final context = SecurityContext(withTrustedRoots: true);
    final roots = extraRoots;
    if (roots != null) context.setTrustedCertificatesBytes(roots);
    return context;
  }

  /// A TLS socket to [host], verified as [authority].
  Future<SecureSocket> connect({Duration? timeout}) async {
    final raw = await Socket.connect(host, port, timeout: timeout);
    // Don't wait for buffers to fill before sending: gRPC frames are small and interactive.
    raw.setOption(SocketOption.tcpNoDelay, true);
    return SecureSocket.secure(raw, host: authority, context: securityContext());
  }
}
