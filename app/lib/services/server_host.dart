/// Where to reach the cosigner and the ASP, and whether the cosigner must prove
/// it is running inside a Nitro enclave before we talk to it.
///
/// Shared by [MpcService] (foreground) and the FCM background isolate in
/// `push_service.dart`, which previously carried its own copy of the URL rule.
///
/// The ASP endpoint is new here. The cosigner used to hold that connection and
/// relay it — `GetArkInfo`, `ListVtxos` and the batch round all went through it
/// — so the app never needed to know where the ASP was. A guest has no egress
/// at all, so the app talks to the ASP itself and the address has to come from
/// somewhere: it is pinned per cosigner host, not discovered, because an ASP
/// the cosigner did not expect is an ASP whose VTXOs it will refuse to sign for.
library;

/// Dev/loopback addresses. The runtime is a bare process on a workstation
/// here — plaintext gRPC, and no enclave to attest.
///
/// `10.0.2.2` is the Android emulator's alias for the host machine;
/// `127.0.0.1` is how a physical phone reaches it over `adb reverse`.
bool isLocalHost(String host) =>
    host == '127.0.0.1' ||
    host == 'localhost' ||
    host == '10.0.2.2' ||
    host.startsWith('192.168.');

/// Remote deployments that are deliberately NOT enclave-backed, and so cannot
/// produce an attestation document.
///
/// This is a WAIVER list, not an opt-in list — [requiresAttestation] demands
/// attestation for every host that is not named here or covered by
/// [isLocalHost], so an unrecognised host fails CLOSED.
///
/// The inverse spelling ("attest only when host == the production hostname")
/// would fail OPEN: `serverHost` is persisted in Hive and rewritten by
/// `MpcService.setHost`, so any other value — a typo, a stale box, a tampered
/// one — would silently downgrade to unattested plain REST against a server of
/// someone else's choosing. Adding a host here is a deliberate, reviewable act.
const Set<String> _unattestedRemoteHosts = {
  // mutinynet (signet). The cosigner runs directly on the EC2 host with its
  // store on an EBS volume; there is no enclave in front of it yet, so there is
  // no PCR0 to verify and nothing serving an attestation document.
  // Signet coins only. When the enclave fronts this deployment, delete this
  // entry — that is the whole change needed to switch attestation back on.
  'mutiny.vtxos.network',
};

/// Whether [host] must present a verified Nitro attestation (matching PCR0,
/// with the response-signing key bound to the attested image) before the app
/// will exchange any wallet traffic with it.
///
/// True for every remote host except the explicitly waived ones above — in
/// particular TRUE for `mainnet.vtxos.network`, and true for any host nobody
/// has classified yet.
bool requiresAttestation(String host) =>
    !isLocalHost(host) && !_unattestedRemoteHosts.contains(host);

/// An endpoint to dial: a host, a port, and whether to use TLS.
class Endpoint {
  const Endpoint(this.host, this.port, {this.secure = false});
  final String host;
  final int port;
  final bool secure;

  @override
  String toString() => '${secure ? 'https' : 'http'}://$host:$port';
}

/// The cosigner's gRPC endpoint.
///
/// Port 7075, not the old 7074: that was the REST listener, and the cosigner
/// serves one gRPC service now. Local dev is plaintext; anything remote is TLS
/// on 443, terminated by whatever fronts the guest — the component itself has
/// no listener and no certificate.
Endpoint cosignerEndpoint(String host) => isLocalHost(host)
    ? Endpoint(host, 7075)
    : Endpoint(host, 443, secure: true);

/// The runtime's own HTTP surface, for the things that are not the cosigner.
///
/// Passkey enrolment and assertion live here, not in the guest: verifying an
/// assertion needs the stored credential, the issued challenge, the relying-party
/// configuration and the ability to mark that challenge used — all four live in
/// the runtime, and a guest is given standard WASI and no host function to ask
/// through. The deployment manifest is fetched over this too.
String hostBaseUrl(String host) =>
    isLocalHost(host) ? 'http://$host:7074' : 'https://$host';

/// The ASP this cosigner's wallet settles against.
///
/// Pinned per cosigner host rather than configurable, and deliberately: the
/// cosigner derives every output it signs from the ASP's signer key, so pointing
/// the app at a different ASP does not redirect funds — it produces VTXOs the
/// cosigner will not recognise as its own. Getting it wrong is a wallet that
/// reads as empty, which is worth failing loudly for rather than defaulting.
Endpoint aspEndpoint(String host) {
  if (isLocalHost(host)) {
    // The regtest arkd from docker-compose.ark.yml, reached the same way the
    // cosigner is — `10.0.2.2` on the emulator, `127.0.0.1` over adb reverse.
    return Endpoint(host, 7070);
  }
  if (host == 'mutiny.vtxos.network') {
    return const Endpoint('mutinynet.arkade.sh', 443, secure: true);
  }
  throw StateError(
    'no ASP configured for cosigner host "$host" — add one in server_host.dart '
    'rather than guessing, since the wrong ASP reads as an empty wallet',
  );
}
