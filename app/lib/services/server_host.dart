/// Where a cosigner host's enclave and ASP are, and what the app pins about the enclave.
///
/// **Every cosigner is inside an enclave now.** It is a Wasm component with no listener of its
/// own; enclave-runtime owns the socket, gates every request on a passkey, and attests itself on
/// every approval. So there is no longer a list of hosts waived from attestation, nor a plaintext
/// local port: a host with no enclave in front of it has no cosigner to reach at all.
///
/// The ASP is the one party reached directly. A guest has no egress, so the app talks to arkd
/// itself, and the address is pinned per cosigner host rather than discovered: an ASP the cosigner
/// did not expect is an ASP whose VTXOs it will refuse to sign for.
library;

import 'dart:convert';

import 'package:app_core/enclave/attestation.dart';
import 'package:app_core/enclave/endpoint.dart';

/// Dev/loopback addresses: a dev enclave (`dev-enclave.sh`) on the workstation.
///
/// `10.0.2.2` is the Android emulator's alias for the host machine;
/// `127.0.0.1` is how a physical phone reaches it over `adb reverse`.
bool isLocalHost(String host) =>
    host == '127.0.0.1' ||
    host == 'localhost' ||
    host == '10.0.2.2' ||
    host.startsWith('192.168.');

/// A dev enclave's per-boot values, passed at build time — `make flutter` reads them from the
/// enclave's run directory. A dev enclave mints a new trust root every boot and its certificate
/// comes from Pebble, so none of this can be baked in.
class DevEnclaveConfig {
  const DevEnclaveConfig({
    this.port = 8443,
    this.certificateName = 'enclave.test',
    this.rpId = 'enclave.test',
    this.caPemBase64 = '',
    this.trustRootBase64 = '',
    this.pcr0 = '',
    this.pcr16 = '',
  });

  static const fromDefines = DevEnclaveConfig(
    port: int.fromEnvironment('DEV_ENCLAVE_PORT', defaultValue: 8443),
    certificateName: String.fromEnvironment('DEV_ENCLAVE_CERT_NAME', defaultValue: 'enclave.test'),
    rpId: String.fromEnvironment('DEV_ENCLAVE_RP_ID', defaultValue: 'enclave.test'),
    caPemBase64: String.fromEnvironment('DEV_ENCLAVE_CA_B64'),
    trustRootBase64: String.fromEnvironment('DEV_ENCLAVE_TRUST_ROOT_B64'),
    pcr0: String.fromEnvironment('DEV_ENCLAVE_PCR0'),
    pcr16: String.fromEnvironment('DEV_ENCLAVE_PCR16'),
  );

  final int port;

  /// The name on the dev certificate: what TLS verifies, whatever the address dialled.
  final String certificateName;

  /// The WebAuthn relying party the dev image was built with (`dev-enclave.sh --rp-id`). For a phone
  /// it has to be a domain whose assetlinks.json names the app — `make up-enclave` boots one with
  /// `vtxos.com` — since Android creates no passkey for `enclave.test`.
  final String rpId;
  final String caPemBase64;
  final String trustRootBase64;
  final String pcr0;
  final String pcr16;

  /// This boot's pins. Refuses rather than guessing: a dev build without them has nothing to
  /// verify the enclave against, and an unverified enclave is exactly what pinning exists to stop.
  EnclavePins pins() {
    if (trustRootBase64.isEmpty || pcr0.length != 96 || pcr16.length != 96) {
      throw StateError(
        'this build has no dev enclave pins — build with `make flutter`, which passes the running '
        "enclave's DEV_ENCLAVE_TRUST_ROOT_B64, DEV_ENCLAVE_PCR0 and DEV_ENCLAVE_PCR16",
      );
    }
    return EnclavePins(trustRoot: base64.decode(trustRootBase64), pcr0: pcr0, pcr16: pcr16);
  }
}

/// The enclave serving [host]'s cosigner.
///
/// Remote: the host itself, on 443, under the public roots. Local: the dev enclave's port on that
/// address, verified as its certificate's name, under Pebble's root.
EnclaveEndpoint enclaveEndpoint(String host, {DevEnclaveConfig dev = DevEnclaveConfig.fromDefines}) =>
    isLocalHost(host)
        ? EnclaveEndpoint(
            host: host,
            port: dev.port,
            authority: dev.certificateName,
            extraRoots: dev.caPemBase64.isEmpty ? null : base64.decode(dev.caPemBase64),
          )
        : EnclaveEndpoint.public(host);

/// The relying party every production passkey is bound to.
///
/// One domain for every deployment, not each cosigner host: a platform authenticator only creates a
/// passkey for an rp id whose domain publishes Digital Asset Links naming this app, and
/// `https://vtxos.com/.well-known/assetlinks.json` is where `com.vtxos.app` is named, with
/// `get_login_creds`. The deployments live under `vtxos.network`, which publishes none.
///
/// The rp id is the enclave's setting (`--webauthn-rp-id`), independent of the name it is served
/// under, so each deployment's enclave must be configured with this one — its assertions are
/// checked against it.
const String productionRpId = 'vtxos.com';

/// The WebAuthn relying party for [host] — the domain a passkey is bound to.
///
/// A dev enclave's is baked into its image (`enclave.test`), and publishes no asset links, so a
/// phone cannot register against one; the software authenticator in the e2e suite and the CLI can.
String relyingPartyId(String host, {DevEnclaveConfig dev = DevEnclaveConfig.fromDefines}) =>
    isLocalHost(host) ? dev.rpId : productionRpId;

/// What an assertion for [host] claims as its origin — see `EnclaveGate.origin`.
String origin(String host, {DevEnclaveConfig dev = DevEnclaveConfig.fromDefines}) =>
    'https://${relyingPartyId(host, dev: dev)}';

/// An endpoint to dial: a host, a port, and whether to use TLS.
class Endpoint {
  const Endpoint(this.host, this.port, {this.secure = false});
  final String host;
  final int port;
  final bool secure;

  @override
  String toString() => '${secure ? 'https' : 'http'}://$host:$port';
}

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
    // enclave is — `10.0.2.2` on the emulator, `127.0.0.1` over adb reverse.
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
