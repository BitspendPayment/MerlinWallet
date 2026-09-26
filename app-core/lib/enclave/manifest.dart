/// Deployment manifest fetching: what a remote enclave should measure to.
///
/// A deployment publishes a `deployment.json` with the image's PCR0 and the cosigner component's
/// PCR16. The app pins both — PCR0 alone says which runtime, not which guest that runtime is
/// serving.
///
/// An emulated enclave (the MutinyNet host) also publishes `trust_root`: the root its attestation
/// documents chain to, which it mints at every boot, and `host`, the name it serves. Real Nitro
/// publishes neither; its root is AWS's.
library;

import 'dart:convert';
import 'package:http/http.dart' as http;

/// Deployment manifest from GitHub Releases.
class DeploymentManifest {
  final String baseUrl;
  final String pcr0;
  final String pcr16;
  final String pcr1;
  final String pcr2;
  final String timestamp;
  final String commit;
  final String repo;

  /// The host this deployment serves. Empty in a manifest that does not say.
  final String host;

  /// DER of the attestation root, for an emulated enclave. Null means AWS's.
  final List<int>? trustRoot;

  /// The WebAuthn relying party the image was built with. Empty when not published.
  final String rpId;

  DeploymentManifest({
    required this.baseUrl,
    required this.pcr0,
    this.pcr16 = '',
    this.pcr1 = '',
    this.pcr2 = '',
    this.timestamp = '',
    this.commit = '',
    this.repo = '',
    this.host = '',
    this.trustRoot,
    this.rpId = '',
  });

  factory DeploymentManifest.fromJson(Map<String, dynamic> json) {
    return DeploymentManifest(
      baseUrl: json['base_url'] as String? ?? '',
      pcr0: json['pcr0'] as String? ?? '',
      pcr16: json['pcr16'] as String? ?? '',
      pcr1: json['pcr1'] as String? ?? '',
      pcr2: json['pcr2'] as String? ?? '',
      timestamp: json['timestamp'] as String? ?? '',
      commit: json['commit'] as String? ?? '',
      repo: json['repo'] as String? ?? '',
      host: json['host'] as String? ?? '',
      trustRoot: switch (json['trust_root']) {
        final String b64 when b64.isNotEmpty => base64.decode(b64),
        _ => null,
      },
      rpId: json['rp_id'] as String? ?? '',
    );
  }
}

/// Construct the GitHub Releases URL for a deployment manifest.
String manifestUrl(String repo, String tag) {
  return 'https://github.com/$repo/releases/download/$tag/deployment.json';
}

/// Fetch the deployment manifest published at [url].
Future<DeploymentManifest> fetchManifestFrom(Uri url, {http.Client? client}) async {
  final resp = await (client?.get(url) ?? http.get(url));
  if (resp.statusCode != 200) {
    throw Exception('Failed to fetch manifest from $url: HTTP ${resp.statusCode}');
  }
  return DeploymentManifest.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
}

/// Fetch the deployment manifest from GitHub Releases.
///
/// [repo] - GitHub repo (e.g. "BitspendPayment/MPCWallet")
/// [tag] - Release tag (e.g. "eif-latest")
Future<DeploymentManifest> fetchManifest(String repo,
    {String tag = 'eif-latest'}) async {
  final url = manifestUrl(repo, tag);
  final resp = await http.get(Uri.parse(url));
  if (resp.statusCode != 200) {
    throw Exception('Failed to fetch manifest from $url: HTTP ${resp.statusCode}');
  }
  final json = jsonDecode(resp.body) as Map<String, dynamic>;
  return DeploymentManifest.fromJson(json);
}
