/// Deployment manifest fetching: what a remote enclave should measure to.
///
/// The enclave build publishes a `deployment.json` to GitHub Releases with the image's PCR0 and the
/// cosigner component's PCR16. The app pins both — PCR0 alone says which runtime, not which guest
/// that runtime is serving.
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

  DeploymentManifest({
    required this.baseUrl,
    required this.pcr0,
    this.pcr16 = '',
    this.pcr1 = '',
    this.pcr2 = '',
    this.timestamp = '',
    this.commit = '',
    this.repo = '',
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
    );
  }
}

/// Construct the GitHub Releases URL for a deployment manifest.
String manifestUrl(String repo, String tag) {
  return 'https://github.com/$repo/releases/download/$tag/deployment.json';
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
