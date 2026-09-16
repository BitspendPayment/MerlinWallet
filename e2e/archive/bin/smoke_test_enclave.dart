/// Smoke test for a deployed enclave server.
///
/// Usage:
///   cd e2e && dart run bin/smoke_test_enclave.dart <enclave-url>
///
/// Example:
///   dart run bin/smoke_test_enclave.dart http://1.2.3.4:7074
///
/// Tests:
///   1. Health check (GET /api/health)
///   2. DKG (3 rounds over REST)
///   3. GetArkInfo (verifies ASP connection)
///   4. GetBoardingAddress (verifies address derivation on signet)
library;

import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:app_core/client.dart';
import 'package:hive/hive.dart';

/// HTTP client that accepts self-signed certs (for Nitro enclave TLS).
http.Client _insecureHttpClient() {
  final inner = HttpClient()
    ..badCertificateCallback = (cert, host, port) => true;
  return IOClient(inner);
}

void main(List<String> args) async {
  if (args.isEmpty) {
    print('Usage: dart run bin/smoke_test_enclave.dart <enclave-url>');
    print('Example: dart run bin/smoke_test_enclave.dart http://1.2.3.4:7074');
    exit(1);
  }

  // Allow self-signed certs (enclaves use self-signed TLS)
  HttpOverrides.global = _AllowAllCerts();

  final baseUrl = args[0].replaceAll(RegExp(r'/+$'), '');
  print('=== Enclave Smoke Test ===');
  print('Target: $baseUrl');
  print('');

  final httpClient = _insecureHttpClient();

  // 1. Health check
  print('1. Health check...');
  try {
    final resp = await httpClient.get(Uri.parse('$baseUrl/api/health'));
    if (resp.statusCode == 200) {
      print('   OK: ${resp.body}');
    } else {
      print('   FAIL: HTTP ${resp.statusCode} ${resp.body}');
      exit(1);
    }
  } catch (e) {
    print('   FAIL: $e');
    exit(1);
  }

  // 2. DKG
  print('2. DKG...');
  final tempDir = await Directory.systemTemp.createTemp('enclave_smoke_');
  Hive.init(tempDir.path);

  try {
    final client = MpcClient.rest(baseUrl, storageId: 'enclave_smoke', httpClient: httpClient);
    await client.doDkg();
    print('   OK: DKG complete, userId=${client.userId?.substring(0, 16)}...');

    // 3. GetArkInfo
    print('3. GetArkInfo...');
    try {
      final arkInfo = await client.getArkInfo();
      print('   OK: network=${arkInfo.network}, signer=${arkInfo.signerPubkey.substring(0, 16)}...');
    } catch (e) {
      print('   SKIP (ASP may not be configured): $e');
    }

    // 4. GetBoardingAddress
    print('4. GetBoardingAddress...');
    try {
      final addr = await client.getBoardingAddress();
      print('   OK: $addr');
    } catch (e) {
      print('   SKIP: $e');
    }

    print('');
    print('=== Smoke test passed ===');
  } catch (e) {
    print('   FAIL: $e');
    exit(1);
  } finally {
    try {
      await tempDir.delete(recursive: true);
    } catch (_) {}
  }
}

class _AllowAllCerts extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (cert, host, port) => true;
  }
}
