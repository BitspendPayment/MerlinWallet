/// Attested REST transport. Dart owns HTTP (`package:http`); the Rust
/// FFI is called only for the crypto-heavy work: COSE_Sign1 / X.509
/// verification of the attestation document, and BIP-340 Schnorr
/// verification of each response.
///
/// Per-request flow:
///   1. ensure attestation cache is fresh (re-verify on TTL expiry)
///   2. POST `<baseUrl>/<path>` via `package:http`
///   3. read `X-Attestation-Signature` header
///   4. FFI `verify_schnorr_signature(body, sig, pubkey)` (sub-ms)
///   5. parse body as JSON, return
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:http/http.dart' as http;
import 'package:protocol/protocol.dart';

import 'enclave/native_enclave.dart';
import 'rest_wallet_api.dart';
import 'wallet_api.dart';

const int _nonceLen = 20;

/// `WalletApi` whose every response is bound to an attested enclave.
class AttestedWalletApi implements WalletApi {
  final _Attested _attested;
  final RestWalletApi _inner;

  AttestedWalletApi._(this._attested, this._inner);

  /// Build an attested client and run an initial verification.
  ///
  /// Throws if the enclave is unreachable, the document fails to verify,
  /// or PCR0 doesn't match [expectedPcr0].
  static Future<AttestedWalletApi> create(
    String baseUrl, {
    required String expectedPcr0,
    int cacheTtlSecs = 60,
    http.Client? httpClient,
  }) async {
    final attested = _Attested(
      baseUrl: baseUrl,
      expectedPcr0: expectedPcr0,
      ttl: Duration(seconds: cacheTtlSecs),
      httpClient: httpClient ?? http.Client(),
    );
    await attested.verify();

    final inner = RestWalletApi.withPostFn(baseUrl, (path, body) async {
      // Retry once on transient HTTP / signature-verify failures, matching
      // the prior behavior. A second consecutive failure propagates.
      Object? lastErr;
      for (var attempt = 0; attempt < 2; attempt++) {
        try {
          return await attested.post(path, body);
        } catch (e) {
          lastErr = e;
        }
      }
      throw Exception('Enclave request failed: $lastErr');
    });

    return AttestedWalletApi._(attested, inner);
  }

  /// Cached attestation status for UI display. Synchronous — no FFI call.
  Future<AttestationStatus> getAttestationStatus() async => _attested.status;

  // ── WalletApi delegation ───────────────────────────────────────────
  @override Future<DKGStep1Response> dKGStep1(DKGStep1Request r) => _inner.dKGStep1(r);
  @override Future<DKGStep2Response> dKGStep2(DKGStep2Request r) => _inner.dKGStep2(r);
  @override Future<DKGStep3Response> dKGStep3(DKGStep3Request r) => _inner.dKGStep3(r);
   @override Future<SignStep1Response> signStep1(SignStep1Request r, {String? routeGroupKeyHex}) => _inner.signStep1(r, routeGroupKeyHex: routeGroupKeyHex);
  @override Future<SignStep2Response> signStep2(SignStep2Request r, {String? routeGroupKeyHex}) => _inner.signStep2(r, routeGroupKeyHex: routeGroupKeyHex);
  @override Future<GetArkInfoResponse> getArkInfo(GetArkInfoRequest r) => _inner.getArkInfo(r);
  @override Future<GetArkAddressResponse> getArkAddress(GetArkAddressRequest r) => _inner.getArkAddress(r);
  @override Future<GetBoardingAddressResponse> getBoardingAddress(GetBoardingAddressRequest r) => _inner.getBoardingAddress(r);
  @override Future<ListVtxosResponse> listVtxos(ListVtxosRequest r) => _inner.listVtxos(r);
   @override Future<SendVtxoResponse> sendVtxo(SendVtxoRequest r) => _inner.sendVtxo(r);
  @override Future<RedeemVtxoResponse> redeemVtxo(RedeemVtxoRequest r) => _inner.redeemVtxo(r);
  @override Future<SettleResponse> settle(SettleRequest r) => _inner.settle(r);
  @override Future<SettleDelegateResponse> settleDelegate(SettleDelegateRequest r) => _inner.settleDelegate(r);
  @override Future<SubmitArkSendResponse> submitArkSend(SubmitArkSendRequest r) => _inner.submitArkSend(r);
  // Request-to-pay — plain delegation; the attestation guarantees apply to the transport.
  @override Future<ContactAddResponse> contactAdd(ContactAddRequest r) => _inner.contactAdd(r);
  @override Future<ContactRemoveResponse> contactRemove(ContactRemoveRequest r) => _inner.contactRemove(r);
  @override Future<ContactListResponse> contactList(ContactListRequest r) => _inner.contactList(r);
  @override Future<PaymentRequestCreateResponse> createPaymentRequest(PaymentRequestCreateRequest r, String payerGroupKeyHex) => _inner.createPaymentRequest(r, payerGroupKeyHex);
  @override Future<PaymentRequestListResponse> paymentRequestList(PaymentRequestListRequest r) => _inner.paymentRequestList(r);
  @override Future<PaymentRequestDeclineResponse> paymentRequestDecline(PaymentRequestDeclineRequest r) => _inner.paymentRequestDecline(r);
  @override Future<GetServerInfoResponse> getServerInfo(GetServerInfoRequest r) => _inner.getServerInfo(r);
   @override
  Future<void> shutdown() async {
    _attested.dispose();
  }
}

// ── Internals ────────────────────────────────────────────────────────

class _AttestationCache {
  final String pcr0;
  final String attestationKey;
  final DateTime verifiedAt;
  _AttestationCache({
    required this.pcr0,
    required this.attestationKey,
    required this.verifiedAt,
  });
}

class _Attested {
  final String baseUrl;
  final String expectedPcr0;
  final Duration ttl;
  final http.Client _http;
  final Random _rng = Random.secure();

  /// In-flight verify guard: dedupe concurrent re-verifications so the
  /// first request after TTL expiry triggers one HTTP round-trip, not N.
  Future<_AttestationCache>? _verifyInFlight;
  _AttestationCache? _cache;

  _Attested({
    required this.baseUrl,
    required this.expectedPcr0,
    required this.ttl,
    required http.Client httpClient,
  }) : _http = httpClient;

  void dispose() {
    _http.close();
  }

  AttestationStatus get status {
    final c = _cache;
    if (c == null) return AttestationStatus.unverified();
    final remaining = ttl - _elapsedSince(c.verifiedAt);
    return AttestationStatus(
      verified: true,
      pcr0: c.pcr0,
      verifiedAtEpochSecs: c.verifiedAt.millisecondsSinceEpoch ~/ 1000,
      ttlRemainingSecs:
          remaining.isNegative ? 0 : remaining.inSeconds,
      attestationKey: c.attestationKey,
    );
  }

  Future<_AttestationCache> _ensureFresh() {
    final c = _cache;
    if (c != null && _elapsedSince(c.verifiedAt) < ttl) {
      return Future.value(c);
    }
    return verify();
  }

  /// Wall-clock elapsed time, clamped to zero on backward clock jumps
  /// (NTP correction, manual time change). A naive `now - verifiedAt`
  /// goes negative across a backward jump, which is harmless for the
  /// `< ttl` cache check but produces nonsense `ttlRemainingSecs`
  /// values in the UI (e.g. "300s remaining" on a 60s TTL). The clamp
  /// keeps both the cache decision and the UI status sane. The cache
  /// still self-heals across the next failed signature verify if the
  /// enclave actually rotated underneath us.
  Duration _elapsedSince(DateTime t) {
    final d = DateTime.now().difference(t);
    return d.isNegative ? Duration.zero : d;
  }

  /// Force a full attestation round-trip. Dedupes concurrent callers.
  Future<_AttestationCache> verify() {
    return _verifyInFlight ??= _doVerify().whenComplete(() {
      _verifyInFlight = null;
    });
  }

  Future<_AttestationCache> _doVerify() async {
    // 1. Fresh nonce so a replay of an older signed doc fails.
    final nonce = Uint8List.fromList(
        List<int>.generate(_nonceLen, (_) => _rng.nextInt(256)));
    final nonceHex = _hex(nonce);

    // 2. Fetch document.
    final docResp = await _http
        .get(Uri.parse('$baseUrl/enclave/attestation?nonce=$nonceHex'));
    if (docResp.statusCode != 200) {
      throw Exception(
          'attestation fetch HTTP ${docResp.statusCode}: ${docResp.body}');
    }
    final docBytes = _unwrapDocumentEnvelope(docResp.body);

    // 3. Hand to Rust for COSE/X.509/PCR0/nonce verification.
    final v = EnclaveVerifier.verifyAttestationDoc(
      docBytes: docBytes,
      expectedPcr0: expectedPcr0,
      nonce: nonce,
    );
    if (!v.ok) {
      throw Exception('attestation verify failed: ${v.error}');
    }

    // 4. Fetch the enclave's attestation pubkey and bind it via SHA256.
    final infoResp =
        await _http.get(Uri.parse('$baseUrl/v1/enclave-info'));
    if (infoResp.statusCode != 200) {
      throw Exception(
          'enclave-info HTTP ${infoResp.statusCode}: ${infoResp.body}');
    }
    final info = jsonDecode(infoResp.body) as Map<String, dynamic>;
    final pubkeyHex = (info['attestation_pubkey'] as String?) ?? '';
    if (pubkeyHex.isEmpty) {
      throw Exception('enclave reports no attestation pubkey');
    }
    // SECURITY: the appKeyHash binds the response-signing pubkey to the attested
    // enclave image (SHA256(attestation_pubkey) must equal the appKeyHash embedded
    // in the signed attestation UserData). This MUST fail closed: an empty /
    // unextractable appKeyHash previously skipped the check, which would let a
    // server present any `attestation_pubkey` and MITM every "attested" response.
    if (v.appKeyHash.isEmpty) {
      throw Exception(
          'attestation has no appKeyHash binding — refusing to trust the '
          'response-signing key (enclave must publish the sha256:tls;sha256:app '
          'UserData binding)');
    }
    final expected = sha256.convert(_unhex(pubkeyHex)).bytes;
    final got = _unhex(v.appKeyHash);
    if (!_constantTimeEq(expected, got)) {
      throw Exception(
          'appKeyHash mismatch: SHA256($pubkeyHex) != ${v.appKeyHash}');
    }

    final cache = _AttestationCache(
      pcr0: v.pcr0,
      attestationKey: pubkeyHex,
      verifiedAt: DateTime.now(),
    );
    _cache = cache;
    return cache;
  }

  /// Make a POST and verify the response signature. The path is
  /// relative to `baseUrl` (e.g. `/api/u/<id>/sign-step1`); the body is
  /// the JSON map RestWalletApi wants to send.
  Future<Map<String, dynamic>> post(
      String path, Map<String, dynamic> body) async {
    final cache = await _ensureFresh();

    final resp = await _http.post(
      Uri.parse('$baseUrl$path'),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );

    // Verify response signature. The server signs SHA256(body) with
    // BIP-340 Schnorr using the attestation pubkey.
    final sigHex = resp.headers['x-attestation-signature'] ?? '';
    if (sigHex.isEmpty) {
      throw Exception(
          'response missing X-Attestation-Signature header (HTTP ${resp.statusCode})');
    }
    final v = EnclaveVerifier.verifySchnorrSignature(
      body: resp.bodyBytes,
      sigHex: sigHex,
      pubkeyHex: cache.attestationKey,
    );
    if (!v.ok) {
      throw Exception('response signature verify failed: ${v.error}');
    }

    if (resp.statusCode != 200) {
      try {
        final err = jsonDecode(resp.body);
        throw Exception(err['error'] ?? 'HTTP ${resp.statusCode}: ${resp.body}');
      } catch (e) {
        if (e is Exception) rethrow;
        throw Exception('HTTP ${resp.statusCode}: ${resp.body}');
      }
    }
    if (resp.body.isEmpty) {
      throw Exception('empty response body (HTTP ${resp.statusCode})');
    }
    return jsonDecode(resp.body) as Map<String, dynamic>;
  }
}

/// The attestation endpoint may return raw base64 or `{"document": "..."}`.
/// Unwrap either to raw bytes.
Uint8List _unwrapDocumentEnvelope(String payload) {
  final trimmed = payload.trim();
  String b64;
  if (trimmed.startsWith('{')) {
    final json = jsonDecode(trimmed);
    if (json is Map<String, dynamic> && json['document'] is String) {
      b64 = json['document'] as String;
    } else {
      b64 = trimmed;
    }
  } else {
    b64 = trimmed;
  }
  return base64Decode(b64);
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Uint8List _unhex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

bool _constantTimeEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
