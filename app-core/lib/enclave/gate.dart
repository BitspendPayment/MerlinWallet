/// The runtime's front door.
///
/// **Nothing reaches the cosigner without a fresh approval.** enclave-runtime gates every request
/// on a WebAuthn assertion bound to that exact method, path and query, exchanged for a token that
/// is single-use and lives 60 seconds. Only `/auth/*` answers without one.
///
/// Four steps per request:
///
/// ```text
///   POST /auth/request/options   {credential_id, method, path, query}  -> {challenge_id, options}
///   sign the challenge                                                    (the Authenticator)
///   POST /auth/request/verify    {challenge_id, assertion}              -> {token, expires_in_secs}
///   the real request             authorization: Bearer <token>
/// ```
///
/// **And nothing is said to an enclave that has not proved what it is.** Every `/auth/*` response
/// carries an attestation document over the request's nonce, and every one is verified here against
/// [EnclavePins] and the certificate the socket was actually served, before its body is read. The
/// certificate it vouches for becomes [attested], which the cosigner's channel pins — guest responses
/// carry no document of their own.
///
/// Two things about the scope are worth stating, because both are enforced rather than advisory: a
/// token moved to another route is refused, and redeeming removes it *before* anything about it is
/// checked — so offering one for the wrong route spends it.
///
/// What 60 seconds bounds is the time to *start* an interaction, not how long one may run. A
/// bidirectional stream is approved once, at open, and then runs to completion.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart' as crypto;

import 'attestation.dart';
import 'authenticator.dart';
import 'endpoint.dart';

/// The runtime refused, and says almost nothing about why — deliberately: every refusal maps to one
/// message so the route cannot be used to tell one failure from another.
class GateException implements Exception {
  GateException(this.step, this.status, this.detail);
  final String step;
  final int status;
  final String detail;
  @override
  String toString() => 'enclave gate refused at $step ($status): $detail';
}

/// A minted interaction token and when it stops being worth offering.
class InteractionToken {
  InteractionToken(this.token, this.expiresAt);
  final String token;
  final DateTime expiresAt;
  bool get spent => DateTime.now().isAfter(expiresAt);
}

/// A passkey the runtime registered: a new tenant, and the credential that reaches it.
class Enrolment {
  Enrolment(this.tenantId, this.credentialId);
  final String tenantId;

  /// Base64url, unpadded. Every later assertion names it, so it has to be kept.
  final String credentialId;
}

/// Mints interaction tokens against one enclave, and attests it on every exchange.
class EnclaveGate {
  EnclaveGate({
    required this.endpoint,
    required EnclavePins pins,
    required this.origin,
    this.authenticator,
    this.refreshPins,
    ConnectionVerifier verifier = verifyConnection,
  })  : _pins = pins,
        _verifier = verifier {
    _http = HttpClient(context: endpoint.securityContext())
      ..connectionFactory = (uri, proxyHost, proxyPort) {
        // The TLS handshake happens here, not in `HttpClient`, so the socket can go to
        // `endpoint.host` while SNI and verification use `endpoint.authority`.
        return Future.value(ConnectionTask.fromSocket(endpoint.connect(), () {}));
      };
  }

  final EnclaveEndpoint endpoint;

  /// What the enclave must attest to. Replaced only by [refreshPins].
  EnclavePins get pins => _pins;
  EnclavePins _pins;

  /// Where newer pins come from, when a document fails against the current ones.
  ///
  /// For an enclave whose pins change while the app runs: a redeploy changes PCR16, and an emulated
  /// enclave mints a new trust root every boot. Asked once per failure; the same document is then
  /// checked against what it returns, so a refresh can only ever accept what a publisher vouches
  /// for, and a document that fails both is refused as before. Null means pins never change.
  final Future<EnclavePins> Function()? refreshPins;

  /// What an assertion claims, e.g. `https://enclave.test`.
  ///
  /// **Compared exactly, not by suffix**, and unrelated to where the socket goes: the origin is a
  /// string inside `clientDataJSON`.
  final String origin;

  /// Who signs. Absent until a passkey exists — [enrol] needs none.
  Authenticator? authenticator;

  final ConnectionVerifier _verifier;
  late final HttpClient _http;
  static final _random = Random.secure();

  AttestedConnection? _attested;
  final _attestedChanges = StreamController<AttestedConnection>.broadcast();

  /// The last connection a document vouched for. Null until the first `/auth/*` exchange.
  AttestedConnection? get attested => _attested;

  /// Fires when the attested certificate changes — a renewal, say.
  Stream<AttestedConnection> get attestedChanges => _attestedChanges.stream;

  /// Attest the enclave without asking it for anything.
  ///
  /// `/auth/` itself routes nowhere, but its response is attested like any other under the prefix —
  /// it is what `nitro-attest` asks for. The status is ignored; the document is the point.
  Future<AttestedConnection> attest() async {
    await _exchange('GET', '/auth/', null, acceptAnyStatus: true);
    return _attested!;
  }

  /// A token for one request at [method] [path].
  ///
  /// [query] distinguishes `null` from `''` — the runtime treats them as different scopes.
  Future<InteractionToken> mint({
    required String method,
    required String path,
    String? query,
  }) async {
    final authenticator = this.authenticator;
    if (authenticator == null) {
      throw StateError('no passkey to approve $method $path with — enrol one first');
    }
    final options = await _exchange('POST', '/auth/request/options', {
      'credential_id': authenticator.credentialId,
      'method': method,
      'path': path,
      'query': query,
    });

    final publicKey = (options['options'] as Map<String, dynamic>)['publicKey'] as Map<String, dynamic>;
    final assertion = await authenticator.assertion(publicKey, origin);

    final granted = await _exchange('POST', '/auth/request/verify', {
      'challenge_id': options['challenge_id'],
      // Double-encoded, and that is the contract: the field carries base64url of the credential
      // JSON, not the JSON.
      'assertion': _b64u(utf8.encode(jsonEncode(assertion))),
    });

    final ttl = (granted['expires_in_secs'] as num).toInt();
    return InteractionToken(
      granted['token'] as String,
      // Shaded by a second. A token that expires in flight is refused with the same opaque message
      // as a forged one, which is a miserable thing to debug.
      DateTime.now().add(Duration(seconds: ttl - 1)),
    );
  }

  /// Register a new passkey with [registrar], which creates a new tenant with its own isolated
  /// filesystem. Registration is open: no invitation, no operator step.
  ///
  /// The caller keeps [Enrolment.credentialId] and builds its [Authenticator] from it.
  Future<Enrolment> enrol(PasskeyRegistrar registrar, {String? displayName}) async {
    final options = await _exchange('POST', '/auth/register/options', {
      if (displayName != null) 'display_name': displayName,
    });
    final publicKey = (options['options'] as Map<String, dynamic>)['publicKey'] as Map<String, dynamic>;
    final credential = await registrar.createCredential(publicKey, origin);
    // Unlike an assertion, the credential goes as the JSON object itself.
    final registered = await _exchange('POST', '/auth/register/verify', {
      'registration_id': options['registration_id'],
      'credential': credential,
    });
    return Enrolment(registered['tenant_id'] as String, registered['credential_id'] as String);
  }

  /// Every request the runtime accepts carries one of these, gate or no gate.
  ///
  /// Checked before routing, so a missing one is a 400 and the guest never runs. Unpadded
  /// base64url of 8..64 bytes.
  static String nonce() => _b64u(nonceBytes());

  static List<int> nonceBytes() => List<int>.generate(20, (_) => _random.nextInt(256));

  /// One attested request. The document is verified before the body is read, and a response
  /// without one is refused outright: every `/auth/*` response carries one, so its absence means
  /// something between here and the enclave took it off.
  Future<Map<String, dynamic>> _exchange(
    String method,
    String path,
    Map<String, dynamic>? body, {
    bool acceptAnyStatus = false,
  }) async {
    final nonce = nonceBytes();
    late HttpClientResponse resp;
    try {
      final req = await _http.openUrl(method, Uri.parse('${endpoint.baseUrl}$path'));
      req.headers.set('x-enclave-nonce', _b64u(nonce));
      if (body != null) {
        req.headers.contentType = ContentType.json;
        req.write(jsonEncode(body));
      }
      resp = await req.close();
    } catch (e) {
      throw GateException(path, 0, 'could not reach the enclave: $e');
    }
    final text = await utf8.decodeStream(resp);

    final header = resp.headers.value('x-enclave-attestation');
    final served = resp.certificate;
    if (header == null || served == null) {
      throw AttestationException(
        '$path answered ${resp.statusCode} with ${header == null ? 'no attestation document' : 'no certificate'}',
      );
    }
    final document = base64.decode(header);
    AttestedConnection verifyWith(EnclavePins p) =>
        _verifier(document: document, pins: p, servedCertificate: served.der, nonce: nonce);
    late AttestedConnection attested;
    try {
      attested = verifyWith(_pins);
    } on AttestationException catch (refused, trace) {
      final refresh = refreshPins;
      if (refresh == null) rethrow;
      // Pins that cannot be fetched leave the document refused for the reason it was: an
      // unreachable manifest must not read as a network fault instead of an attestation failure.
      final EnclavePins fresh;
      try {
        fresh = await refresh();
      } catch (_) {
        Error.throwWithStackTrace(refused, trace);
      }
      attested = verifyWith(fresh);
      _pins = fresh;
    }
    // Belt and braces: the verifier compared the same bytes, but the pin is what everything after
    // this relies on, so it is derived here from what the socket presented.
    final servedHash = crypto.sha256.convert(served.der).toString();
    if (attested.certificateSha256 != servedHash) {
      throw AttestationException('the verifier bound $servedHash to ${attested.certificateSha256}');
    }
    if (_attested?.certificateSha256 != attested.certificateSha256) {
      _attestedChanges.add(attested);
    }
    _attested = attested;

    if (resp.statusCode != 200) {
      if (acceptAnyStatus) return const {};
      throw GateException(path, resp.statusCode, text);
    }
    return jsonDecode(text) as Map<String, dynamic>;
  }

  void close() {
    _http.close(force: true);
    _attestedChanges.close();
  }
}

String _b64u(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
