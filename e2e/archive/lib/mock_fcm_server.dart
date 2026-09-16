/// In-process mock for Firebase Cloud Messaging used by e2e tests.
///
/// Listens on a random localhost port and answers the two requests the
/// cosigner makes during a push:
///
///   * `POST /token` — the OAuth2 JWT-bearer token endpoint. Returns a
///     fake access token. The mock does NOT verify the JWT signature —
///     `fcm_test_key.pem` exists only so the cosigner can produce a
///     syntactically valid signature; nothing checks it.
///
///   * `POST /v1/projects/{project_id}/messages:send` — the FCM message
///     send endpoint. Records the request body in `recordedSends` and
///     returns a 200 with a fake message-name response.
///
/// Tests configure the cosigner to point at this mock via two env
/// vars:
///
///   * `FCM_BASE_URL` — overrides the `https://fcm.googleapis.com` base.
///   * The `token_uri` field inside `FCM_SERVICE_ACCOUNT_JSON` — overrides
///     the OAuth token endpoint.
///
/// Pushes only fire when (a) a user has registered a device token via
/// `register_device_token`, and (b) a new VTXO arrives on the vtxo_stream.
/// Other tests in the suite don't register tokens, so the mock sits idle
/// for them; that's intentional — sharing setUpAll keeps the fixtures
/// cheap.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// One recorded FCM `messages:send` POST.
class RecordedSend {
  /// Parsed JSON body of the request.
  final Map<String, dynamic> body;

  /// The bearer token the cosigner attached, sans the `Bearer ` prefix.
  /// Useful for asserting the OAuth flow happened.
  final String? bearerToken;

  /// The `{project_id}` path component the cosigner targeted.
  final String projectId;

  RecordedSend({
    required this.body,
    required this.bearerToken,
    required this.projectId,
  });

  /// Convenience getter: the FCM token the push was addressed to.
  String? get targetToken =>
      (body['message'] as Map<String, dynamic>?)?['token'] as String?;

  /// Convenience getter: the data payload (the `type=vtxo_received`,
  /// `user_id=…` map the cosigner attaches).
  Map<String, String>? get data {
    final raw = (body['message'] as Map<String, dynamic>?)?['data'];
    if (raw is Map) {
      return raw.map((k, v) => MapEntry(k.toString(), v.toString()));
    }
    return null;
  }
}

class MockFcmServer {
  late HttpServer _server;
  final List<RecordedSend> _recordedSends = [];

  /// Mock access token returned for every OAuth POST. Tests can assert
  /// that the cosigner's bearer header matches this value to prove the
  /// OAuth round-trip happened.
  static const String mockAccessToken = 'mock-fcm-access-token-for-e2e';

  Future<void> start() async {
    _server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    _server.listen(_handle, onError: (e, st) {
      // Keep listening across handler exceptions — they shouldn't crash
      // the whole mock for the rest of the suite.
      // ignore: avoid_print
      print('[MockFcmServer] handler error: $e');
    });
  }

  Future<void> stop() async {
    await _server.close(force: true);
  }

  int get port => _server.port;
  String get baseUrl => 'http://127.0.0.1:$port';
  String get tokenUri => '$baseUrl/token';

  /// All `messages:send` calls received so far, in arrival order.
  /// The returned list is a snapshot — modifications by the test don't
  /// affect the internal buffer.
  List<RecordedSend> get sends => List.unmodifiable(_recordedSends);

  /// Clear the recorded sends. Useful when a single setUpAll fixtures
  /// several tests but each test wants its own scoped assertions.
  void clearSends() => _recordedSends.clear();

  /// Poll for at least one send within the timeout. Pushes are
  /// fire-and-forget from the cosigner's side, so tests need to wait
  /// for the network round-trip.
  Future<RecordedSend?> waitForFirstSend(
      {Duration timeout = const Duration(seconds: 10)}) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (_recordedSends.isNotEmpty) return _recordedSends.first;
      await Future.delayed(Duration(milliseconds: 100));
    }
    return null;
  }

  Future<void> _handle(HttpRequest req) async {
    try {
      if (req.method == 'POST' && req.uri.path == '/token') {
        await _handleToken(req);
        return;
      }
      if (req.method == 'POST' &&
          req.uri.path.startsWith('/v1/projects/') &&
          req.uri.path.endsWith('/messages:send')) {
        await _handleMessagesSend(req);
        return;
      }
      req.response.statusCode = HttpStatus.notFound;
      await req.response.close();
    } catch (e) {
      try {
        req.response.statusCode = HttpStatus.internalServerError;
        await req.response.close();
      } catch (_) {}
    }
  }

  Future<void> _handleToken(HttpRequest req) async {
    // Drain the form body so the client's POST completes; we don't verify
    // the JWT — the fixture key is unauthenticated by design.
    await utf8.decoder.bind(req).join();
    req.response
      ..statusCode = HttpStatus.ok
      ..headers.contentType = ContentType.json
      ..write(jsonEncode({
        'access_token': mockAccessToken,
        'expires_in': 3600,
        'token_type': 'Bearer',
      }));
    await req.response.close();
  }

  Future<void> _handleMessagesSend(HttpRequest req) async {
    // Path is /v1/projects/{project_id}/messages:send — pull project_id.
    final parts = req.uri.path.split('/');
    // ['', 'v1', 'projects', '{project_id}', 'messages:send']
    final projectId = parts.length >= 4 ? parts[3] : '';

    final bodyText = await utf8.decoder.bind(req).join();
    Map<String, dynamic> body;
    try {
      body = jsonDecode(bodyText) as Map<String, dynamic>;
    } catch (_) {
      body = {};
    }

    final auth = req.headers.value(HttpHeaders.authorizationHeader);
    String? bearer;
    if (auth != null && auth.startsWith('Bearer ')) {
      bearer = auth.substring('Bearer '.length);
    }

    _recordedSends.add(RecordedSend(
      body: body,
      bearerToken: bearer,
      projectId: projectId,
    ));

    req.response
      ..statusCode = HttpStatus.ok
      ..headers.contentType = ContentType.json
      ..write(jsonEncode({
        'name': 'projects/$projectId/messages/mock-msg-${_recordedSends.length}',
      }));
    await req.response.close();
  }
}
