/// A service, as small as one can be and still be real.
///
/// A service is paired into an escrow so that `{service, cosigner}` can sign it. Its share reaches
/// it as **two halves by two routes** — one from inside the enclave, one from the payer's device —
/// and neither party may hold both, so nobody can hand it a finished share. Assembling them is the
/// service's own job, and so is deciding whether to believe them.
///
/// ```text
///   GET  /escrow/stream?id=…  ◀── runtime    held open; what this service says travels on it
///   POST /escrow/send?id=…    ◀── runtime    the cosigner's half, and its replies
///   POST /pair/wallet         ◀── wallet     { escrow_key, attempt_id, contribution }
///                                             └── s = a + b, checked against the verifying share
/// ```
///
/// # Why the enclave's half arrives on a held connection
///
/// Not for pairing's sake — a POST would do for that. It is because of what comes *after*: a
/// service asking to be paid has to speak first, and it has no passkey for its user's tenant, so it
/// can never call in. The enclave cannot hold a socket either, having no execution context between
/// invocations. So the runtime holds one, opened at pairing and re-dialled by the runtime whenever
/// it drops, and everything in both directions rides it.
///
/// This service is therefore a **server** for the connection the enclave's runtime dials: server-sent
/// events for what it says, and a POST endpoint for what it is told. Both carry the same JSON
/// envelope, tagged by `kind`.
///
/// **It believes a half because the sum checks out, not because of who sent it.** Neither delivery
/// is authenticated and neither needs to be: the pairing package publishes the verifying share the
/// assembled share must match, and nothing that does not match it can sign. That is why this has no
/// credentials and refuses nothing on grounds of identity.
///
/// **Halves are kept per attempt.** A pairing that failed part-way is retried under a fresh attempt
/// id, and two attempts deal on different slopes — so halves from different attempts sum to
/// nothing. Keying by `(escrow, attempt)` keeps them apart deliberately rather than relying on the
/// verification to notice, and lets a redelivery of one attempt be the same delivery rather than a
/// second one.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:app_core/threshold_types.dart' as threshold;

/// One pairing the service is party to, once both halves have arrived and checked out.
class ServiceShare {
  ServiceShare({
    required this.escrowKeyHex,
    required this.attemptIdHex,
    required this.keyPackage,
    required this.publicKeyPackage,
    required this.streamId,
  });

  final String escrowKeyHex;
  final String attemptIdHex;

  /// The connection this pairing arrived on, as the wire names it. What a release travels back up.
  final String streamId;

  /// This service's share of the escrow key. Half of a 2-of-2 — it signs nothing alone.
  final threshold.KeyPackage keyPackage;
  final threshold.PublicKeyPackage publicKeyPackage;
}

/// What has arrived for one attempt so far.
class _Pending {
  BigInt? fromCosigner;
  BigInt? fromWallet;
  threshold.PublicKeyPackage? pkp;
  String? verifyingShareHex;
  threshold.Identifier? serviceId;

  /// The connection the enclave's half came in on, as the wire names it. The wallet's half
  /// arrives by a route with no connection at all, so this is the only place the answer is
  /// recorded — and it is what the service says "I can sign with this" back down.
  String? streamId;
}

/// One connection the runtime is holding, and the id it announced.
///
/// Identity is the object, not the id: several wallets' connections arrive under the same id, and
/// telling them apart is what stops one customer's answer going down another's socket.
class _Held {
  _Held(this.id, this.response);
  final String id;
  final HttpResponse response;
}

class EscrowService {
  EscrowService({required this.identifier});

  /// This service's FROST identifier. Fixed, because the enclave's image names it: a service is
  /// reachable only if its id is in `SERVICE_ORIGINS`, and that is decided at build time.
  final threshold.Identifier identifier;

  HttpServer? _server;

  /// Every connection the runtime is currently holding to this service, by the id it announced.
  ///
  /// That id is `<tenant hex>-<the guest's own id>`, and the tenant half is what makes it usable.
  /// The guest derives its half from *this service's* identifier, so every wallet the enclave
  /// serves opens a connection under the same local name; only the tenant tells them apart. And a
  /// message sent to this service arrives as a POST of its own, carrying no connection identity
  /// beyond that id — so without the tenant there would be no way to answer the customer who
  /// asked, and the answer would go to whichever connection happened to be first.
  ///
  /// That is not hypothetical. It is what happened, and it is why the runtime puts the tenant on
  /// the wire.
  final Map<String, _Held> _held = {};

  /// What could not be said because nothing was holding a connection, by stream id. Sent on the
  /// next dial: the runtime re-establishes these, so a moment with no connection is a wait and not
  /// a loss.
  final Map<String, List<Map<String, dynamic>>> _waiting = {};

  /// Everything the cosigner has said back, newest last, for a test to assert on.
  final List<Map<String, dynamic>> replies = [];

  /// Answers this service is still waiting for, by the request they answer.
  final Map<String, Completer<Map<String, dynamic>>> _awaiting = {};

  /// How many times the runtime has dialled. More than one means it re-established a connection,
  /// which is the property the whole design rests on.
  int connects = 0;

  /// `escrowKey:attemptId` → what has arrived.
  final Map<String, _Pending> _pending = {};

  /// The finished pairings, by the same key. What the service can actually sign with.
  final Map<String, ServiceShare> _ready = {};

  /// Deliveries refused rather than accepted, for a test to assert on.
  final List<String> refusals = [];

  /// Set to make the next cosigner delivery fail, so a test can exercise what happens when one
  /// half never arrives.
  bool rejectCosignerDeliveries = false;

  /// Set to make the next wallet delivery fail, for the same reason from the other side.
  bool rejectWalletDeliveries = false;

  int get port => _server!.port;

  /// The origin the enclave should be told about — the host as the guest sees it.
  String originFor(String host) => 'http://$host:$port';

  ServiceShare? shareFor(String escrowKeyHex, String attemptIdHex) =>
      _ready[_key(escrowKeyHex, attemptIdHex)];

  bool isReady(String escrowKeyHex, String attemptIdHex) =>
      _ready.containsKey(_key(escrowKeyHex, attemptIdHex));

  /// Bind on every interface: the enclave reaches this from its own network, not over loopback.
  Future<void> start({int port = 0}) async {
    final server = await HttpServer.bind(InternetAddress.anyIPv4, port);
    _server = server;
    unawaited(_serve(server));
  }

  Future<void> stop() async => _server?.close(force: true);

  Future<void> _serve(HttpServer server) async {
    await for (final request in server) {
      try {
        await _handle(request);
      } catch (e) {
        request.response.statusCode = HttpStatus.internalServerError;
        request.response.write('$e');
        await request.response.close();
      }
    }
  }

  Future<void> _handle(HttpRequest request) async {
    if (request.method == 'GET' && request.uri.path == '/escrow/stream') {
      return _hold(request);
    }
    if (request.method != 'POST') {
      return _refuse(request, HttpStatus.methodNotAllowed, 'only GET /escrow/stream and POST');
    }
    final body = jsonDecode(await utf8.decodeStream(request)) as Map<String, dynamic>;
    switch (request.uri.path) {
      case '/escrow/send':
        return _fromEnclave(request, body);
      case '/pair/wallet':
        return _fromWallet(request, body);
      default:
        return _refuse(request, HttpStatus.notFound, 'no such path');
    }
  }

  /// Hold a connection open, and say nothing until there is something to say.
  ///
  /// The runtime dials this and keeps dialling: a first-byte timeout of sixty seconds, then a
  /// backoff of one second growing to five minutes. So ending this response is not a failure — it
  /// is a reconnect, and the next dial arrives with the same id.
  Future<void> _hold(HttpRequest request) async {
    final id = request.uri.queryParameters['id'];
    if (id == null || id.isEmpty) {
      return _refuse(request, HttpStatus.badRequest, 'a stream needs an id');
    }
    connects += 1;
    final response = request.response
      ..statusCode = HttpStatus.ok
      ..headers.set(HttpHeaders.contentTypeHeader, 'text/event-stream')
      ..headers.set('cache-control', 'no-cache')
      ..bufferOutput = false;
    // A comment line, so the response head is on the wire and the runtime counts the stream up
    // before anything real needs sending.
    response.write(': open\n\n');
    await response.flush();

    final held = _Held(id, response);
    // A second dial under the same id replaces the first: it IS the same connection, re-dialled.
    _held[id]?.response.close().catchError((_) {});
    _held[id] = held;
    // Held until the far side goes away. `done` completes when it does.
    unawaited(response.done.catchError((Object _) => response).whenComplete(() {
      if (identical(_held[id], held)) _held.remove(id);
    }));

    // Anything that had nowhere to go now does.
    final backlog = _waiting.remove(id) ?? const [];
    for (final message in backlog) {
      await _write(held, message);
    }
  }

  /// Say something on the connection the runtime is holding under [streamId].
  ///
  /// If nothing is holding one right now the message waits for the next dial rather than being
  /// dropped: the runtime re-establishes these, so a moment with no connection is a wait, and "the
  /// service could not reach the enclave for a second" must not mean "the pairing never finishes".
  Future<void> emit(String streamId, Map<String, dynamic> message) async {
    final target = _held[streamId];
    if (target == null) {
      _waiting.putIfAbsent(streamId, () => []).add(message);
      return;
    }
    await _write(target, message);
  }

  Future<void> _write(_Held held, Map<String, dynamic> message) async {
    final payload = base64.encode(utf8.encode(jsonEncode(message)));
    final id = '${message['kind']}-${_emitted++}';
    held.response.write('id: $id\ndata: $payload\n\n');
    await held.response.flush();
  }

  int _emitted = 0;

  /// Ask to be paid out of an escrow, and wait for the answer.
  ///
  /// Everything the cosigner needs to judge this AND to build the transaction itself: it does not
  /// take a transaction from here, because a transaction it did not build is one it would have to
  /// re-derive before it could sign it. What this sends is the proposal, and the commitments for
  /// the signature — the service commits FIRST, which is what lets the cosigner make its nonce and
  /// its share inside one invocation and never write a nonce down.
  Future<Map<String, dynamic>> requestRelease({
    required ServiceShare share,
    required String requestId,
    required String toArkAddress,
    required int amountSats,
    required List<Map<String, dynamic>> inputs,
    required String paymentReference,
    required List<Map<String, String>> commitments,
    Duration limit = const Duration(seconds: 60),
  }) async {
    final answer = Completer<Map<String, dynamic>>();
    _awaiting[requestId] = answer;
    await emit(share.streamId, {
      'kind': 'release-request',
      'request_id': requestId,
      'escrow_key': share.escrowKeyHex,
      'to_ark_address': toArkAddress,
      'amount_sats': amountSats,
      'inputs': inputs,
      'payment_reference': paymentReference,
      'commitments': commitments,
    });
    return answer.future.timeout(limit, onTimeout: () {
      _awaiting.remove(requestId);
      throw StateError('the cosigner never answered $requestId');
    });
  }

  /// Whether the runtime is holding a connection whose id ends in [localId] — the guest's own
  /// half of the name, which is all a caller outside the enclave can know.
  bool isHolding(String localId) => _held.keys.any((id) => id.endsWith('-$localId'));

  /// How many it is holding under that local id: one per wallet the enclave serves.
  int heldUnder(String localId) => _held.keys.where((id) => id.endsWith('-$localId')).length;

  /// Drop every held connection, as a network that went away would. The runtime re-dials.
  Future<void> dropConnections() async {
    final all = List<_Held>.from(_held.values);
    _held.clear();
    for (final held in all) {
      await held.response.close().catchError((_) {});
    }
  }

  /// One message from the enclave, on the connection its runtime holds.
  Future<void> _fromEnclave(HttpRequest request, Map<String, dynamic> body) async {
    final streamId = request.uri.queryParameters['id'] ?? '';
    switch (body['kind']) {
      case 'pairing-half':
        return _fromCosigner(request, body, streamId);
      default:
        // A reply to something this service said.
        replies.add(body);
        final about = (body['request_id'] ?? body['about']) as String?;
        final waiting = about == null ? null : _awaiting.remove(about);
        waiting?.complete(body);
        request.response.statusCode = HttpStatus.ok;
        return request.response.close();
    }
  }

  /// The cosigner's half, with everything public the assembled share is checked against.
  Future<void> _fromCosigner(
    HttpRequest request,
    Map<String, dynamic> body,
    String streamId,
  ) async {
    if (rejectCosignerDeliveries) {
      return _refuse(request, HttpStatus.serviceUnavailable, 'not taking deliveries');
    }
    final key = _key(body['escrow_key'] as String, body['attempt_id'] as String);
    final pending = _pending.putIfAbsent(key, _Pending.new);

    final serviceId = _identifierFromHex(body['service_identifier'] as String);
    if (serviceId != identifier) {
      return _refuse(request, HttpStatus.badRequest, 'that is not this service');
    }
    // A POST is a request of its own and carries no connection identity — so the id is the whole
    // of the tie, and it names the tenant as well as the stream. That is what makes the answer
    // reach the customer who asked rather than whichever one connected first.
    pending
      ..streamId = streamId
      ..serviceId = serviceId
      ..fromCosigner = _scalarFromHex(body['half'] as String)
      ..pkp = threshold.PublicKeyPackage.fromJson(
          jsonDecode(body['public_key_package_json'] as String) as Map<String, dynamic>)
      ..verifyingShareHex = (body['service_verifying_share'] as String).toLowerCase();

    return _settle(request, key);
  }

  /// The wallet's half. Nothing public comes with it — it is one scalar, and the package the
  /// cosigner sent is what it is checked against.
  Future<void> _fromWallet(HttpRequest request, Map<String, dynamic> body) async {
    if (rejectWalletDeliveries) {
      return _refuse(request, HttpStatus.serviceUnavailable, 'not taking deliveries');
    }
    final key = _key(body['escrow_key'] as String, body['attempt_id'] as String);
    final pending = _pending.putIfAbsent(key, _Pending.new);
    pending.fromWallet = _scalarFromHex(body['contribution'] as String);
    return _settle(request, key);
  }

  /// Both halves present? Then assemble and check. Until then, accept and wait.
  ///
  /// The check is the whole of the service's trust in this: `s·G` against the verifying share the
  /// pairing published. A half from another attempt, a tampered one, or a cosigner that dealt
  /// something else all fail it, and none of them can be told apart from here — which is fine,
  /// because the answer to all three is the same.
  Future<void> _settle(HttpRequest request, String key) async {
    final pending = _pending[key]!;
    final a = pending.fromWallet;
    final b = pending.fromCosigner;
    if (a == null || b == null) {
      request.response.statusCode = HttpStatus.accepted;
      request.response.write('{"state":"waiting"}');
      return request.response.close();
    }

    final n = threshold.secp256k1Curve.n;
    final share = (a + b) % n;
    final expected = pending.verifyingShareHex!;
    final parts = key.split(':');
    if (threshold.elemBaseMul(share).toLowerCase() != expected) {
      refusals.add(key);
      final stream = pending.streamId;
      _pending.remove(key);
      // Say so on the connection, so the cosigner knows this attempt went nowhere rather than
      // waiting on a confirmation that is never coming.
      if (stream != null) {
        await emit(stream, {
          'kind': 'pairing-refused',
          'escrow_key': parts[0],
          'attempt_id': parts[1],
          'reason': 'the two halves do not sum to the share this pairing published',
        });
      }
      return _refuse(
        request,
        HttpStatus.badRequest,
        'the two halves do not sum to the share this pairing published',
      );
    }

    _ready[key] = ServiceShare(
      escrowKeyHex: parts[0],
      attemptIdHex: parts[1],
      keyPackage: threshold.KeyPackage(
        pending.serviceId!,
        share,
        expected,
        pending.pkp!.verifyingKey,
        2,
      ),
      publicKeyPackage: pending.pkp!,
      streamId: pending.streamId!,
    );
    final stream = pending.streamId;
    _pending.remove(key);
    request.response.statusCode = HttpStatus.ok;
    request.response.write('{"state":"ready"}');
    await request.response.close();

    // The service's half of "this pairing works", and the only party that can say it: it is the
    // only one that ever holds both halves. The wallet says the other half, over its own channel,
    // and the cosigner treats the pairing as usable only with both.
    if (stream != null) {
      await emit(stream, {
        'kind': 'pairing-ready',
        'escrow_key': parts[0],
        'attempt_id': parts[1],
      });
    }
  }

  Future<void> _refuse(HttpRequest request, int status, String why) async {
    request.response.statusCode = status;
    request.response.write(jsonEncode({'error': why}));
    return request.response.close();
  }

  static String _key(String escrowKeyHex, String attemptIdHex) =>
      '${escrowKeyHex.toLowerCase()}:${attemptIdHex.toLowerCase()}';

  static BigInt _scalarFromHex(String hex) =>
      threshold.bytesToBigInt(Uint8List.fromList(_bytes(hex)));

  static threshold.Identifier _identifierFromHex(String hex) =>
      threshold.Identifier.deserialize(Uint8List.fromList(_bytes(hex)));

  static List<int> _bytes(String hex) => [
        for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16),
      ];
}
