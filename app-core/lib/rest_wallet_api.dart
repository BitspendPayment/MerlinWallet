/// REST/JSON implementation of [WalletApi] — uses HTTP/1.1 POST requests.
///
/// Byte fields are hex-encoded strings in JSON.
/// Works with the server's axum REST API (`--rest-port`).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:fixnum/fixnum.dart';
import 'package:protocol/protocol.dart';

import 'package:app_core/passkey/session_token_source.dart';
import 'wallet_api.dart';

/// Hex encode bytes for JSON.
String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Hex decode string from JSON.
Uint8List _unhex(String? s) {
  if (s == null || s.isEmpty) return Uint8List(0);
  final bytes = <int>[];
  for (var i = 0; i < s.length; i += 2) {
    bytes.add(int.parse(s.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(bytes);
}

/// Function type for making HTTP POST requests.
/// Used to allow different HTTP backends (plain http.Client vs enclave FFI).
typedef PostFn = Future<Map<String, dynamic>> Function(
    String path, Map<String, dynamic> body);

/// The cosigner refused our credentials (401/403).
///
/// Deliberately distinct from a transport or ASP failure: an expired session
/// token, a dismissed biometric prompt and a dead ASP all used to surface as the
/// same bare `Exception`, so the poll loop read a routine re-auth as an outage
/// and dropped the user out of Ark entirely.
class WalletAuthException implements Exception {
  final String message;
  final int statusCode;

  WalletAuthException(this.message, this.statusCode);

  @override
  String toString() => 'WalletAuthException($statusCode): $message';
}

class RestWalletApi implements WalletApi {
  final String baseUrl;
  final http.Client? _http;
  PostFn? customPost;

  /// Source of the upstream Bearer session token (auth-off-the-share migration).
  /// Defaults to [NoSessionToken] (Schnorr auth only, via the body `signature`);
  /// set once a token is available and it rides as `Authorization: Bearer` on
  /// every request. The cosigner prefers a valid token and ignores the Schnorr
  /// signature, which is what frees the FROST share to be PIN-gated to ARK.
  SessionTokenSource sessionTokens = const NoSessionToken();

  RestWalletApi(this.baseUrl, {http.Client? httpClient})
      : _http = httpClient ?? http.Client(),
        customPost = null;

  /// Create a RestWalletApi with a custom POST function (e.g. enclave FFI).
  RestWalletApi.withPostFn(this.baseUrl, PostFn postFn)
      : _http = null,
        customPost = postFn;

  Future<Map<String, dynamic>> _post(String path, Map<String, dynamic> body,
      {bool retryOnTokenReject = true}) async {
    if (customPost != null) {
      return customPost!(path, body);
    }
    final headers = <String, String>{'content-type': 'application/json'};
    await _addAuthHeader(headers);
    final resp = await _http!.post(
      Uri.parse('$baseUrl$path'),
      headers: headers,
      body: jsonEncode(body),
    );
    if (resp.statusCode != 200) {
      // Long-lived tokens can die server-side (secret rotation, early expiry).
      // Drop the cache and retry ONCE with a freshly-minted token, so a stale
      // cached token degrades to a single re-auth instead of a dead wallet.
      if (resp.statusCode == 401 &&
          retryOnTokenReject &&
          resp.body.contains('session token')) {
        sessionTokens.onRejected();
        return _post(path, body, retryOnTokenReject: false);
      }
      final errBody = jsonDecode(resp.body);
      final message =
          errBody['error'] ?? 'HTTP ${resp.statusCode}: ${resp.body}';
      // Typed so callers can tell "our credentials were refused" from "the
      // server or the ASP is down". Conflating them made a single expired
      // session token look like an ASP outage and evict the user from Ark.
      if (resp.statusCode == 401 || resp.statusCode == 403) {
        throw WalletAuthException(message.toString(), resp.statusCode);
      }
      throw Exception(message);
    }
    return jsonDecode(resp.body) as Map<String, dynamic>;
  }

  /// GET helper for unauthenticated read-only endpoints (e.g. /server-info).
  /// Falls back to a POST through `customPost` when one is configured, since
  /// the enclave-FFI transport only models POST.
  Future<Map<String, dynamic>> _get(String path) async {
    if (customPost != null) {
      return customPost!(path, {});
    }
    final headers = <String, String>{};
    await _addAuthHeader(headers);
    final resp = await _http!.get(Uri.parse('$baseUrl$path'), headers: headers);
    if (resp.statusCode != 200) {
      throw Exception('HTTP ${resp.statusCode}: ${resp.body}');
    }
    return jsonDecode(resp.body) as Map<String, dynamic>;
  }

  /// Attach the upstream session token as `Authorization: Bearer <jwt>` when one
  /// is available. No-op (Schnorr-only) otherwise. Body auth fields are still
  /// sent during migration; the cosigner prefers a valid token.
  Future<void> _addAuthHeader(Map<String, String> headers) async {
    final token = await sessionTokens.currentToken();
    if (token != null) {
      headers['authorization'] = 'Bearer $token';
    }
  }

  /// Common auth fields present on most requests.
  Map<String, dynamic> _authFields(
      List<int> userId, List<int> signature, Int64 timestampMs) {
    return {
      'user_id': _hex(userId),
      'signature': _hex(signature),
      'timestamp_ms': timestampMs.toInt(),
    };
  }

  // -------------------------------------------------------------------------
  // DKG
  // -------------------------------------------------------------------------

  @override
  Future<DKGStep1Response> dKGStep1(DKGStep1Request r) async {
    final resp = await _post('/api/dkg/step1', {
      'user_id': _hex(r.userId),
      'identifier': _hex(r.identifier),
      'round1_package': r.round1Package,
    });
    return DKGStep1Response()
      ..round1Packages
          .addAll((resp['round1_packages'] as Map<String, dynamic>? ?? {})
              .map((k, v) => MapEntry(k, v.toString())));
  }

  @override
  Future<DKGStep2Response> dKGStep2(DKGStep2Request r) async {
    final resp = await _post('/api/dkg/step2', {
      'user_id': _hex(r.userId),
      'identifier': _hex(r.identifier),
      'round1_package': r.round1Package,
    });
    return DKGStep2Response()
      ..allRound1Packages
          .addAll((resp['all_round1_packages'] as Map<String, dynamic>? ?? {})
              .map((k, v) => MapEntry(k, v.toString())));
  }

  @override
  Future<DKGStep3Response> dKGStep3(DKGStep3Request r) async {
    final resp = await _post('/api/dkg/step3', {
      'user_id': _hex(r.userId),
      'identifier': _hex(r.identifier),
      'round2_packages_for_others':
          r.round2PackagesForOthers.map((k, v) => MapEntry(k, v)),
    });
    return DKGStep3Response()
      ..round2PackagesForMe
          .addAll((resp['round2_packages_for_me'] as Map<String, dynamic>? ?? {})
              .map((k, v) => MapEntry(k, v.toString())));
  }

  // -------------------------------------------------------------------------
  // Contract eVTXO creation
  // -------------------------------------------------------------------------

  @override
   @override
   @override
   // -------------------------------------------------------------------------
  // Request-to-pay
  // -------------------------------------------------------------------------
  //
  // Identity here is the wallet's GROUP key, not its share key: the cosigner derives the payee's
  // Ark address from whatever key identifies the requester, so a share key would produce an
  // address the requester cannot spend. A group key also can't be Schnorr-signed (nobody holds
  // its private half) — the session token, whose `sub` IS the group key, is what authenticates.

  @override
  Future<ContactAddResponse> contactAdd(ContactAddRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/contacts/add', {
      ..._authFields(r.userId, r.signature, r.timestampMs),
      'contact_verifying_key': _hex(r.contactVerifyingKey),
      'label': r.label,
    });
    return ContactAddResponse()..ok = resp['ok'] as bool? ?? false;
  }

  @override
  Future<ContactRemoveResponse> contactRemove(ContactRemoveRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/contacts/remove', {
      ..._authFields(r.userId, r.signature, r.timestampMs),
      'contact_verifying_key': _hex(r.contactVerifyingKey),
    });
    return ContactRemoveResponse()..ok = resp['ok'] as bool? ?? false;
  }

  @override
  Future<ContactListResponse> contactList(ContactListRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/contacts/list',
        _authFields(r.userId, r.signature, r.timestampMs));
    final contacts = (resp['contacts'] as List<dynamic>? ?? [])
        .map((c) => Contact()
          ..verifyingKey = _unhex(c['verifying_key'] as String?)
          ..label = c['label'] as String? ?? ''
          ..addedAt = Int64(_asInt(c['added_at'])))
        .toList();
    return ContactListResponse()..contacts.addAll(contacts);
  }

  /// Ask [payerGroupKeyHex] to pay us. The URL addresses the PAYER's actor while `user_id`
  /// identifies US — the only call where those differ. The payer's contact allowlist is the
  /// authorization; being able to reach the endpoint is not.
  @override
  Future<PaymentRequestCreateResponse> createPaymentRequest(
      PaymentRequestCreateRequest r, String payerGroupKeyHex) async {
    final resp = await _post('/api/u/$payerGroupKeyHex/payment-request/create', {
      ..._authFields(r.userId, r.signature, r.timestampMs),
      'amount_sats': r.amountSats.toInt(),
      'memo': r.memo,
      'expires_in_secs': r.expiresInSecs.toInt(),
    });
    final intent = resp['intent'];
    return PaymentRequestCreateResponse()
      ..intent = intent == null
          ? PaymentIntent()
          : _intentFromJson(intent as Map<String, dynamic>);
  }

  @override
  Future<PaymentRequestListResponse> paymentRequestList(
      PaymentRequestListRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/payment-request/list',
        _authFields(r.userId, r.signature, r.timestampMs));
    final intents = (resp['intents'] as List<dynamic>? ?? [])
        .map((i) => _intentFromJson(i as Map<String, dynamic>))
        .toList();
    return PaymentRequestListResponse()..intents.addAll(intents);
  }

  @override
  Future<PaymentRequestDeclineResponse> paymentRequestDecline(
      PaymentRequestDeclineRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/payment-request/decline', {
      ..._authFields(r.userId, r.signature, r.timestampMs),
      'id': r.id,
    });
    return PaymentRequestDeclineResponse()..ok = resp['ok'] as bool? ?? false;
  }

  PaymentIntent _intentFromJson(Map<String, dynamic> i) => PaymentIntent()
    ..id = i['id'] as String? ?? ''
    ..fromVerifyingKey = _unhex(i['from_verifying_key'] as String?)
    ..toArkAddress = i['to_ark_address'] as String? ?? ''
    ..amountSats = Int64(_asInt(i['amount_sats']))
    ..memo = i['memo'] as String? ?? ''
    ..createdAt = Int64(_asInt(i['created_at']))
    ..expiresAt = Int64(_asInt(i['expires_at']))
    ..status = i['status'] as String? ?? ''
    ..arkTxid = i['ark_txid'] as String? ?? '';

  /// JSON numbers arrive as `int` (or `double` after a round-trip); normalise.
  static int _asInt(dynamic v) =>
      v is int ? v : (v is num ? v.toInt() : 0);

  // -------------------------------------------------------------------------
  // Signing
  // -------------------------------------------------------------------------

  @override
  Future<SignStep1Response> signStep1(SignStep1Request r,
      {String? routeGroupKeyHex}) async {
    final route = routeGroupKeyHex ?? _hex(r.userId);
    final resp = await _post('/api/u/$route/sign/step1', {
      'user_id': _hex(r.userId),
      'hiding_commitment': _hex(r.hidingCommitment),
      'binding_commitment': _hex(r.bindingCommitment),
      'message_to_sign': _hex(r.messageToSign),
      'signature': _hex(r.signature),
      'full_transaction': _hex(r.fullTransaction),
      'ark_tx': _hex(r.arkTx),
      'timestamp_ms': r.timestampMs.toInt(),
      'script_path_spend': r.scriptPathSpend,
    });
    final result = SignStep1Response()
      ..messageToSign = _unhex(resp['message_to_sign'] as String?)
      ..usedKeyIndex = (resp['used_key_index'] as num?)?.toInt() ?? 0;
    final comms = resp['commitments'] as Map<String, dynamic>? ?? {};
    for (final entry in comms.entries) {
      final c = entry.value as Map<String, dynamic>;
      result.commitments[entry.key] = SignStep1Response_Commitment()
        ..hiding = _unhex(c['hiding'] as String?)
        ..binding = _unhex(c['binding'] as String?);
    }
    return result;
  }

  @override
  Future<SignStep2Response> signStep2(SignStep2Request r,
      {String? routeGroupKeyHex}) async {
    final route = routeGroupKeyHex ?? _hex(r.userId);
    final resp = await _post('/api/u/$route/sign/step2', {
      'user_id': _hex(r.userId),
      'signature_share': _hex(r.signatureShare),
      'signature': _hex(r.signature),
      'timestamp_ms': r.timestampMs.toInt(),
    });
    return SignStep2Response()
      ..rPoint = _unhex(resp['r_point'] as String?)
      ..zScalar = _unhex(resp['z_scalar'] as String?);
  }

  // -------------------------------------------------------------------------
  // Transactions
  // -------------------------------------------------------------------------

  // -------------------------------------------------------------------------
  // Ark
  // -------------------------------------------------------------------------

  @override
  Future<GetArkInfoResponse> getArkInfo(GetArkInfoRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/ark/info', {
      ..._authFields(r.userId, r.signature, r.timestampMs),
    });
    return GetArkInfoResponse()
      ..signerPubkey = resp['signer_pubkey'] as String? ?? ''
      ..forfeitPubkey = resp['forfeit_pubkey'] as String? ?? ''
      ..network = resp['network'] as String? ?? ''
      ..sessionDuration = Int64(resp['session_duration'] as int? ?? 0)
      ..unilateralExitDelay = Int64(resp['unilateral_exit_delay'] as int? ?? 0)
      ..boardingExitDelay = Int64(resp['boarding_exit_delay'] as int? ?? 0)
      ..vtxoMinAmount = Int64(resp['vtxo_min_amount'] as int? ?? 0)
      ..dust = Int64(resp['dust'] as int? ?? 0)
      ..checkpointTapscript = resp['checkpoint_tapscript'] as String? ?? ''
      ..forfeitAddress = resp['forfeit_address'] as String? ?? ''
      ..autoSettleSafetyMarginSecs =
          Int64(resp['auto_settle_safety_margin_secs'] as int? ?? 0);
  }

  @override
  Future<GetArkAddressResponse> getArkAddress(GetArkAddressRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/ark/address', {
      ..._authFields(r.userId, r.signature, r.timestampMs),
    });
    return GetArkAddressResponse()
      ..arkAddress = resp['ark_address'] as String? ?? '';
  }

  @override
  Future<GetBoardingAddressResponse> getBoardingAddress(
      GetBoardingAddressRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/ark/boarding-address', {
      ..._authFields(r.userId, r.signature, r.timestampMs),
    });
    return GetBoardingAddressResponse()
      ..boardingAddress = resp['boarding_address'] as String? ?? '';
  }

  @override
  Future<ListVtxosResponse> listVtxos(ListVtxosRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/ark/vtxos', {
      ..._authFields(r.userId, r.signature, r.timestampMs),
    });
    final result = ListVtxosResponse()
      ..totalBalance = Int64(resp['total_balance'] as int? ?? 0)
      ..hasActiveDelegate = resp['has_active_delegate'] as bool? ?? false;
    for (final v in (resp['vtxos'] as List? ?? [])) {
      result.vtxos.add(VtxoInfo()
        ..txid = v['txid'] as String? ?? ''
        ..vout = (v['vout'] as num?)?.toInt() ?? 0
        ..amount = Int64(v['amount'] as int? ?? 0)
        ..createdAt = Int64(v['created_at'] as int? ?? 0)
        ..expiresAt = Int64(v['expires_at'] as int? ?? 0)
        ..status = v['status'] as String? ?? ''
        ..isPreconfirmed = v['is_preconfirmed'] as bool? ?? false
        ..exitDelay = (v['exit_delay'] as num?)?.toInt() ?? 0
        ..script = v['script'] as String? ?? '');
    }
    return result;
  }

  @override
   @override
  Future<SendVtxoResponse> sendVtxo(SendVtxoRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/ark/send', {
      'user_id': _hex(r.userId),
      'recipient_ark_address': r.recipientArkAddress,
      'amount': r.amount.toInt(),
      'signature': _hex(r.signature),
      'timestamp_ms': r.timestampMs.toInt(),
      'signed_messages': r.signedMessages.map((m) => _hex(m)).toList(),
    });
    final result = SendVtxoResponse()
      ..status = SendVtxoResponse_Status.valueOf(
              (resp['status'] as num?)?.toInt() ?? 0) ??
          SendVtxoResponse_Status.SIGNING_REQUIRED
      ..scriptPathSpend = resp['script_path_spend'] as bool? ?? false
      ..arkTxid = resp['ark_txid'] as String? ?? ''
      ..errorMessage = resp['error_message'] as String? ?? '';
    for (final m in (resp['messages_to_sign'] as List? ?? [])) {
      result.messagesToSign.add(_unhex(m as String?));
    }
    return result;
  }

  @override
  Future<RedeemVtxoResponse> redeemVtxo(RedeemVtxoRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/ark/redeem', {
      'user_id': _hex(r.userId),
      'on_chain_address': r.onChainAddress,
      'amount': r.amount.toInt(),
      'signature': _hex(r.signature),
      'timestamp_ms': r.timestampMs.toInt(),
    });
    return RedeemVtxoResponse()
      ..success = resp['success'] as bool? ?? false
      ..txid = resp['txid'] as String? ?? '';
  }

  @override
  Future<SettleResponse> settle(SettleRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/ark/settle', {
      'user_id': _hex(r.userId),
      'signature': _hex(r.signature),
      'timestamp_ms': r.timestampMs.toInt(),
      'signed_messages': r.signedMessages.map((m) => _hex(m)).toList(),
      'boarding_utxos': r.boardingUtxos
          .map((u) => {
                'txid': u.txid,
                'vout': u.vout,
                'amount_sats': u.amountSats.toInt(),
              })
          .toList(),
    });
    final result = SettleResponse()
      ..status = SettleResponse_Status.valueOf(
              (resp['status'] as num?)?.toInt() ?? 0) ??
          SettleResponse_Status.SIGNING_REQUIRED
      ..scriptPathSpend = resp['script_path_spend'] as bool? ?? false
      ..commitmentTxid = resp['commitment_txid'] as String? ?? ''
      ..errorMessage = resp['error_message'] as String? ?? '';
    for (final m in (resp['messages_to_sign'] as List? ?? [])) {
      result.messagesToSign.add(_unhex(m as String?));
    }
    return result;
  }

  @override
  Future<SettleDelegateResponse> settleDelegate(
      SettleDelegateRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/ark/settle-delegate', {
      'user_id': _hex(r.userId),
      'signature': _hex(r.signature),
      'timestamp_ms': r.timestampMs.toInt(),
      'signed_messages': r.signedMessages.map((m) => _hex(m)).toList(),
      'store_only': r.storeOnly,
    });
    final result = SettleDelegateResponse()
      ..status = SettleDelegateResponse_Status.valueOf(
              (resp['status'] as num?)?.toInt() ?? 0) ??
          SettleDelegateResponse_Status.SIGNING_REQUIRED
      ..scriptPathSpend = resp['script_path_spend'] as bool? ?? false
      ..commitmentTxid = resp['commitment_txid'] as String? ?? ''
      ..errorMessage = resp['error_message'] as String? ?? '';
    for (final m in (resp['messages_to_sign'] as List? ?? [])) {
      result.messagesToSign.add(_unhex(m as String?));
    }
    return result;
  }

  @override
  Future<SubmitArkSendResponse> submitArkSend(SubmitArkSendRequest r) async {
    final resp = await _post('/api/u/${_hex(r.userId)}/ark/submit-send', {
      'user_id': _hex(r.userId),
      'signature': _hex(r.signature),
      'timestamp_ms': r.timestampMs.toInt(),
      'signed_ark_tx_b64': r.signedArkTxB64,
      'signed_checkpoint_txs_b64': r.signedCheckpointTxsB64,
      'spent_outpoints': r.spentOutpoints,
    });
    return SubmitArkSendResponse()
      ..arkTxid = resp['ark_txid'] as String? ?? ''
      ..changeTxid = resp['change_txid'] as String? ?? ''
      ..changeVout = (resp['change_vout'] as num?)?.toInt() ?? 0
      ..changeAmount = Int64(resp['change_amount'] as int? ?? 0);
  }

  @override
  Future<GetServerInfoResponse> getServerInfo(GetServerInfoRequest r) async {
    final resp = await _get('/api/server-info');
    return GetServerInfoResponse()
      ..bitcoinNetwork = resp['bitcoin_network'] as String? ?? '';
  }

  @override
   @override
  Future<void> shutdown() async {
    _http?.close();
  }
}
