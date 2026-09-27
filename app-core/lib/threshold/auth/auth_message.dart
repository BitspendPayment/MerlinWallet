import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

/// Authentication message builder for MPC Wallet requests.
///
/// Uses a static message prefix with operation type and timestamp
/// to create a deterministic message for Schnorr signature authentication.
/// This design prevents replay attacks through timestamp validation.
class AuthMessage {
  /// Protocol version prefix for domain separation
  static const String protocolVersion = 'MPC_WALLET_AUTH_V1';

  /// Maximum allowed timestamp drift in milliseconds (5 minutes)
  static const int maxTimestampDriftMs = 5 * 60 * 1000;

  /// Operation types for different RPC calls
  static const String opSignStep1 = 'SIGN_STEP1';
  static const String opSignStep2 = 'SIGN_STEP2';
  static const String opFetchHistory = 'FETCH_HISTORY';
  static const String opFetchRecentTxs = 'FETCH_RECENT_TXS';
  static const String opSubscribeHistory = 'SUBSCRIBE_HISTORY';
  static const String opGetArkInfo = 'GET_ARK_INFO';
  static const String opGetArkAddress = 'GET_ARK_ADDRESS';
  static const String opGetBoardingAddress = 'GET_BOARDING_ADDRESS';
  static const String opListVtxos = 'LIST_VTXOS';
  static const String opSendVtxo = 'SEND_VTXO';
  static const String opRedeemVtxo = 'REDEEM_VTXO';
  static const String opSettle = 'SETTLE';
  static const String opSettleDelegate = 'SETTLE_DELEGATE';
  static const String opListArkTxs = 'LIST_ARK_TXS';
  static const String opCheckBoardingBalance = 'CHECK_BOARDING_BALANCE';
  static const String opRegisterDeviceToken = 'REGISTER_DEVICE_TOKEN';
  static const String opEvtxoPending = 'EVTXO_PENDING';
  static const String opEvtxoAck = 'EVTXO_ACK';
  static const String opEventsSubscribe = 'EVENTS_SUBSCRIBE';
  /// Attaching a passkey to this wallet. Signed with the wallet's own key — the
  /// cosigner will not accept a session token here, since a token is what a
  /// passkey mints.
  static const String opPasskeyRegister = 'PASSKEY_REGISTER';

  final String operation;
  final int timestampMs;
  final String userIdHex;

  AuthMessage({
    required this.operation,
    required this.timestampMs,
    required this.userIdHex,
  });

  /// Creates an auth message for the current time
  factory AuthMessage.now({
    required String operation,
    required String userIdHex,
  }) {
    return AuthMessage(
      operation: operation,
      timestampMs: DateTime.now().millisecondsSinceEpoch,
      userIdHex: userIdHex,
    );
  }

  /// Builds the canonical message string for signing
  /// Format: MPC_WALLET_AUTH_V1:<operation>:<timestamp_ms>:<user_id_hex>
  String get canonicalMessage {
    return '$protocolVersion:$operation:$timestampMs:$userIdHex';
  }

  /// Returns the message bytes to be signed (SHA256 hash of canonical message)
  /// Using a hash ensures consistent 32-byte message length for BIP-340
  Uint8List get messageBytes {
    final canonical = canonicalMessage;
    final hash = sha256.convert(utf8.encode(canonical));
    return Uint8List.fromList(hash.bytes);
  }

  /// Validates that the timestamp is within acceptable drift range
  bool isTimestampValid({int? serverTimeMs}) {
    final now = serverTimeMs ?? DateTime.now().millisecondsSinceEpoch;
    final diff = (now - timestampMs).abs();
    return diff <= maxTimestampDriftMs;
  }

  /// Parses an auth message from its components
  factory AuthMessage.parse({
    required String operation,
    required int timestampMs,
    required String userIdHex,
  }) {
    return AuthMessage(
      operation: operation,
      timestampMs: timestampMs,
      userIdHex: userIdHex,
    );
  }

  @override
  String toString() => canonicalMessage;
}

/// Exception thrown when authentication fails
class AuthenticationException implements Exception {
  final String message;
  final String? code;

  AuthenticationException(this.message, {this.code});

  @override
  String toString() => 'AuthenticationException: $message${code != null ? ' (code: $code)' : ''}';
}

/// Exception thrown when timestamp validation fails
class TimestampValidationException extends AuthenticationException {
  TimestampValidationException(String message) : super(message, code: 'TIMESTAMP_INVALID');
}

/// Exception thrown when signature verification fails
class SignatureVerificationException extends AuthenticationException {
  SignatureVerificationException(String message) : super(message, code: 'SIGNATURE_INVALID');
}
