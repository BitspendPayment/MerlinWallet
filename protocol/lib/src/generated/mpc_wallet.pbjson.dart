//
//  Generated code. Do not modify.
//  source: mpc_wallet.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:convert' as $convert;
import 'dart:core' as $core;
import 'dart:typed_data' as $typed_data;

@$core.Deprecated('Use dKGStep1RequestDescriptor instead')
const DKGStep1Request$json = {
  '1': 'DKGStep1Request',
  '2': [
    {'1': 'identifier', '3': 2, '4': 1, '5': 12, '10': 'identifier'},
    {'1': 'round1_package', '3': 3, '4': 1, '5': 9, '10': 'round1Package'},
  ],
  '9': [
    {'1': 1, '2': 2},
    {'1': 4, '2': 5},
  ],
  '10': ['user_id'],
};

/// Descriptor for `DKGStep1Request`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List dKGStep1RequestDescriptor = $convert.base64Decode(
    'Cg9ES0dTdGVwMVJlcXVlc3QSHgoKaWRlbnRpZmllchgCIAEoDFIKaWRlbnRpZmllchIlCg5yb3'
    'VuZDFfcGFja2FnZRgDIAEoCVINcm91bmQxUGFja2FnZUoECAEQAkoECAQQBVIHdXNlcl9pZA==');

@$core.Deprecated('Use dKGStep1ResponseDescriptor instead')
const DKGStep1Response$json = {
  '1': 'DKGStep1Response',
  '2': [
    {'1': 'round1_packages', '3': 1, '4': 3, '5': 11, '6': '.mpc_wallet.DKGStep1Response.Round1PackagesEntry', '10': 'round1Packages'},
  ],
  '3': [DKGStep1Response_Round1PackagesEntry$json],
};

@$core.Deprecated('Use dKGStep1ResponseDescriptor instead')
const DKGStep1Response_Round1PackagesEntry$json = {
  '1': 'Round1PackagesEntry',
  '2': [
    {'1': 'key', '3': 1, '4': 1, '5': 9, '10': 'key'},
    {'1': 'value', '3': 2, '4': 1, '5': 9, '10': 'value'},
  ],
  '7': {'7': true},
};

/// Descriptor for `DKGStep1Response`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List dKGStep1ResponseDescriptor = $convert.base64Decode(
    'ChBES0dTdGVwMVJlc3BvbnNlElkKD3JvdW5kMV9wYWNrYWdlcxgBIAMoCzIwLm1wY193YWxsZX'
    'QuREtHU3RlcDFSZXNwb25zZS5Sb3VuZDFQYWNrYWdlc0VudHJ5Ug5yb3VuZDFQYWNrYWdlcxpB'
    'ChNSb3VuZDFQYWNrYWdlc0VudHJ5EhAKA2tleRgBIAEoCVIDa2V5EhQKBXZhbHVlGAIgASgJUg'
    'V2YWx1ZToCOAE=');

@$core.Deprecated('Use dKGStep3RequestDescriptor instead')
const DKGStep3Request$json = {
  '1': 'DKGStep3Request',
  '2': [
    {'1': 'identifier', '3': 2, '4': 1, '5': 12, '10': 'identifier'},
    {'1': 'round2_packages_for_others', '3': 3, '4': 3, '5': 11, '6': '.mpc_wallet.DKGStep3Request.Round2PackagesForOthersEntry', '10': 'round2PackagesForOthers'},
  ],
  '3': [DKGStep3Request_Round2PackagesForOthersEntry$json],
  '9': [
    {'1': 1, '2': 2},
  ],
  '10': ['user_id'],
};

@$core.Deprecated('Use dKGStep3RequestDescriptor instead')
const DKGStep3Request_Round2PackagesForOthersEntry$json = {
  '1': 'Round2PackagesForOthersEntry',
  '2': [
    {'1': 'key', '3': 1, '4': 1, '5': 9, '10': 'key'},
    {'1': 'value', '3': 2, '4': 1, '5': 9, '10': 'value'},
  ],
  '7': {'7': true},
};

/// Descriptor for `DKGStep3Request`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List dKGStep3RequestDescriptor = $convert.base64Decode(
    'Cg9ES0dTdGVwM1JlcXVlc3QSHgoKaWRlbnRpZmllchgCIAEoDFIKaWRlbnRpZmllchJ1Chpyb3'
    'VuZDJfcGFja2FnZXNfZm9yX290aGVycxgDIAMoCzI4Lm1wY193YWxsZXQuREtHU3RlcDNSZXF1'
    'ZXN0LlJvdW5kMlBhY2thZ2VzRm9yT3RoZXJzRW50cnlSF3JvdW5kMlBhY2thZ2VzRm9yT3RoZX'
    'JzGkoKHFJvdW5kMlBhY2thZ2VzRm9yT3RoZXJzRW50cnkSEAoDa2V5GAEgASgJUgNrZXkSFAoF'
    'dmFsdWUYAiABKAlSBXZhbHVlOgI4AUoECAEQAlIHdXNlcl9pZA==');

@$core.Deprecated('Use dKGStep3ResponseDescriptor instead')
const DKGStep3Response$json = {
  '1': 'DKGStep3Response',
  '2': [
    {'1': 'round2_packages_for_me', '3': 1, '4': 3, '5': 11, '6': '.mpc_wallet.DKGStep3Response.Round2PackagesForMeEntry', '10': 'round2PackagesForMe'},
  ],
  '3': [DKGStep3Response_Round2PackagesForMeEntry$json],
};

@$core.Deprecated('Use dKGStep3ResponseDescriptor instead')
const DKGStep3Response_Round2PackagesForMeEntry$json = {
  '1': 'Round2PackagesForMeEntry',
  '2': [
    {'1': 'key', '3': 1, '4': 1, '5': 9, '10': 'key'},
    {'1': 'value', '3': 2, '4': 1, '5': 9, '10': 'value'},
  ],
  '7': {'7': true},
};

/// Descriptor for `DKGStep3Response`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List dKGStep3ResponseDescriptor = $convert.base64Decode(
    'ChBES0dTdGVwM1Jlc3BvbnNlEmoKFnJvdW5kMl9wYWNrYWdlc19mb3JfbWUYASADKAsyNS5tcG'
    'Nfd2FsbGV0LkRLR1N0ZXAzUmVzcG9uc2UuUm91bmQyUGFja2FnZXNGb3JNZUVudHJ5UhNyb3Vu'
    'ZDJQYWNrYWdlc0Zvck1lGkYKGFJvdW5kMlBhY2thZ2VzRm9yTWVFbnRyeRIQCgNrZXkYASABKA'
    'lSA2tleRIUCgV2YWx1ZRgCIAEoCVIFdmFsdWU6AjgB');

@$core.Deprecated('Use sendVtxoRequestDescriptor instead')
const SendVtxoRequest$json = {
  '1': 'SendVtxoRequest',
  '2': [
    {'1': 'recipient_ark_address', '3': 2, '4': 1, '5': 9, '10': 'recipientArkAddress'},
    {'1': 'amount', '3': 3, '4': 1, '5': 4, '10': 'amount'},
    {'1': 'signed_messages', '3': 6, '4': 3, '5': 12, '10': 'signedMessages'},
  ],
  '9': [
    {'1': 1, '2': 2},
    {'1': 4, '2': 5},
    {'1': 5, '2': 6},
  ],
  '10': ['user_id', 'signature', 'timestamp_ms'],
};

/// Descriptor for `SendVtxoRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List sendVtxoRequestDescriptor = $convert.base64Decode(
    'Cg9TZW5kVnR4b1JlcXVlc3QSMgoVcmVjaXBpZW50X2Fya19hZGRyZXNzGAIgASgJUhNyZWNpcG'
    'llbnRBcmtBZGRyZXNzEhYKBmFtb3VudBgDIAEoBFIGYW1vdW50EicKD3NpZ25lZF9tZXNzYWdl'
    'cxgGIAMoDFIOc2lnbmVkTWVzc2FnZXNKBAgBEAJKBAgEEAVKBAgFEAZSB3VzZXJfaWRSCXNpZ2'
    '5hdHVyZVIMdGltZXN0YW1wX21z');

@$core.Deprecated('Use sendVtxoResponseDescriptor instead')
const SendVtxoResponse$json = {
  '1': 'SendVtxoResponse',
  '2': [
    {'1': 'status', '3': 1, '4': 1, '5': 14, '6': '.mpc_wallet.SendVtxoResponse.Status', '10': 'status'},
    {'1': 'messages_to_sign', '3': 2, '4': 3, '5': 12, '10': 'messagesToSign'},
    {'1': 'script_path_spend', '3': 3, '4': 1, '5': 8, '10': 'scriptPathSpend'},
    {'1': 'ark_txid', '3': 4, '4': 1, '5': 9, '10': 'arkTxid'},
    {'1': 'error_message', '3': 5, '4': 1, '5': 9, '10': 'errorMessage'},
  ],
  '4': [SendVtxoResponse_Status$json],
};

@$core.Deprecated('Use sendVtxoResponseDescriptor instead')
const SendVtxoResponse_Status$json = {
  '1': 'Status',
  '2': [
    {'1': 'SIGNING_REQUIRED', '2': 0},
    {'1': 'SETTLED', '2': 1},
    {'1': 'ERROR', '2': 2},
  ],
};

/// Descriptor for `SendVtxoResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List sendVtxoResponseDescriptor = $convert.base64Decode(
    'ChBTZW5kVnR4b1Jlc3BvbnNlEjsKBnN0YXR1cxgBIAEoDjIjLm1wY193YWxsZXQuU2VuZFZ0eG'
    '9SZXNwb25zZS5TdGF0dXNSBnN0YXR1cxIoChBtZXNzYWdlc190b19zaWduGAIgAygMUg5tZXNz'
    'YWdlc1RvU2lnbhIqChFzY3JpcHRfcGF0aF9zcGVuZBgDIAEoCFIPc2NyaXB0UGF0aFNwZW5kEh'
    'kKCGFya190eGlkGAQgASgJUgdhcmtUeGlkEiMKDWVycm9yX21lc3NhZ2UYBSABKAlSDGVycm9y'
    'TWVzc2FnZSI2CgZTdGF0dXMSFAoQU0lHTklOR19SRVFVSVJFRBAAEgsKB1NFVFRMRUQQARIJCg'
    'VFUlJPUhAC');

@$core.Deprecated('Use getServerInfoRequestDescriptor instead')
const GetServerInfoRequest$json = {
  '1': 'GetServerInfoRequest',
};

/// Descriptor for `GetServerInfoRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getServerInfoRequestDescriptor = $convert.base64Decode(
    'ChRHZXRTZXJ2ZXJJbmZvUmVxdWVzdA==');

@$core.Deprecated('Use getServerInfoResponseDescriptor instead')
const GetServerInfoResponse$json = {
  '1': 'GetServerInfoResponse',
  '2': [
    {'1': 'bitcoin_network', '3': 1, '4': 1, '5': 9, '10': 'bitcoinNetwork'},
  ],
};

/// Descriptor for `GetServerInfoResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getServerInfoResponseDescriptor = $convert.base64Decode(
    'ChVHZXRTZXJ2ZXJJbmZvUmVzcG9uc2USJwoPYml0Y29pbl9uZXR3b3JrGAEgASgJUg5iaXRjb2'
    'luTmV0d29yaw==');

@$core.Deprecated('Use contactDescriptor instead')
const Contact$json = {
  '1': 'Contact',
  '2': [
    {'1': 'verifying_key', '3': 1, '4': 1, '5': 12, '10': 'verifyingKey'},
    {'1': 'label', '3': 2, '4': 1, '5': 9, '10': 'label'},
    {'1': 'added_at', '3': 3, '4': 1, '5': 3, '10': 'addedAt'},
  ],
};

/// Descriptor for `Contact`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List contactDescriptor = $convert.base64Decode(
    'CgdDb250YWN0EiMKDXZlcmlmeWluZ19rZXkYASABKAxSDHZlcmlmeWluZ0tleRIUCgVsYWJlbB'
    'gCIAEoCVIFbGFiZWwSGQoIYWRkZWRfYXQYAyABKANSB2FkZGVkQXQ=');

@$core.Deprecated('Use contactAddRequestDescriptor instead')
const ContactAddRequest$json = {
  '1': 'ContactAddRequest',
  '2': [
    {'1': 'contact_verifying_key', '3': 2, '4': 1, '5': 12, '10': 'contactVerifyingKey'},
    {'1': 'label', '3': 3, '4': 1, '5': 9, '10': 'label'},
  ],
  '9': [
    {'1': 1, '2': 2},
    {'1': 4, '2': 5},
    {'1': 5, '2': 6},
  ],
  '10': ['user_id', 'signature', 'timestamp_ms'],
};

/// Descriptor for `ContactAddRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List contactAddRequestDescriptor = $convert.base64Decode(
    'ChFDb250YWN0QWRkUmVxdWVzdBIyChVjb250YWN0X3ZlcmlmeWluZ19rZXkYAiABKAxSE2Nvbn'
    'RhY3RWZXJpZnlpbmdLZXkSFAoFbGFiZWwYAyABKAlSBWxhYmVsSgQIARACSgQIBBAFSgQIBRAG'
    'Ugd1c2VyX2lkUglzaWduYXR1cmVSDHRpbWVzdGFtcF9tcw==');

@$core.Deprecated('Use contactAddResponseDescriptor instead')
const ContactAddResponse$json = {
  '1': 'ContactAddResponse',
  '2': [
    {'1': 'ok', '3': 1, '4': 1, '5': 8, '10': 'ok'},
  ],
};

/// Descriptor for `ContactAddResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List contactAddResponseDescriptor = $convert.base64Decode(
    'ChJDb250YWN0QWRkUmVzcG9uc2USDgoCb2sYASABKAhSAm9r');

@$core.Deprecated('Use contactRemoveRequestDescriptor instead')
const ContactRemoveRequest$json = {
  '1': 'ContactRemoveRequest',
  '2': [
    {'1': 'contact_verifying_key', '3': 2, '4': 1, '5': 12, '10': 'contactVerifyingKey'},
  ],
  '9': [
    {'1': 1, '2': 2},
    {'1': 3, '2': 4},
    {'1': 4, '2': 5},
  ],
  '10': ['user_id', 'signature', 'timestamp_ms'],
};

/// Descriptor for `ContactRemoveRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List contactRemoveRequestDescriptor = $convert.base64Decode(
    'ChRDb250YWN0UmVtb3ZlUmVxdWVzdBIyChVjb250YWN0X3ZlcmlmeWluZ19rZXkYAiABKAxSE2'
    'NvbnRhY3RWZXJpZnlpbmdLZXlKBAgBEAJKBAgDEARKBAgEEAVSB3VzZXJfaWRSCXNpZ25hdHVy'
    'ZVIMdGltZXN0YW1wX21z');

@$core.Deprecated('Use contactRemoveResponseDescriptor instead')
const ContactRemoveResponse$json = {
  '1': 'ContactRemoveResponse',
  '2': [
    {'1': 'ok', '3': 1, '4': 1, '5': 8, '10': 'ok'},
  ],
};

/// Descriptor for `ContactRemoveResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List contactRemoveResponseDescriptor = $convert.base64Decode(
    'ChVDb250YWN0UmVtb3ZlUmVzcG9uc2USDgoCb2sYASABKAhSAm9r');

@$core.Deprecated('Use contactListRequestDescriptor instead')
const ContactListRequest$json = {
  '1': 'ContactListRequest',
  '9': [
    {'1': 1, '2': 2},
    {'1': 2, '2': 3},
    {'1': 3, '2': 4},
  ],
  '10': ['user_id', 'signature', 'timestamp_ms'],
};

/// Descriptor for `ContactListRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List contactListRequestDescriptor = $convert.base64Decode(
    'ChJDb250YWN0TGlzdFJlcXVlc3RKBAgBEAJKBAgCEANKBAgDEARSB3VzZXJfaWRSCXNpZ25hdH'
    'VyZVIMdGltZXN0YW1wX21z');

@$core.Deprecated('Use contactListResponseDescriptor instead')
const ContactListResponse$json = {
  '1': 'ContactListResponse',
  '2': [
    {'1': 'contacts', '3': 1, '4': 3, '5': 11, '6': '.mpc_wallet.Contact', '10': 'contacts'},
  ],
};

/// Descriptor for `ContactListResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List contactListResponseDescriptor = $convert.base64Decode(
    'ChNDb250YWN0TGlzdFJlc3BvbnNlEi8KCGNvbnRhY3RzGAEgAygLMhMubXBjX3dhbGxldC5Db2'
    '50YWN0Ughjb250YWN0cw==');

@$core.Deprecated('Use paymentIntentDescriptor instead')
const PaymentIntent$json = {
  '1': 'PaymentIntent',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '10': 'id'},
    {'1': 'from_verifying_key', '3': 2, '4': 1, '5': 12, '10': 'fromVerifyingKey'},
    {'1': 'to_ark_address', '3': 3, '4': 1, '5': 9, '10': 'toArkAddress'},
    {'1': 'amount_sats', '3': 4, '4': 1, '5': 4, '10': 'amountSats'},
    {'1': 'memo', '3': 5, '4': 1, '5': 9, '10': 'memo'},
    {'1': 'created_at', '3': 6, '4': 1, '5': 3, '10': 'createdAt'},
    {'1': 'expires_at', '3': 7, '4': 1, '5': 3, '10': 'expiresAt'},
    {'1': 'status', '3': 8, '4': 1, '5': 9, '10': 'status'},
    {'1': 'ark_txid', '3': 9, '4': 1, '5': 9, '10': 'arkTxid'},
  ],
};

/// Descriptor for `PaymentIntent`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List paymentIntentDescriptor = $convert.base64Decode(
    'Cg1QYXltZW50SW50ZW50Eg4KAmlkGAEgASgJUgJpZBIsChJmcm9tX3ZlcmlmeWluZ19rZXkYAi'
    'ABKAxSEGZyb21WZXJpZnlpbmdLZXkSJAoOdG9fYXJrX2FkZHJlc3MYAyABKAlSDHRvQXJrQWRk'
    'cmVzcxIfCgthbW91bnRfc2F0cxgEIAEoBFIKYW1vdW50U2F0cxISCgRtZW1vGAUgASgJUgRtZW'
    '1vEh0KCmNyZWF0ZWRfYXQYBiABKANSCWNyZWF0ZWRBdBIdCgpleHBpcmVzX2F0GAcgASgDUgll'
    'eHBpcmVzQXQSFgoGc3RhdHVzGAggASgJUgZzdGF0dXMSGQoIYXJrX3R4aWQYCSABKAlSB2Fya1'
    'R4aWQ=');

@$core.Deprecated('Use arkInfoDescriptor instead')
const ArkInfo$json = {
  '1': 'ArkInfo',
  '2': [
    {'1': 'signer_pubkey', '3': 1, '4': 1, '5': 9, '10': 'signerPubkey'},
    {'1': 'forfeit_pubkey', '3': 2, '4': 1, '5': 9, '10': 'forfeitPubkey'},
    {'1': 'forfeit_address', '3': 3, '4': 1, '5': 9, '10': 'forfeitAddress'},
    {'1': 'checkpoint_tapscript', '3': 4, '4': 1, '5': 9, '10': 'checkpointTapscript'},
    {'1': 'network', '3': 5, '4': 1, '5': 9, '10': 'network'},
    {'1': 'session_duration', '3': 6, '4': 1, '5': 3, '10': 'sessionDuration'},
    {'1': 'unilateral_exit_delay', '3': 7, '4': 1, '5': 3, '10': 'unilateralExitDelay'},
    {'1': 'boarding_exit_delay', '3': 8, '4': 1, '5': 3, '10': 'boardingExitDelay'},
    {'1': 'vtxo_min_amount', '3': 9, '4': 1, '5': 3, '10': 'vtxoMinAmount'},
    {'1': 'dust', '3': 10, '4': 1, '5': 3, '10': 'dust'},
  ],
};

/// Descriptor for `ArkInfo`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List arkInfoDescriptor = $convert.base64Decode(
    'CgdBcmtJbmZvEiMKDXNpZ25lcl9wdWJrZXkYASABKAlSDHNpZ25lclB1YmtleRIlCg5mb3JmZW'
    'l0X3B1YmtleRgCIAEoCVINZm9yZmVpdFB1YmtleRInCg9mb3JmZWl0X2FkZHJlc3MYAyABKAlS'
    'DmZvcmZlaXRBZGRyZXNzEjEKFGNoZWNrcG9pbnRfdGFwc2NyaXB0GAQgASgJUhNjaGVja3BvaW'
    '50VGFwc2NyaXB0EhgKB25ldHdvcmsYBSABKAlSB25ldHdvcmsSKQoQc2Vzc2lvbl9kdXJhdGlv'
    'bhgGIAEoA1IPc2Vzc2lvbkR1cmF0aW9uEjIKFXVuaWxhdGVyYWxfZXhpdF9kZWxheRgHIAEoA1'
    'ITdW5pbGF0ZXJhbEV4aXREZWxheRIuChNib2FyZGluZ19leGl0X2RlbGF5GAggASgDUhFib2Fy'
    'ZGluZ0V4aXREZWxheRImCg92dHhvX21pbl9hbW91bnQYCSABKANSDXZ0eG9NaW5BbW91bnQSEg'
    'oEZHVzdBgKIAEoA1IEZHVzdA==');

@$core.Deprecated('Use paymentRequestCreateRequestDescriptor instead')
const PaymentRequestCreateRequest$json = {
  '1': 'PaymentRequestCreateRequest',
  '2': [
    {'1': 'amount_sats', '3': 2, '4': 1, '5': 4, '10': 'amountSats'},
    {'1': 'memo', '3': 3, '4': 1, '5': 9, '10': 'memo'},
    {'1': 'expires_in_secs', '3': 4, '4': 1, '5': 3, '10': 'expiresInSecs'},
    {'1': 'ark_info', '3': 7, '4': 1, '5': 11, '6': '.mpc_wallet.ArkInfo', '10': 'arkInfo'},
    {'1': 'authorship', '3': 8, '4': 1, '5': 11, '6': '.mpc_wallet.RequestAuthorship', '10': 'authorship'},
  ],
  '9': [
    {'1': 1, '2': 2},
    {'1': 5, '2': 6},
    {'1': 6, '2': 7},
  ],
  '10': ['user_id', 'signature', 'timestamp_ms'],
};

/// Descriptor for `PaymentRequestCreateRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List paymentRequestCreateRequestDescriptor = $convert.base64Decode(
    'ChtQYXltZW50UmVxdWVzdENyZWF0ZVJlcXVlc3QSHwoLYW1vdW50X3NhdHMYAiABKARSCmFtb3'
    'VudFNhdHMSEgoEbWVtbxgDIAEoCVIEbWVtbxImCg9leHBpcmVzX2luX3NlY3MYBCABKANSDWV4'
    'cGlyZXNJblNlY3MSLgoIYXJrX2luZm8YByABKAsyEy5tcGNfd2FsbGV0LkFya0luZm9SB2Fya0'
    'luZm8SPQoKYXV0aG9yc2hpcBgIIAEoCzIdLm1wY193YWxsZXQuUmVxdWVzdEF1dGhvcnNoaXBS'
    'CmF1dGhvcnNoaXBKBAgBEAJKBAgFEAZKBAgGEAdSB3VzZXJfaWRSCXNpZ25hdHVyZVIMdGltZX'
    'N0YW1wX21z');

@$core.Deprecated('Use requestAuthorshipDescriptor instead')
const RequestAuthorship$json = {
  '1': 'RequestAuthorship',
  '2': [
    {'1': 'requester_group_key', '3': 1, '4': 1, '5': 12, '10': 'requesterGroupKey'},
    {'1': 'payer_group_key', '3': 2, '4': 1, '5': 12, '10': 'payerGroupKey'},
    {'1': 'not_after', '3': 3, '4': 1, '5': 3, '10': 'notAfter'},
    {'1': 'nonce', '3': 4, '4': 1, '5': 12, '10': 'nonce'},
    {'1': 'signature', '3': 5, '4': 1, '5': 12, '10': 'signature'},
  ],
};

/// Descriptor for `RequestAuthorship`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List requestAuthorshipDescriptor = $convert.base64Decode(
    'ChFSZXF1ZXN0QXV0aG9yc2hpcBIuChNyZXF1ZXN0ZXJfZ3JvdXBfa2V5GAEgASgMUhFyZXF1ZX'
    'N0ZXJHcm91cEtleRImCg9wYXllcl9ncm91cF9rZXkYAiABKAxSDXBheWVyR3JvdXBLZXkSGwoJ'
    'bm90X2FmdGVyGAMgASgDUghub3RBZnRlchIUCgVub25jZRgEIAEoDFIFbm9uY2USHAoJc2lnbm'
    'F0dXJlGAUgASgMUglzaWduYXR1cmU=');

@$core.Deprecated('Use paymentRequestCreateResponseDescriptor instead')
const PaymentRequestCreateResponse$json = {
  '1': 'PaymentRequestCreateResponse',
  '2': [
    {'1': 'intent', '3': 1, '4': 1, '5': 11, '6': '.mpc_wallet.PaymentIntent', '10': 'intent'},
  ],
};

/// Descriptor for `PaymentRequestCreateResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List paymentRequestCreateResponseDescriptor = $convert.base64Decode(
    'ChxQYXltZW50UmVxdWVzdENyZWF0ZVJlc3BvbnNlEjEKBmludGVudBgBIAEoCzIZLm1wY193YW'
    'xsZXQuUGF5bWVudEludGVudFIGaW50ZW50');

@$core.Deprecated('Use paymentRequestListRequestDescriptor instead')
const PaymentRequestListRequest$json = {
  '1': 'PaymentRequestListRequest',
  '9': [
    {'1': 1, '2': 2},
    {'1': 2, '2': 3},
    {'1': 3, '2': 4},
  ],
  '10': ['user_id', 'signature', 'timestamp_ms'],
};

/// Descriptor for `PaymentRequestListRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List paymentRequestListRequestDescriptor = $convert.base64Decode(
    'ChlQYXltZW50UmVxdWVzdExpc3RSZXF1ZXN0SgQIARACSgQIAhADSgQIAxAEUgd1c2VyX2lkUg'
    'lzaWduYXR1cmVSDHRpbWVzdGFtcF9tcw==');

@$core.Deprecated('Use paymentRequestListResponseDescriptor instead')
const PaymentRequestListResponse$json = {
  '1': 'PaymentRequestListResponse',
  '2': [
    {'1': 'intents', '3': 1, '4': 3, '5': 11, '6': '.mpc_wallet.PaymentIntent', '10': 'intents'},
  ],
};

/// Descriptor for `PaymentRequestListResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List paymentRequestListResponseDescriptor = $convert.base64Decode(
    'ChpQYXltZW50UmVxdWVzdExpc3RSZXNwb25zZRIzCgdpbnRlbnRzGAEgAygLMhkubXBjX3dhbG'
    'xldC5QYXltZW50SW50ZW50UgdpbnRlbnRz');

@$core.Deprecated('Use paymentRequestDeclineRequestDescriptor instead')
const PaymentRequestDeclineRequest$json = {
  '1': 'PaymentRequestDeclineRequest',
  '2': [
    {'1': 'id', '3': 2, '4': 1, '5': 9, '10': 'id'},
  ],
  '9': [
    {'1': 1, '2': 2},
    {'1': 3, '2': 4},
    {'1': 4, '2': 5},
  ],
  '10': ['user_id', 'signature', 'timestamp_ms'],
};

/// Descriptor for `PaymentRequestDeclineRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List paymentRequestDeclineRequestDescriptor = $convert.base64Decode(
    'ChxQYXltZW50UmVxdWVzdERlY2xpbmVSZXF1ZXN0Eg4KAmlkGAIgASgJUgJpZEoECAEQAkoECA'
    'MQBEoECAQQBVIHdXNlcl9pZFIJc2lnbmF0dXJlUgx0aW1lc3RhbXBfbXM=');

@$core.Deprecated('Use paymentRequestDeclineResponseDescriptor instead')
const PaymentRequestDeclineResponse$json = {
  '1': 'PaymentRequestDeclineResponse',
  '2': [
    {'1': 'ok', '3': 1, '4': 1, '5': 8, '10': 'ok'},
  ],
};

/// Descriptor for `PaymentRequestDeclineResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List paymentRequestDeclineResponseDescriptor = $convert.base64Decode(
    'Ch1QYXltZW50UmVxdWVzdERlY2xpbmVSZXNwb25zZRIOCgJvaxgBIAEoCFICb2s=');

