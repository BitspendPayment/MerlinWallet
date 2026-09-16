//
//  Generated code. Do not modify.
//  source: mpc_wallet.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:core' as $core;

import 'package:fixnum/fixnum.dart' as $fixnum;
import 'package:protobuf/protobuf.dart' as $pb;

import 'mpc_wallet.pbenum.dart';

export 'mpc_wallet.pbenum.dart';

class DKGStep1Request extends $pb.GeneratedMessage {
  factory DKGStep1Request({
    $core.List<$core.int>? identifier,
    $core.String? round1Package,
  }) {
    final $result = create();
    if (identifier != null) {
      $result.identifier = identifier;
    }
    if (round1Package != null) {
      $result.round1Package = round1Package;
    }
    return $result;
  }
  DKGStep1Request._() : super();
  factory DKGStep1Request.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory DKGStep1Request.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'DKGStep1Request', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..a<$core.List<$core.int>>(2, _omitFieldNames ? '' : 'identifier', $pb.PbFieldType.OY)
    ..aOS(3, _omitFieldNames ? '' : 'round1Package')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  DKGStep1Request clone() => DKGStep1Request()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  DKGStep1Request copyWith(void Function(DKGStep1Request) updates) => super.copyWith((message) => updates(message as DKGStep1Request)) as DKGStep1Request;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static DKGStep1Request create() => DKGStep1Request._();
  DKGStep1Request createEmptyInstance() => create();
  static $pb.PbList<DKGStep1Request> createRepeated() => $pb.PbList<DKGStep1Request>();
  @$core.pragma('dart2js:noInline')
  static DKGStep1Request getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<DKGStep1Request>(create);
  static DKGStep1Request? _defaultInstance;

  @$pb.TagNumber(2)
  $core.List<$core.int> get identifier => $_getN(0);
  @$pb.TagNumber(2)
  set identifier($core.List<$core.int> v) { $_setBytes(0, v); }
  @$pb.TagNumber(2)
  $core.bool hasIdentifier() => $_has(0);
  @$pb.TagNumber(2)
  void clearIdentifier() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get round1Package => $_getSZ(1);
  @$pb.TagNumber(3)
  set round1Package($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(3)
  $core.bool hasRound1Package() => $_has(1);
  @$pb.TagNumber(3)
  void clearRound1Package() => clearField(3);
}

class DKGStep1Response extends $pb.GeneratedMessage {
  factory DKGStep1Response({
    $core.Map<$core.String, $core.String>? round1Packages,
  }) {
    final $result = create();
    if (round1Packages != null) {
      $result.round1Packages.addAll(round1Packages);
    }
    return $result;
  }
  DKGStep1Response._() : super();
  factory DKGStep1Response.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory DKGStep1Response.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'DKGStep1Response', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..m<$core.String, $core.String>(1, _omitFieldNames ? '' : 'round1Packages', entryClassName: 'DKGStep1Response.Round1PackagesEntry', keyFieldType: $pb.PbFieldType.OS, valueFieldType: $pb.PbFieldType.OS, packageName: const $pb.PackageName('mpc_wallet'))
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  DKGStep1Response clone() => DKGStep1Response()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  DKGStep1Response copyWith(void Function(DKGStep1Response) updates) => super.copyWith((message) => updates(message as DKGStep1Response)) as DKGStep1Response;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static DKGStep1Response create() => DKGStep1Response._();
  DKGStep1Response createEmptyInstance() => create();
  static $pb.PbList<DKGStep1Response> createRepeated() => $pb.PbList<DKGStep1Response>();
  @$core.pragma('dart2js:noInline')
  static DKGStep1Response getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<DKGStep1Response>(create);
  static DKGStep1Response? _defaultInstance;

  @$pb.TagNumber(1)
  $core.Map<$core.String, $core.String> get round1Packages => $_getMap(0);
}

class DKGStep3Request extends $pb.GeneratedMessage {
  factory DKGStep3Request({
    $core.List<$core.int>? identifier,
    $core.Map<$core.String, $core.String>? round2PackagesForOthers,
  }) {
    final $result = create();
    if (identifier != null) {
      $result.identifier = identifier;
    }
    if (round2PackagesForOthers != null) {
      $result.round2PackagesForOthers.addAll(round2PackagesForOthers);
    }
    return $result;
  }
  DKGStep3Request._() : super();
  factory DKGStep3Request.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory DKGStep3Request.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'DKGStep3Request', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..a<$core.List<$core.int>>(2, _omitFieldNames ? '' : 'identifier', $pb.PbFieldType.OY)
    ..m<$core.String, $core.String>(3, _omitFieldNames ? '' : 'round2PackagesForOthers', entryClassName: 'DKGStep3Request.Round2PackagesForOthersEntry', keyFieldType: $pb.PbFieldType.OS, valueFieldType: $pb.PbFieldType.OS, packageName: const $pb.PackageName('mpc_wallet'))
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  DKGStep3Request clone() => DKGStep3Request()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  DKGStep3Request copyWith(void Function(DKGStep3Request) updates) => super.copyWith((message) => updates(message as DKGStep3Request)) as DKGStep3Request;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static DKGStep3Request create() => DKGStep3Request._();
  DKGStep3Request createEmptyInstance() => create();
  static $pb.PbList<DKGStep3Request> createRepeated() => $pb.PbList<DKGStep3Request>();
  @$core.pragma('dart2js:noInline')
  static DKGStep3Request getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<DKGStep3Request>(create);
  static DKGStep3Request? _defaultInstance;

  @$pb.TagNumber(2)
  $core.List<$core.int> get identifier => $_getN(0);
  @$pb.TagNumber(2)
  set identifier($core.List<$core.int> v) { $_setBytes(0, v); }
  @$pb.TagNumber(2)
  $core.bool hasIdentifier() => $_has(0);
  @$pb.TagNumber(2)
  void clearIdentifier() => clearField(2);

  @$pb.TagNumber(3)
  $core.Map<$core.String, $core.String> get round2PackagesForOthers => $_getMap(1);
}

class DKGStep3Response extends $pb.GeneratedMessage {
  factory DKGStep3Response({
    $core.Map<$core.String, $core.String>? round2PackagesForMe,
  }) {
    final $result = create();
    if (round2PackagesForMe != null) {
      $result.round2PackagesForMe.addAll(round2PackagesForMe);
    }
    return $result;
  }
  DKGStep3Response._() : super();
  factory DKGStep3Response.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory DKGStep3Response.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'DKGStep3Response', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..m<$core.String, $core.String>(1, _omitFieldNames ? '' : 'round2PackagesForMe', entryClassName: 'DKGStep3Response.Round2PackagesForMeEntry', keyFieldType: $pb.PbFieldType.OS, valueFieldType: $pb.PbFieldType.OS, packageName: const $pb.PackageName('mpc_wallet'))
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  DKGStep3Response clone() => DKGStep3Response()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  DKGStep3Response copyWith(void Function(DKGStep3Response) updates) => super.copyWith((message) => updates(message as DKGStep3Response)) as DKGStep3Response;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static DKGStep3Response create() => DKGStep3Response._();
  DKGStep3Response createEmptyInstance() => create();
  static $pb.PbList<DKGStep3Response> createRepeated() => $pb.PbList<DKGStep3Response>();
  @$core.pragma('dart2js:noInline')
  static DKGStep3Response getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<DKGStep3Response>(create);
  static DKGStep3Response? _defaultInstance;

  @$pb.TagNumber(1)
  $core.Map<$core.String, $core.String> get round2PackagesForMe => $_getMap(0);
}

class SendVtxoRequest extends $pb.GeneratedMessage {
  factory SendVtxoRequest({
    $core.String? recipientArkAddress,
    $fixnum.Int64? amount,
    $core.Iterable<$core.List<$core.int>>? signedMessages,
  }) {
    final $result = create();
    if (recipientArkAddress != null) {
      $result.recipientArkAddress = recipientArkAddress;
    }
    if (amount != null) {
      $result.amount = amount;
    }
    if (signedMessages != null) {
      $result.signedMessages.addAll(signedMessages);
    }
    return $result;
  }
  SendVtxoRequest._() : super();
  factory SendVtxoRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory SendVtxoRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'SendVtxoRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..aOS(2, _omitFieldNames ? '' : 'recipientArkAddress')
    ..a<$fixnum.Int64>(3, _omitFieldNames ? '' : 'amount', $pb.PbFieldType.OU6, defaultOrMaker: $fixnum.Int64.ZERO)
    ..p<$core.List<$core.int>>(6, _omitFieldNames ? '' : 'signedMessages', $pb.PbFieldType.PY)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  SendVtxoRequest clone() => SendVtxoRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  SendVtxoRequest copyWith(void Function(SendVtxoRequest) updates) => super.copyWith((message) => updates(message as SendVtxoRequest)) as SendVtxoRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SendVtxoRequest create() => SendVtxoRequest._();
  SendVtxoRequest createEmptyInstance() => create();
  static $pb.PbList<SendVtxoRequest> createRepeated() => $pb.PbList<SendVtxoRequest>();
  @$core.pragma('dart2js:noInline')
  static SendVtxoRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<SendVtxoRequest>(create);
  static SendVtxoRequest? _defaultInstance;

  @$pb.TagNumber(2)
  $core.String get recipientArkAddress => $_getSZ(0);
  @$pb.TagNumber(2)
  set recipientArkAddress($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(2)
  $core.bool hasRecipientArkAddress() => $_has(0);
  @$pb.TagNumber(2)
  void clearRecipientArkAddress() => clearField(2);

  @$pb.TagNumber(3)
  $fixnum.Int64 get amount => $_getI64(1);
  @$pb.TagNumber(3)
  set amount($fixnum.Int64 v) { $_setInt64(1, v); }
  @$pb.TagNumber(3)
  $core.bool hasAmount() => $_has(1);
  @$pb.TagNumber(3)
  void clearAmount() => clearField(3);

  /// FROST signatures for previously requested sighashes (phase 2)
  @$pb.TagNumber(6)
  $core.List<$core.List<$core.int>> get signedMessages => $_getList(2);
}

class SendVtxoResponse extends $pb.GeneratedMessage {
  factory SendVtxoResponse({
    SendVtxoResponse_Status? status,
    $core.Iterable<$core.List<$core.int>>? messagesToSign,
    $core.bool? scriptPathSpend,
    $core.String? arkTxid,
    $core.String? errorMessage,
  }) {
    final $result = create();
    if (status != null) {
      $result.status = status;
    }
    if (messagesToSign != null) {
      $result.messagesToSign.addAll(messagesToSign);
    }
    if (scriptPathSpend != null) {
      $result.scriptPathSpend = scriptPathSpend;
    }
    if (arkTxid != null) {
      $result.arkTxid = arkTxid;
    }
    if (errorMessage != null) {
      $result.errorMessage = errorMessage;
    }
    return $result;
  }
  SendVtxoResponse._() : super();
  factory SendVtxoResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory SendVtxoResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'SendVtxoResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..e<SendVtxoResponse_Status>(1, _omitFieldNames ? '' : 'status', $pb.PbFieldType.OE, defaultOrMaker: SendVtxoResponse_Status.SIGNING_REQUIRED, valueOf: SendVtxoResponse_Status.valueOf, enumValues: SendVtxoResponse_Status.values)
    ..p<$core.List<$core.int>>(2, _omitFieldNames ? '' : 'messagesToSign', $pb.PbFieldType.PY)
    ..aOB(3, _omitFieldNames ? '' : 'scriptPathSpend')
    ..aOS(4, _omitFieldNames ? '' : 'arkTxid')
    ..aOS(5, _omitFieldNames ? '' : 'errorMessage')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  SendVtxoResponse clone() => SendVtxoResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  SendVtxoResponse copyWith(void Function(SendVtxoResponse) updates) => super.copyWith((message) => updates(message as SendVtxoResponse)) as SendVtxoResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SendVtxoResponse create() => SendVtxoResponse._();
  SendVtxoResponse createEmptyInstance() => create();
  static $pb.PbList<SendVtxoResponse> createRepeated() => $pb.PbList<SendVtxoResponse>();
  @$core.pragma('dart2js:noInline')
  static SendVtxoResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<SendVtxoResponse>(create);
  static SendVtxoResponse? _defaultInstance;

  @$pb.TagNumber(1)
  SendVtxoResponse_Status get status => $_getN(0);
  @$pb.TagNumber(1)
  set status(SendVtxoResponse_Status v) { setField(1, v); }
  @$pb.TagNumber(1)
  $core.bool hasStatus() => $_has(0);
  @$pb.TagNumber(1)
  void clearStatus() => clearField(1);

  /// Sighashes that need FROST signing (when SIGNING_REQUIRED)
  @$pb.TagNumber(2)
  $core.List<$core.List<$core.int>> get messagesToSign => $_getList(1);

  /// Always true for send (script-path spend, no taproot tweak)
  @$pb.TagNumber(3)
  $core.bool get scriptPathSpend => $_getBF(2);
  @$pb.TagNumber(3)
  set scriptPathSpend($core.bool v) { $_setBool(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasScriptPathSpend() => $_has(2);
  @$pb.TagNumber(3)
  void clearScriptPathSpend() => clearField(3);

  /// Ark txid when SETTLED
  @$pb.TagNumber(4)
  $core.String get arkTxid => $_getSZ(3);
  @$pb.TagNumber(4)
  set arkTxid($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasArkTxid() => $_has(3);
  @$pb.TagNumber(4)
  void clearArkTxid() => clearField(4);

  /// Error message when ERROR
  @$pb.TagNumber(5)
  $core.String get errorMessage => $_getSZ(4);
  @$pb.TagNumber(5)
  set errorMessage($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasErrorMessage() => $_has(4);
  @$pb.TagNumber(5)
  void clearErrorMessage() => clearField(5);
}

class GetServerInfoRequest extends $pb.GeneratedMessage {
  factory GetServerInfoRequest() => create();
  GetServerInfoRequest._() : super();
  factory GetServerInfoRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory GetServerInfoRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'GetServerInfoRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  GetServerInfoRequest clone() => GetServerInfoRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  GetServerInfoRequest copyWith(void Function(GetServerInfoRequest) updates) => super.copyWith((message) => updates(message as GetServerInfoRequest)) as GetServerInfoRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetServerInfoRequest create() => GetServerInfoRequest._();
  GetServerInfoRequest createEmptyInstance() => create();
  static $pb.PbList<GetServerInfoRequest> createRepeated() => $pb.PbList<GetServerInfoRequest>();
  @$core.pragma('dart2js:noInline')
  static GetServerInfoRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetServerInfoRequest>(create);
  static GetServerInfoRequest? _defaultInstance;
}

class GetServerInfoResponse extends $pb.GeneratedMessage {
  factory GetServerInfoResponse({
    $core.String? bitcoinNetwork,
  }) {
    final $result = create();
    if (bitcoinNetwork != null) {
      $result.bitcoinNetwork = bitcoinNetwork;
    }
    return $result;
  }
  GetServerInfoResponse._() : super();
  factory GetServerInfoResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory GetServerInfoResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'GetServerInfoResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'bitcoinNetwork')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  GetServerInfoResponse clone() => GetServerInfoResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  GetServerInfoResponse copyWith(void Function(GetServerInfoResponse) updates) => super.copyWith((message) => updates(message as GetServerInfoResponse)) as GetServerInfoResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetServerInfoResponse create() => GetServerInfoResponse._();
  GetServerInfoResponse createEmptyInstance() => create();
  static $pb.PbList<GetServerInfoResponse> createRepeated() => $pb.PbList<GetServerInfoResponse>();
  @$core.pragma('dart2js:noInline')
  static GetServerInfoResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetServerInfoResponse>(create);
  static GetServerInfoResponse? _defaultInstance;

  /// The Bitcoin network this deployment operates on. One of: "mainnet",
  /// "testnet", "signet", "mutinynet", "regtest". Source of truth for the
  /// client's address-rendering HRP.
  @$pb.TagNumber(1)
  $core.String get bitcoinNetwork => $_getSZ(0);
  @$pb.TagNumber(1)
  set bitcoinNetwork($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasBitcoinNetwork() => $_has(0);
  @$pb.TagNumber(1)
  void clearBitcoinNetwork() => clearField(1);
}

/// A party this wallet has authorized to send it payment requests. One-way: the owner decides who
/// may bill it; the contact needs no consent and is not notified.
class Contact extends $pb.GeneratedMessage {
  factory Contact({
    $core.List<$core.int>? verifyingKey,
    $core.String? label,
    $fixnum.Int64? addedAt,
  }) {
    final $result = create();
    if (verifyingKey != null) {
      $result.verifyingKey = verifyingKey;
    }
    if (label != null) {
      $result.label = label;
    }
    if (addedAt != null) {
      $result.addedAt = addedAt;
    }
    return $result;
  }
  Contact._() : super();
  factory Contact.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory Contact.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'Contact', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..a<$core.List<$core.int>>(1, _omitFieldNames ? '' : 'verifyingKey', $pb.PbFieldType.OY)
    ..aOS(2, _omitFieldNames ? '' : 'label')
    ..aInt64(3, _omitFieldNames ? '' : 'addedAt')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  Contact clone() => Contact()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  Contact copyWith(void Function(Contact) updates) => super.copyWith((message) => updates(message as Contact)) as Contact;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static Contact create() => Contact._();
  Contact createEmptyInstance() => create();
  static $pb.PbList<Contact> createRepeated() => $pb.PbList<Contact>();
  @$core.pragma('dart2js:noInline')
  static Contact getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<Contact>(create);
  static Contact? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<$core.int> get verifyingKey => $_getN(0);
  @$pb.TagNumber(1)
  set verifyingKey($core.List<$core.int> v) { $_setBytes(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasVerifyingKey() => $_has(0);
  @$pb.TagNumber(1)
  void clearVerifyingKey() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get label => $_getSZ(1);
  @$pb.TagNumber(2)
  set label($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasLabel() => $_has(1);
  @$pb.TagNumber(2)
  void clearLabel() => clearField(2);

  @$pb.TagNumber(3)
  $fixnum.Int64 get addedAt => $_getI64(2);
  @$pb.TagNumber(3)
  set addedAt($fixnum.Int64 v) { $_setInt64(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasAddedAt() => $_has(2);
  @$pb.TagNumber(3)
  void clearAddedAt() => clearField(3);
}

class ContactAddRequest extends $pb.GeneratedMessage {
  factory ContactAddRequest({
    $core.List<$core.int>? contactVerifyingKey,
    $core.String? label,
  }) {
    final $result = create();
    if (contactVerifyingKey != null) {
      $result.contactVerifyingKey = contactVerifyingKey;
    }
    if (label != null) {
      $result.label = label;
    }
    return $result;
  }
  ContactAddRequest._() : super();
  factory ContactAddRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ContactAddRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ContactAddRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..a<$core.List<$core.int>>(2, _omitFieldNames ? '' : 'contactVerifyingKey', $pb.PbFieldType.OY)
    ..aOS(3, _omitFieldNames ? '' : 'label')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ContactAddRequest clone() => ContactAddRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ContactAddRequest copyWith(void Function(ContactAddRequest) updates) => super.copyWith((message) => updates(message as ContactAddRequest)) as ContactAddRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ContactAddRequest create() => ContactAddRequest._();
  ContactAddRequest createEmptyInstance() => create();
  static $pb.PbList<ContactAddRequest> createRepeated() => $pb.PbList<ContactAddRequest>();
  @$core.pragma('dart2js:noInline')
  static ContactAddRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ContactAddRequest>(create);
  static ContactAddRequest? _defaultInstance;

  @$pb.TagNumber(2)
  $core.List<$core.int> get contactVerifyingKey => $_getN(0);
  @$pb.TagNumber(2)
  set contactVerifyingKey($core.List<$core.int> v) { $_setBytes(0, v); }
  @$pb.TagNumber(2)
  $core.bool hasContactVerifyingKey() => $_has(0);
  @$pb.TagNumber(2)
  void clearContactVerifyingKey() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get label => $_getSZ(1);
  @$pb.TagNumber(3)
  set label($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(3)
  $core.bool hasLabel() => $_has(1);
  @$pb.TagNumber(3)
  void clearLabel() => clearField(3);
}

class ContactAddResponse extends $pb.GeneratedMessage {
  factory ContactAddResponse({
    $core.bool? ok,
  }) {
    final $result = create();
    if (ok != null) {
      $result.ok = ok;
    }
    return $result;
  }
  ContactAddResponse._() : super();
  factory ContactAddResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ContactAddResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ContactAddResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'ok')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ContactAddResponse clone() => ContactAddResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ContactAddResponse copyWith(void Function(ContactAddResponse) updates) => super.copyWith((message) => updates(message as ContactAddResponse)) as ContactAddResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ContactAddResponse create() => ContactAddResponse._();
  ContactAddResponse createEmptyInstance() => create();
  static $pb.PbList<ContactAddResponse> createRepeated() => $pb.PbList<ContactAddResponse>();
  @$core.pragma('dart2js:noInline')
  static ContactAddResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ContactAddResponse>(create);
  static ContactAddResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get ok => $_getBF(0);
  @$pb.TagNumber(1)
  set ok($core.bool v) { $_setBool(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasOk() => $_has(0);
  @$pb.TagNumber(1)
  void clearOk() => clearField(1);
}

class ContactRemoveRequest extends $pb.GeneratedMessage {
  factory ContactRemoveRequest({
    $core.List<$core.int>? contactVerifyingKey,
  }) {
    final $result = create();
    if (contactVerifyingKey != null) {
      $result.contactVerifyingKey = contactVerifyingKey;
    }
    return $result;
  }
  ContactRemoveRequest._() : super();
  factory ContactRemoveRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ContactRemoveRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ContactRemoveRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..a<$core.List<$core.int>>(2, _omitFieldNames ? '' : 'contactVerifyingKey', $pb.PbFieldType.OY)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ContactRemoveRequest clone() => ContactRemoveRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ContactRemoveRequest copyWith(void Function(ContactRemoveRequest) updates) => super.copyWith((message) => updates(message as ContactRemoveRequest)) as ContactRemoveRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ContactRemoveRequest create() => ContactRemoveRequest._();
  ContactRemoveRequest createEmptyInstance() => create();
  static $pb.PbList<ContactRemoveRequest> createRepeated() => $pb.PbList<ContactRemoveRequest>();
  @$core.pragma('dart2js:noInline')
  static ContactRemoveRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ContactRemoveRequest>(create);
  static ContactRemoveRequest? _defaultInstance;

  @$pb.TagNumber(2)
  $core.List<$core.int> get contactVerifyingKey => $_getN(0);
  @$pb.TagNumber(2)
  set contactVerifyingKey($core.List<$core.int> v) { $_setBytes(0, v); }
  @$pb.TagNumber(2)
  $core.bool hasContactVerifyingKey() => $_has(0);
  @$pb.TagNumber(2)
  void clearContactVerifyingKey() => clearField(2);
}

class ContactRemoveResponse extends $pb.GeneratedMessage {
  factory ContactRemoveResponse({
    $core.bool? ok,
  }) {
    final $result = create();
    if (ok != null) {
      $result.ok = ok;
    }
    return $result;
  }
  ContactRemoveResponse._() : super();
  factory ContactRemoveResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ContactRemoveResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ContactRemoveResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'ok')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ContactRemoveResponse clone() => ContactRemoveResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ContactRemoveResponse copyWith(void Function(ContactRemoveResponse) updates) => super.copyWith((message) => updates(message as ContactRemoveResponse)) as ContactRemoveResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ContactRemoveResponse create() => ContactRemoveResponse._();
  ContactRemoveResponse createEmptyInstance() => create();
  static $pb.PbList<ContactRemoveResponse> createRepeated() => $pb.PbList<ContactRemoveResponse>();
  @$core.pragma('dart2js:noInline')
  static ContactRemoveResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ContactRemoveResponse>(create);
  static ContactRemoveResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get ok => $_getBF(0);
  @$pb.TagNumber(1)
  set ok($core.bool v) { $_setBool(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasOk() => $_has(0);
  @$pb.TagNumber(1)
  void clearOk() => clearField(1);
}

class ContactListRequest extends $pb.GeneratedMessage {
  factory ContactListRequest() => create();
  ContactListRequest._() : super();
  factory ContactListRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ContactListRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ContactListRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ContactListRequest clone() => ContactListRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ContactListRequest copyWith(void Function(ContactListRequest) updates) => super.copyWith((message) => updates(message as ContactListRequest)) as ContactListRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ContactListRequest create() => ContactListRequest._();
  ContactListRequest createEmptyInstance() => create();
  static $pb.PbList<ContactListRequest> createRepeated() => $pb.PbList<ContactListRequest>();
  @$core.pragma('dart2js:noInline')
  static ContactListRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ContactListRequest>(create);
  static ContactListRequest? _defaultInstance;
}

class ContactListResponse extends $pb.GeneratedMessage {
  factory ContactListResponse({
    $core.Iterable<Contact>? contacts,
  }) {
    final $result = create();
    if (contacts != null) {
      $result.contacts.addAll(contacts);
    }
    return $result;
  }
  ContactListResponse._() : super();
  factory ContactListResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ContactListResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ContactListResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..pc<Contact>(1, _omitFieldNames ? '' : 'contacts', $pb.PbFieldType.PM, subBuilder: Contact.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ContactListResponse clone() => ContactListResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ContactListResponse copyWith(void Function(ContactListResponse) updates) => super.copyWith((message) => updates(message as ContactListResponse)) as ContactListResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ContactListResponse create() => ContactListResponse._();
  ContactListResponse createEmptyInstance() => create();
  static $pb.PbList<ContactListResponse> createRepeated() => $pb.PbList<ContactListResponse>();
  @$core.pragma('dart2js:noInline')
  static ContactListResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ContactListResponse>(create);
  static ContactListResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<Contact> get contacts => $_getList(0);
}

/// A request-to-pay held for the payer. NOT a pre-signed transaction: FROST is 2-round interactive
/// and Ark checkpoints need an ASP counter-signature, so no payment can be fully signed ahead of the
/// payer's approval. This records WHO asked, HOW MUCH, TO WHICH ADDRESS and UNTIL WHEN; the payer
/// reviews it and either signs the payment or declines.
class PaymentIntent extends $pb.GeneratedMessage {
  factory PaymentIntent({
    $core.String? id,
    $core.List<$core.int>? fromVerifyingKey,
    $core.String? toArkAddress,
    $fixnum.Int64? amountSats,
    $core.String? memo,
    $fixnum.Int64? createdAt,
    $fixnum.Int64? expiresAt,
    $core.String? status,
    $core.String? arkTxid,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    if (fromVerifyingKey != null) {
      $result.fromVerifyingKey = fromVerifyingKey;
    }
    if (toArkAddress != null) {
      $result.toArkAddress = toArkAddress;
    }
    if (amountSats != null) {
      $result.amountSats = amountSats;
    }
    if (memo != null) {
      $result.memo = memo;
    }
    if (createdAt != null) {
      $result.createdAt = createdAt;
    }
    if (expiresAt != null) {
      $result.expiresAt = expiresAt;
    }
    if (status != null) {
      $result.status = status;
    }
    if (arkTxid != null) {
      $result.arkTxid = arkTxid;
    }
    return $result;
  }
  PaymentIntent._() : super();
  factory PaymentIntent.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory PaymentIntent.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'PaymentIntent', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..a<$core.List<$core.int>>(2, _omitFieldNames ? '' : 'fromVerifyingKey', $pb.PbFieldType.OY)
    ..aOS(3, _omitFieldNames ? '' : 'toArkAddress')
    ..a<$fixnum.Int64>(4, _omitFieldNames ? '' : 'amountSats', $pb.PbFieldType.OU6, defaultOrMaker: $fixnum.Int64.ZERO)
    ..aOS(5, _omitFieldNames ? '' : 'memo')
    ..aInt64(6, _omitFieldNames ? '' : 'createdAt')
    ..aInt64(7, _omitFieldNames ? '' : 'expiresAt')
    ..aOS(8, _omitFieldNames ? '' : 'status')
    ..aOS(9, _omitFieldNames ? '' : 'arkTxid')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  PaymentIntent clone() => PaymentIntent()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  PaymentIntent copyWith(void Function(PaymentIntent) updates) => super.copyWith((message) => updates(message as PaymentIntent)) as PaymentIntent;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static PaymentIntent create() => PaymentIntent._();
  PaymentIntent createEmptyInstance() => create();
  static $pb.PbList<PaymentIntent> createRepeated() => $pb.PbList<PaymentIntent>();
  @$core.pragma('dart2js:noInline')
  static PaymentIntent getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<PaymentIntent>(create);
  static PaymentIntent? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get fromVerifyingKey => $_getN(1);
  @$pb.TagNumber(2)
  set fromVerifyingKey($core.List<$core.int> v) { $_setBytes(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasFromVerifyingKey() => $_has(1);
  @$pb.TagNumber(2)
  void clearFromVerifyingKey() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get toArkAddress => $_getSZ(2);
  @$pb.TagNumber(3)
  set toArkAddress($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasToArkAddress() => $_has(2);
  @$pb.TagNumber(3)
  void clearToArkAddress() => clearField(3);

  @$pb.TagNumber(4)
  $fixnum.Int64 get amountSats => $_getI64(3);
  @$pb.TagNumber(4)
  set amountSats($fixnum.Int64 v) { $_setInt64(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasAmountSats() => $_has(3);
  @$pb.TagNumber(4)
  void clearAmountSats() => clearField(4);

  @$pb.TagNumber(5)
  $core.String get memo => $_getSZ(4);
  @$pb.TagNumber(5)
  set memo($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasMemo() => $_has(4);
  @$pb.TagNumber(5)
  void clearMemo() => clearField(5);

  @$pb.TagNumber(6)
  $fixnum.Int64 get createdAt => $_getI64(5);
  @$pb.TagNumber(6)
  set createdAt($fixnum.Int64 v) { $_setInt64(5, v); }
  @$pb.TagNumber(6)
  $core.bool hasCreatedAt() => $_has(5);
  @$pb.TagNumber(6)
  void clearCreatedAt() => clearField(6);

  @$pb.TagNumber(7)
  $fixnum.Int64 get expiresAt => $_getI64(6);
  @$pb.TagNumber(7)
  set expiresAt($fixnum.Int64 v) { $_setInt64(6, v); }
  @$pb.TagNumber(7)
  $core.bool hasExpiresAt() => $_has(6);
  @$pb.TagNumber(7)
  void clearExpiresAt() => clearField(7);

  @$pb.TagNumber(8)
  $core.String get status => $_getSZ(7);
  @$pb.TagNumber(8)
  set status($core.String v) { $_setString(7, v); }
  @$pb.TagNumber(8)
  $core.bool hasStatus() => $_has(7);
  @$pb.TagNumber(8)
  void clearStatus() => clearField(8);

  @$pb.TagNumber(9)
  $core.String get arkTxid => $_getSZ(8);
  @$pb.TagNumber(9)
  set arkTxid($core.String v) { $_setString(8, v); }
  @$pb.TagNumber(9)
  $core.bool hasArkTxid() => $_has(8);
  @$pb.TagNumber(9)
  void clearArkTxid() => clearField(9);
}

/// Sent by the REQUESTER but routed to the PAYER's actor: `user_id` is the requester (who signs),
/// while the URL/actor id is the payer. The payer's allowlist is the only authorization.
class ArkInfo extends $pb.GeneratedMessage {
  factory ArkInfo({
    $core.String? signerPubkey,
    $core.String? forfeitPubkey,
    $core.String? forfeitAddress,
    $core.String? checkpointTapscript,
    $core.String? network,
    $fixnum.Int64? sessionDuration,
    $fixnum.Int64? unilateralExitDelay,
    $fixnum.Int64? boardingExitDelay,
    $fixnum.Int64? vtxoMinAmount,
    $fixnum.Int64? dust,
  }) {
    final $result = create();
    if (signerPubkey != null) {
      $result.signerPubkey = signerPubkey;
    }
    if (forfeitPubkey != null) {
      $result.forfeitPubkey = forfeitPubkey;
    }
    if (forfeitAddress != null) {
      $result.forfeitAddress = forfeitAddress;
    }
    if (checkpointTapscript != null) {
      $result.checkpointTapscript = checkpointTapscript;
    }
    if (network != null) {
      $result.network = network;
    }
    if (sessionDuration != null) {
      $result.sessionDuration = sessionDuration;
    }
    if (unilateralExitDelay != null) {
      $result.unilateralExitDelay = unilateralExitDelay;
    }
    if (boardingExitDelay != null) {
      $result.boardingExitDelay = boardingExitDelay;
    }
    if (vtxoMinAmount != null) {
      $result.vtxoMinAmount = vtxoMinAmount;
    }
    if (dust != null) {
      $result.dust = dust;
    }
    return $result;
  }
  ArkInfo._() : super();
  factory ArkInfo.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ArkInfo.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ArkInfo', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'signerPubkey')
    ..aOS(2, _omitFieldNames ? '' : 'forfeitPubkey')
    ..aOS(3, _omitFieldNames ? '' : 'forfeitAddress')
    ..aOS(4, _omitFieldNames ? '' : 'checkpointTapscript')
    ..aOS(5, _omitFieldNames ? '' : 'network')
    ..aInt64(6, _omitFieldNames ? '' : 'sessionDuration')
    ..aInt64(7, _omitFieldNames ? '' : 'unilateralExitDelay')
    ..aInt64(8, _omitFieldNames ? '' : 'boardingExitDelay')
    ..aInt64(9, _omitFieldNames ? '' : 'vtxoMinAmount')
    ..aInt64(10, _omitFieldNames ? '' : 'dust')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ArkInfo clone() => ArkInfo()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ArkInfo copyWith(void Function(ArkInfo) updates) => super.copyWith((message) => updates(message as ArkInfo)) as ArkInfo;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ArkInfo create() => ArkInfo._();
  ArkInfo createEmptyInstance() => create();
  static $pb.PbList<ArkInfo> createRepeated() => $pb.PbList<ArkInfo>();
  @$core.pragma('dart2js:noInline')
  static ArkInfo getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ArkInfo>(create);
  static ArkInfo? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get signerPubkey => $_getSZ(0);
  @$pb.TagNumber(1)
  set signerPubkey($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasSignerPubkey() => $_has(0);
  @$pb.TagNumber(1)
  void clearSignerPubkey() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get forfeitPubkey => $_getSZ(1);
  @$pb.TagNumber(2)
  set forfeitPubkey($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasForfeitPubkey() => $_has(1);
  @$pb.TagNumber(2)
  void clearForfeitPubkey() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get forfeitAddress => $_getSZ(2);
  @$pb.TagNumber(3)
  set forfeitAddress($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasForfeitAddress() => $_has(2);
  @$pb.TagNumber(3)
  void clearForfeitAddress() => clearField(3);

  @$pb.TagNumber(4)
  $core.String get checkpointTapscript => $_getSZ(3);
  @$pb.TagNumber(4)
  set checkpointTapscript($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasCheckpointTapscript() => $_has(3);
  @$pb.TagNumber(4)
  void clearCheckpointTapscript() => clearField(4);

  @$pb.TagNumber(5)
  $core.String get network => $_getSZ(4);
  @$pb.TagNumber(5)
  set network($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasNetwork() => $_has(4);
  @$pb.TagNumber(5)
  void clearNetwork() => clearField(5);

  @$pb.TagNumber(6)
  $fixnum.Int64 get sessionDuration => $_getI64(5);
  @$pb.TagNumber(6)
  set sessionDuration($fixnum.Int64 v) { $_setInt64(5, v); }
  @$pb.TagNumber(6)
  $core.bool hasSessionDuration() => $_has(5);
  @$pb.TagNumber(6)
  void clearSessionDuration() => clearField(6);

  @$pb.TagNumber(7)
  $fixnum.Int64 get unilateralExitDelay => $_getI64(6);
  @$pb.TagNumber(7)
  set unilateralExitDelay($fixnum.Int64 v) { $_setInt64(6, v); }
  @$pb.TagNumber(7)
  $core.bool hasUnilateralExitDelay() => $_has(6);
  @$pb.TagNumber(7)
  void clearUnilateralExitDelay() => clearField(7);

  @$pb.TagNumber(8)
  $fixnum.Int64 get boardingExitDelay => $_getI64(7);
  @$pb.TagNumber(8)
  set boardingExitDelay($fixnum.Int64 v) { $_setInt64(7, v); }
  @$pb.TagNumber(8)
  $core.bool hasBoardingExitDelay() => $_has(7);
  @$pb.TagNumber(8)
  void clearBoardingExitDelay() => clearField(8);

  @$pb.TagNumber(9)
  $fixnum.Int64 get vtxoMinAmount => $_getI64(8);
  @$pb.TagNumber(9)
  set vtxoMinAmount($fixnum.Int64 v) { $_setInt64(8, v); }
  @$pb.TagNumber(9)
  $core.bool hasVtxoMinAmount() => $_has(8);
  @$pb.TagNumber(9)
  void clearVtxoMinAmount() => clearField(9);

  @$pb.TagNumber(10)
  $fixnum.Int64 get dust => $_getI64(9);
  @$pb.TagNumber(10)
  set dust($fixnum.Int64 v) { $_setInt64(9, v); }
  @$pb.TagNumber(10)
  $core.bool hasDust() => $_has(9);
  @$pb.TagNumber(10)
  void clearDust() => clearField(10);
}

class PaymentRequestCreateRequest extends $pb.GeneratedMessage {
  factory PaymentRequestCreateRequest({
    $fixnum.Int64? amountSats,
    $core.String? memo,
    $fixnum.Int64? expiresInSecs,
    ArkInfo? arkInfo,
    RequestAuthorship? authorship,
  }) {
    final $result = create();
    if (amountSats != null) {
      $result.amountSats = amountSats;
    }
    if (memo != null) {
      $result.memo = memo;
    }
    if (expiresInSecs != null) {
      $result.expiresInSecs = expiresInSecs;
    }
    if (arkInfo != null) {
      $result.arkInfo = arkInfo;
    }
    if (authorship != null) {
      $result.authorship = authorship;
    }
    return $result;
  }
  PaymentRequestCreateRequest._() : super();
  factory PaymentRequestCreateRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory PaymentRequestCreateRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'PaymentRequestCreateRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..a<$fixnum.Int64>(2, _omitFieldNames ? '' : 'amountSats', $pb.PbFieldType.OU6, defaultOrMaker: $fixnum.Int64.ZERO)
    ..aOS(3, _omitFieldNames ? '' : 'memo')
    ..aInt64(4, _omitFieldNames ? '' : 'expiresInSecs')
    ..aOM<ArkInfo>(7, _omitFieldNames ? '' : 'arkInfo', subBuilder: ArkInfo.create)
    ..aOM<RequestAuthorship>(8, _omitFieldNames ? '' : 'authorship', subBuilder: RequestAuthorship.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  PaymentRequestCreateRequest clone() => PaymentRequestCreateRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  PaymentRequestCreateRequest copyWith(void Function(PaymentRequestCreateRequest) updates) => super.copyWith((message) => updates(message as PaymentRequestCreateRequest)) as PaymentRequestCreateRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static PaymentRequestCreateRequest create() => PaymentRequestCreateRequest._();
  PaymentRequestCreateRequest createEmptyInstance() => create();
  static $pb.PbList<PaymentRequestCreateRequest> createRepeated() => $pb.PbList<PaymentRequestCreateRequest>();
  @$core.pragma('dart2js:noInline')
  static PaymentRequestCreateRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<PaymentRequestCreateRequest>(create);
  static PaymentRequestCreateRequest? _defaultInstance;

  @$pb.TagNumber(2)
  $fixnum.Int64 get amountSats => $_getI64(0);
  @$pb.TagNumber(2)
  set amountSats($fixnum.Int64 v) { $_setInt64(0, v); }
  @$pb.TagNumber(2)
  $core.bool hasAmountSats() => $_has(0);
  @$pb.TagNumber(2)
  void clearAmountSats() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get memo => $_getSZ(1);
  @$pb.TagNumber(3)
  set memo($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(3)
  $core.bool hasMemo() => $_has(1);
  @$pb.TagNumber(3)
  void clearMemo() => clearField(3);

  @$pb.TagNumber(4)
  $fixnum.Int64 get expiresInSecs => $_getI64(2);
  @$pb.TagNumber(4)
  set expiresInSecs($fixnum.Int64 v) { $_setInt64(2, v); }
  @$pb.TagNumber(4)
  $core.bool hasExpiresInSecs() => $_has(2);
  @$pb.TagNumber(4)
  void clearExpiresInSecs() => clearField(4);

  /// The ASP parameters the payee address is derived with. From the caller, because the caller is
  /// the one talking to the ASP — and it cannot redirect the payment with them: the address is
  /// derived from the ALLOWLISTED key, never a supplied one.
  @$pb.TagNumber(7)
  ArkInfo get arkInfo => $_getN(3);
  @$pb.TagNumber(7)
  set arkInfo(ArkInfo v) { setField(7, v); }
  @$pb.TagNumber(7)
  $core.bool hasArkInfo() => $_has(3);
  @$pb.TagNumber(7)
  void clearArkInfo() => clearField(7);
  @$pb.TagNumber(7)
  ArkInfo ensureArkInfo() => $_ensure(3);

  /// Proof that the requester wrote this. Required.
  @$pb.TagNumber(8)
  RequestAuthorship get authorship => $_getN(4);
  @$pb.TagNumber(8)
  set authorship(RequestAuthorship v) { setField(8, v); }
  @$pb.TagNumber(8)
  $core.bool hasAuthorship() => $_has(4);
  @$pb.TagNumber(8)
  void clearAuthorship() => clearField(8);
  @$pb.TagNumber(8)
  RequestAuthorship ensureAuthorship() => $_ensure(4);
}

///  That a payment request was written by the wallet it names.
///
///  The caller of `PaymentRequestCreate` is the PAYER, not the requester. The runtime resolves a tenant
///  from the caller's own token and strips any tenant header a client sends, so nobody can address
///  another wallet's cosigner — a request has to travel out of band, and the payer's own app submits it
///  to the payer's own cosigner. The runtime therefore authenticates the payer, which says nothing about
///  who asked. This does.
///
///  It is a BIP-340 signature by the requester's GROUP key, which only the requester and the requester's
///  cosigner together can produce. That is the point of it being the group key: the old check took a
///  share key and resolved it to a group key through `policy_owner_idx`, an index DKG writes into each
///  wallet's own store — which worked only while every wallet shared one store, and would otherwise have
///  derived the payee address from a share key, an address the requester could not spend.
///
///  The signature covers
///
///  ```text
///  sha256( "merlin/payment-request/v1" ‖ payer_group_key ‖ requester_group_key
///          ‖ amount_sats ‖ expires_in_secs ‖ not_after ‖ nonce ‖ sha256(memo) )
///  ```
///
///  Fenced as text on purpose: prost copies these comments into the generated Rust as doc comments,
///  and an indented block there is compiled as a doctest.
///  with integers as 8-byte big-endian. The domain tag means it can never double as a transaction
///  sighash; the payer's key means a request to one wallet cannot be replayed to another; `not_after` and
///  the nonce mean it cannot be replayed to the same wallet later.
class RequestAuthorship extends $pb.GeneratedMessage {
  factory RequestAuthorship({
    $core.List<$core.int>? requesterGroupKey,
    $core.List<$core.int>? payerGroupKey,
    $fixnum.Int64? notAfter,
    $core.List<$core.int>? nonce,
    $core.List<$core.int>? signature,
  }) {
    final $result = create();
    if (requesterGroupKey != null) {
      $result.requesterGroupKey = requesterGroupKey;
    }
    if (payerGroupKey != null) {
      $result.payerGroupKey = payerGroupKey;
    }
    if (notAfter != null) {
      $result.notAfter = notAfter;
    }
    if (nonce != null) {
      $result.nonce = nonce;
    }
    if (signature != null) {
      $result.signature = signature;
    }
    return $result;
  }
  RequestAuthorship._() : super();
  factory RequestAuthorship.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory RequestAuthorship.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'RequestAuthorship', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..a<$core.List<$core.int>>(1, _omitFieldNames ? '' : 'requesterGroupKey', $pb.PbFieldType.OY)
    ..a<$core.List<$core.int>>(2, _omitFieldNames ? '' : 'payerGroupKey', $pb.PbFieldType.OY)
    ..aInt64(3, _omitFieldNames ? '' : 'notAfter')
    ..a<$core.List<$core.int>>(4, _omitFieldNames ? '' : 'nonce', $pb.PbFieldType.OY)
    ..a<$core.List<$core.int>>(5, _omitFieldNames ? '' : 'signature', $pb.PbFieldType.OY)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  RequestAuthorship clone() => RequestAuthorship()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  RequestAuthorship copyWith(void Function(RequestAuthorship) updates) => super.copyWith((message) => updates(message as RequestAuthorship)) as RequestAuthorship;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static RequestAuthorship create() => RequestAuthorship._();
  RequestAuthorship createEmptyInstance() => create();
  static $pb.PbList<RequestAuthorship> createRepeated() => $pb.PbList<RequestAuthorship>();
  @$core.pragma('dart2js:noInline')
  static RequestAuthorship getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<RequestAuthorship>(create);
  static RequestAuthorship? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<$core.int> get requesterGroupKey => $_getN(0);
  @$pb.TagNumber(1)
  set requesterGroupKey($core.List<$core.int> v) { $_setBytes(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasRequesterGroupKey() => $_has(0);
  @$pb.TagNumber(1)
  void clearRequesterGroupKey() => clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get payerGroupKey => $_getN(1);
  @$pb.TagNumber(2)
  set payerGroupKey($core.List<$core.int> v) { $_setBytes(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasPayerGroupKey() => $_has(1);
  @$pb.TagNumber(2)
  void clearPayerGroupKey() => clearField(2);

  @$pb.TagNumber(3)
  $fixnum.Int64 get notAfter => $_getI64(2);
  @$pb.TagNumber(3)
  set notAfter($fixnum.Int64 v) { $_setInt64(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasNotAfter() => $_has(2);
  @$pb.TagNumber(3)
  void clearNotAfter() => clearField(3);

  @$pb.TagNumber(4)
  $core.List<$core.int> get nonce => $_getN(3);
  @$pb.TagNumber(4)
  set nonce($core.List<$core.int> v) { $_setBytes(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasNonce() => $_has(3);
  @$pb.TagNumber(4)
  void clearNonce() => clearField(4);

  @$pb.TagNumber(5)
  $core.List<$core.int> get signature => $_getN(4);
  @$pb.TagNumber(5)
  set signature($core.List<$core.int> v) { $_setBytes(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasSignature() => $_has(4);
  @$pb.TagNumber(5)
  void clearSignature() => clearField(5);
}

class PaymentRequestCreateResponse extends $pb.GeneratedMessage {
  factory PaymentRequestCreateResponse({
    PaymentIntent? intent,
  }) {
    final $result = create();
    if (intent != null) {
      $result.intent = intent;
    }
    return $result;
  }
  PaymentRequestCreateResponse._() : super();
  factory PaymentRequestCreateResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory PaymentRequestCreateResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'PaymentRequestCreateResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..aOM<PaymentIntent>(1, _omitFieldNames ? '' : 'intent', subBuilder: PaymentIntent.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  PaymentRequestCreateResponse clone() => PaymentRequestCreateResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  PaymentRequestCreateResponse copyWith(void Function(PaymentRequestCreateResponse) updates) => super.copyWith((message) => updates(message as PaymentRequestCreateResponse)) as PaymentRequestCreateResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static PaymentRequestCreateResponse create() => PaymentRequestCreateResponse._();
  PaymentRequestCreateResponse createEmptyInstance() => create();
  static $pb.PbList<PaymentRequestCreateResponse> createRepeated() => $pb.PbList<PaymentRequestCreateResponse>();
  @$core.pragma('dart2js:noInline')
  static PaymentRequestCreateResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<PaymentRequestCreateResponse>(create);
  static PaymentRequestCreateResponse? _defaultInstance;

  @$pb.TagNumber(1)
  PaymentIntent get intent => $_getN(0);
  @$pb.TagNumber(1)
  set intent(PaymentIntent v) { setField(1, v); }
  @$pb.TagNumber(1)
  $core.bool hasIntent() => $_has(0);
  @$pb.TagNumber(1)
  void clearIntent() => clearField(1);
  @$pb.TagNumber(1)
  PaymentIntent ensureIntent() => $_ensure(0);
}

class PaymentRequestListRequest extends $pb.GeneratedMessage {
  factory PaymentRequestListRequest() => create();
  PaymentRequestListRequest._() : super();
  factory PaymentRequestListRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory PaymentRequestListRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'PaymentRequestListRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  PaymentRequestListRequest clone() => PaymentRequestListRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  PaymentRequestListRequest copyWith(void Function(PaymentRequestListRequest) updates) => super.copyWith((message) => updates(message as PaymentRequestListRequest)) as PaymentRequestListRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static PaymentRequestListRequest create() => PaymentRequestListRequest._();
  PaymentRequestListRequest createEmptyInstance() => create();
  static $pb.PbList<PaymentRequestListRequest> createRepeated() => $pb.PbList<PaymentRequestListRequest>();
  @$core.pragma('dart2js:noInline')
  static PaymentRequestListRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<PaymentRequestListRequest>(create);
  static PaymentRequestListRequest? _defaultInstance;
}

class PaymentRequestListResponse extends $pb.GeneratedMessage {
  factory PaymentRequestListResponse({
    $core.Iterable<PaymentIntent>? intents,
  }) {
    final $result = create();
    if (intents != null) {
      $result.intents.addAll(intents);
    }
    return $result;
  }
  PaymentRequestListResponse._() : super();
  factory PaymentRequestListResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory PaymentRequestListResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'PaymentRequestListResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..pc<PaymentIntent>(1, _omitFieldNames ? '' : 'intents', $pb.PbFieldType.PM, subBuilder: PaymentIntent.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  PaymentRequestListResponse clone() => PaymentRequestListResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  PaymentRequestListResponse copyWith(void Function(PaymentRequestListResponse) updates) => super.copyWith((message) => updates(message as PaymentRequestListResponse)) as PaymentRequestListResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static PaymentRequestListResponse create() => PaymentRequestListResponse._();
  PaymentRequestListResponse createEmptyInstance() => create();
  static $pb.PbList<PaymentRequestListResponse> createRepeated() => $pb.PbList<PaymentRequestListResponse>();
  @$core.pragma('dart2js:noInline')
  static PaymentRequestListResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<PaymentRequestListResponse>(create);
  static PaymentRequestListResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<PaymentIntent> get intents => $_getList(0);
}

class PaymentRequestDeclineRequest extends $pb.GeneratedMessage {
  factory PaymentRequestDeclineRequest({
    $core.String? id,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    return $result;
  }
  PaymentRequestDeclineRequest._() : super();
  factory PaymentRequestDeclineRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory PaymentRequestDeclineRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'PaymentRequestDeclineRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..aOS(2, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  PaymentRequestDeclineRequest clone() => PaymentRequestDeclineRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  PaymentRequestDeclineRequest copyWith(void Function(PaymentRequestDeclineRequest) updates) => super.copyWith((message) => updates(message as PaymentRequestDeclineRequest)) as PaymentRequestDeclineRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static PaymentRequestDeclineRequest create() => PaymentRequestDeclineRequest._();
  PaymentRequestDeclineRequest createEmptyInstance() => create();
  static $pb.PbList<PaymentRequestDeclineRequest> createRepeated() => $pb.PbList<PaymentRequestDeclineRequest>();
  @$core.pragma('dart2js:noInline')
  static PaymentRequestDeclineRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<PaymentRequestDeclineRequest>(create);
  static PaymentRequestDeclineRequest? _defaultInstance;

  @$pb.TagNumber(2)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(2)
  set id($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(2)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(2)
  void clearId() => clearField(2);
}

class PaymentRequestDeclineResponse extends $pb.GeneratedMessage {
  factory PaymentRequestDeclineResponse({
    $core.bool? ok,
  }) {
    final $result = create();
    if (ok != null) {
      $result.ok = ok;
    }
    return $result;
  }
  PaymentRequestDeclineResponse._() : super();
  factory PaymentRequestDeclineResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory PaymentRequestDeclineResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'PaymentRequestDeclineResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'mpc_wallet'), createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'ok')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  PaymentRequestDeclineResponse clone() => PaymentRequestDeclineResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  PaymentRequestDeclineResponse copyWith(void Function(PaymentRequestDeclineResponse) updates) => super.copyWith((message) => updates(message as PaymentRequestDeclineResponse)) as PaymentRequestDeclineResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static PaymentRequestDeclineResponse create() => PaymentRequestDeclineResponse._();
  PaymentRequestDeclineResponse createEmptyInstance() => create();
  static $pb.PbList<PaymentRequestDeclineResponse> createRepeated() => $pb.PbList<PaymentRequestDeclineResponse>();
  @$core.pragma('dart2js:noInline')
  static PaymentRequestDeclineResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<PaymentRequestDeclineResponse>(create);
  static PaymentRequestDeclineResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get ok => $_getBF(0);
  @$pb.TagNumber(1)
  set ok($core.bool v) { $_setBool(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasOk() => $_has(0);
  @$pb.TagNumber(1)
  void clearOk() => clearField(1);
}


const _omitFieldNames = $core.bool.fromEnvironment('protobuf.omit_field_names');
const _omitMessageNames = $core.bool.fromEnvironment('protobuf.omit_message_names');
