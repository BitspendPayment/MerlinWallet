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

/// The ASP's parameters, as its `GetInfo` reports them. Supplied by the caller, because the caller is
/// the one talking to the ASP — see `RenewOpen` in cosign_session.proto for why a wrong one cannot
/// redirect funds.
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


const _omitFieldNames = $core.bool.fromEnvironment('protobuf.omit_field_names');
const _omitMessageNames = $core.bool.fromEnvironment('protobuf.omit_message_names');
