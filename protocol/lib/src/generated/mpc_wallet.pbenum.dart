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

import 'package:protobuf/protobuf.dart' as $pb;

class SendVtxoResponse_Status extends $pb.ProtobufEnum {
  static const SendVtxoResponse_Status SIGNING_REQUIRED = SendVtxoResponse_Status._(0, _omitEnumNames ? '' : 'SIGNING_REQUIRED');
  static const SendVtxoResponse_Status SETTLED = SendVtxoResponse_Status._(1, _omitEnumNames ? '' : 'SETTLED');
  static const SendVtxoResponse_Status ERROR = SendVtxoResponse_Status._(2, _omitEnumNames ? '' : 'ERROR');

  static const $core.List<SendVtxoResponse_Status> values = <SendVtxoResponse_Status> [
    SIGNING_REQUIRED,
    SETTLED,
    ERROR,
  ];

  static final $core.Map<$core.int, SendVtxoResponse_Status> _byValue = $pb.ProtobufEnum.initByValue(values);
  static SendVtxoResponse_Status? valueOf($core.int value) => _byValue[value];

  const SendVtxoResponse_Status._($core.int v, $core.String n) : super(v, n);
}


const _omitEnumNames = $core.bool.fromEnvironment('protobuf.omit_enum_names');
