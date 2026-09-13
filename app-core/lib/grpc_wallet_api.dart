/// gRPC implementation of [WalletApi] — wraps the generated [MPCWalletClient] stub.
library;

import 'package:grpc/src/client/channel.dart' as grpc_base;
import 'package:protocol/protocol.dart';
import 'wallet_api.dart';

class GrpcWalletApi implements WalletApi {
  final MPCWalletClient _stub;
  final grpc_base.ClientChannel _channel;

  GrpcWalletApi(grpc_base.ClientChannel channel)
      : _channel = channel,
        _stub = MPCWalletClient(channel);

  @override
  Future<DKGStep1Response> dKGStep1(DKGStep1Request r) => _stub.dKGStep1(r);
  @override
  Future<DKGStep2Response> dKGStep2(DKGStep2Request r) => _stub.dKGStep2(r);
  @override
  Future<DKGStep3Response> dKGStep3(DKGStep3Request r) => _stub.dKGStep3(r);

  @override
   @override
   @override
   @override
  Future<SignStep1Response> signStep1(SignStep1Request r,
          {String? routeGroupKeyHex}) =>
      _stub.signStep1(r);
  @override
  Future<SignStep2Response> signStep2(SignStep2Request r,
          {String? routeGroupKeyHex}) =>
      _stub.signStep2(r);

  @override
  Future<GetArkInfoResponse> getArkInfo(GetArkInfoRequest r) =>
      _stub.getArkInfo(r);
  @override
  Future<GetArkAddressResponse> getArkAddress(GetArkAddressRequest r) =>
      _stub.getArkAddress(r);
  @override
  Future<GetBoardingAddressResponse> getBoardingAddress(
          GetBoardingAddressRequest r) =>
      _stub.getBoardingAddress(r);
  @override
  Future<ListVtxosResponse> listVtxos(ListVtxosRequest r) =>
      _stub.listVtxos(r);
  @override
   @override
  Future<SendVtxoResponse> sendVtxo(SendVtxoRequest r) => _stub.sendVtxo(r);
  @override
  Future<RedeemVtxoResponse> redeemVtxo(RedeemVtxoRequest r) =>
      _stub.redeemVtxo(r);
  @override
  Future<SettleResponse> settle(SettleRequest r) => _stub.settle(r);
  @override
  Future<SettleDelegateResponse> settleDelegate(SettleDelegateRequest r) =>
      _stub.settleDelegate(r);
  @override
  Future<SubmitArkSendResponse> submitArkSend(SubmitArkSendRequest r) =>
      _stub.submitArkSend(r);

  // Request-to-pay is REST-only: the runtime serves no gRPC (nothing binds MPCWallet), so these
  // exist solely to satisfy the interface.
  @override
  Future<ContactAddResponse> contactAdd(ContactAddRequest r) =>
      throw UnsupportedError('request-to-pay is REST-only');
  @override
  Future<ContactRemoveResponse> contactRemove(ContactRemoveRequest r) =>
      throw UnsupportedError('request-to-pay is REST-only');
  @override
  Future<ContactListResponse> contactList(ContactListRequest r) =>
      throw UnsupportedError('request-to-pay is REST-only');
  @override
  Future<PaymentRequestCreateResponse> createPaymentRequest(
          PaymentRequestCreateRequest r, String payerGroupKeyHex) =>
      throw UnsupportedError('request-to-pay is REST-only');
  @override
  Future<PaymentRequestListResponse> paymentRequestList(
          PaymentRequestListRequest r) =>
      throw UnsupportedError('request-to-pay is REST-only');
  @override
  Future<PaymentRequestDeclineResponse> paymentRequestDecline(
          PaymentRequestDeclineRequest r) =>
      throw UnsupportedError('request-to-pay is REST-only');

  @override
  Future<GetServerInfoResponse> getServerInfo(GetServerInfoRequest r) =>
      _stub.getServerInfo(r);

  @override
   @override
  Future<void> shutdown() => _channel.shutdown();
}
