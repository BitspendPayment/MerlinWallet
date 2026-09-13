/// The wallet's connection to its cosigner.
///
/// One service, `cosigner.v1.Cosigner`: four bidirectional streams for the ceremonies and seven
/// single-round calls beside them. This owns the channel and the generated stub, and hands the
/// session drivers a duplex to work over.
///
/// Authentication goes in the *request body*, not in metadata — the cosigner's `check()` reads
/// `user_id`/`signature`/`timestamp_ms` off the message — so `ClientAuthHelper` is unchanged by the
/// move from REST. Each of the four streams authenticates once, at its open, for the whole session.
library;

import 'dart:async';

import 'package:async/async.dart';
import 'package:grpc/grpc.dart';
import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:protocol/protocol.dart';

/// A ceremony in flight: what to send, and what has come back.
///
/// `StreamQueue` rather than `await for`, because every one of these protocols is strict ping-pong
/// — say a thing, read the answer — and a queue is the shape that reads as. It also buffers from
/// the moment the stream opens, which is what lets the Settle driver subscribe to the ASP before
/// telling the cosigner the intent is registered without losing what arrives in between.
class Duplex<Q, R> {
  Duplex(this._out, Stream<R> inbound) : inbound = StreamQueue<R>(inbound);

  final StreamController<Q> _out;
  final StreamQueue<R> inbound;

  void send(Q msg) => _out.add(msg);

  /// The next message, or a [CosignerException] if the stream ended first. A ceremony that ends
  /// early is a failure, never a quiet success: the caller is mid-protocol and has no result.
  Future<R> next(String expecting) async {
    if (!await inbound.hasNext) {
      throw CosignerException('the cosigner closed the stream before $expecting');
    }
    return inbound.next;
  }

  Future<void> close() async {
    await _out.close();
    await inbound.cancel(immediate: true);
  }
}

/// Raised when the cosigner refuses or the ceremony cannot continue. Distinct from `AspException`:
/// they are different parties, and which one failed decides whether retrying is worth anything.
class CosignerException implements Exception {
  CosignerException(this.message);
  final String message;
  @override
  String toString() => 'cosigner: $message';
}

class CosignerConnection {
  CosignerConnection(this._channel) : _stub = cs.CosignerClient(_channel);

  factory CosignerConnection.connect(String host, int port, {bool secure = false}) {
    return CosignerConnection(ClientChannel(
      host,
      port: port,
      options: ChannelOptions(
        credentials:
            secure ? const ChannelCredentials.secure() : const ChannelCredentials.insecure(),
      ),
    ));
  }

  final ClientChannel _channel;
  final cs.CosignerClient _stub;

  // --- The four ceremonies ----------------------------------------------------------------------

  Duplex<cs.SignClientMsg, cs.SignServerMsg> openSign() {
    final out = StreamController<cs.SignClientMsg>();
    return Duplex(out, _stub.sign(out.stream));
  }

  Duplex<cs.DkgClientMsg, cs.DkgServerMsg> openDkg() {
    final out = StreamController<cs.DkgClientMsg>();
    return Duplex(out, _stub.dkg(out.stream));
  }

  Duplex<cs.SendClientMsg, cs.SendServerMsg> openSend() {
    final out = StreamController<cs.SendClientMsg>();
    return Duplex(out, _stub.send(out.stream));
  }

  Duplex<cs.SettleClientMsg, cs.SettleServerMsg> openSettle() {
    final out = StreamController<cs.SettleClientMsg>();
    return Duplex(out, _stub.settle(out.stream));
  }

  // --- The single-round calls -------------------------------------------------------------------

  Future<GetServerInfoResponse> getServerInfo() =>
      _stub.getServerInfo(GetServerInfoRequest());

  Future<ContactAddResponse> contactAdd(ContactAddRequest r) => _stub.contactAdd(r);
  Future<ContactRemoveResponse> contactRemove(ContactRemoveRequest r) => _stub.contactRemove(r);
  Future<ContactListResponse> contactList(ContactListRequest r) => _stub.contactList(r);

  Future<PaymentRequestCreateResponse> paymentRequestCreate(PaymentRequestCreateRequest r) =>
      _stub.paymentRequestCreate(r);
  Future<PaymentRequestListResponse> paymentRequestList(PaymentRequestListRequest r) =>
      _stub.paymentRequestList(r);
  Future<PaymentRequestDeclineResponse> paymentRequestDecline(PaymentRequestDeclineRequest r) =>
      _stub.paymentRequestDecline(r);

  /// Enrol a device for wake signals. The cosigner forwards this to the runtime and keeps nothing —
  /// it has no push channel of its own, and `deviceCount` returns a number rather than the tokens
  /// because it is not meant to be able to enumerate a tenant's devices.
  Future<void> registerDevice(cs.RegisterDeviceRequest r) => _stub.registerDevice(r);
  Future<void> forgetDevice(cs.ForgetDeviceRequest r) => _stub.forgetDevice(r);
  Future<int> deviceCount(cs.DeviceCountRequest r) async =>
      (await _stub.deviceCount(r)).devices;

  Future<void> shutdown() => _channel.shutdown();
}
