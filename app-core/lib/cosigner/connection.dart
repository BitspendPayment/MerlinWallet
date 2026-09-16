/// The wallet's connection to its cosigner.
///
/// One service, `cosigner.v1.Cosigner`: four bidirectional streams for the ceremonies and seven
/// single-round calls beside them. This owns the channel and the generated stub, and hands the
/// session drivers a duplex to work over.
///
/// Authentication is not in here, and not in the messages either. Every request used to carry a
/// Schnorr signature by the wallet's share key in its body; enclave-runtime now gates every request on
/// a WebAuthn assertion bound to its exact method and path, and the cosigner requires the tenant that
/// resolved to and nothing else. So an approval rides as metadata on each call — see `Approver` —
/// and a stream is approved once, at open, for its whole life.
library;

import 'dart:async';

import 'package:async/async.dart';
import 'package:grpc/grpc.dart';
import 'package:grpc/grpc_connection_interface.dart' show ClientChannelBase;
import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:protocol/protocol.dart';

import '../enclave/approval.dart';
import '../enclave/gate.dart';
import '../enclave/pinned_transport.dart';

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
  CosignerConnection(this._channel, {Approver? approver})
      : _stub = cs.CosignerClient(_channel),
        _approver = approver;

  /// Dial a cosigner with no enclave in front of it — plaintext, unapproved. Nothing enclave-runtime
  /// serves answers this; it exists for a cosigner hosted some other way.
  factory CosignerConnection.connect(String host, int port) => CosignerConnection(
        ClientChannel(
          host,
          port: port,
          options: const ChannelOptions(credentials: ChannelCredentials.insecure()),
        ),
      );

  /// Dial the cosigner inside an enclave, through [gate].
  ///
  /// Every call is approved by the gate before it is dispatched, and every connection is refused
  /// unless it serves the certificate the gate last attested — see `PinnedTransportConnector`. Those
  /// two together are what make a gRPC response the attested enclave's, when the response itself
  /// carries no document.
  factory CosignerConnection.enclave(EnclaveGate gate) => CosignerConnection(
        ClientTransportConnectorChannel(PinnedTransportConnector(gate.endpoint, gate)),
        approver: gateApprover(gate),
      );

  final ClientChannelBase _channel;
  final cs.CosignerClient _stub;
  final Approver? _approver;

  /// The options for one call to [method], approval included. Awaited before the call exists, never
  /// inside it — see `Approver` for why.
  Future<CallOptions> _approved(String method) async {
    final approver = _approver;
    if (approver == null) return CallOptions();
    return CallOptions(metadata: await approver('/cosigner.v1.Cosigner/$method'));
  }

  /// A stream that opens once its approval is in hand. The duplex exists at once so a driver can
  /// queue its first message; nothing is dialled until the token is.
  Stream<R> _stream<R>(String method, Stream<R> Function(CallOptions) open) =>
      Stream.fromFuture(_approved(method)).asyncExpand(open);

  // --- The four ceremonies ----------------------------------------------------------------------

  Duplex<cs.SignClientMsg, cs.SignServerMsg> openSign() {
    final out = StreamController<cs.SignClientMsg>();
    return Duplex(out, _stream('Sign', (o) => _stub.sign(out.stream, options: o)));
  }

  Duplex<cs.DkgClientMsg, cs.DkgServerMsg> openDkg() {
    final out = StreamController<cs.DkgClientMsg>();
    return Duplex(out, _stream('Dkg', (o) => _stub.dkg(out.stream, options: o)));
  }

  Duplex<cs.SendClientMsg, cs.SendServerMsg> openSend() {
    final out = StreamController<cs.SendClientMsg>();
    return Duplex(out, _stream('Send', (o) => _stub.send(out.stream, options: o)));
  }

  Duplex<cs.SettleClientMsg, cs.SettleServerMsg> openSettle() {
    final out = StreamController<cs.SettleClientMsg>();
    return Duplex(out, _stream('Settle', (o) => _stub.settle(out.stream, options: o)));
  }

  // --- The single-round calls -------------------------------------------------------------------

  Future<GetServerInfoResponse> getServerInfo() async =>
      _stub.getServerInfo(GetServerInfoRequest(), options: await _approved('GetServerInfo'));

  Future<ContactAddResponse> contactAdd(ContactAddRequest r) async =>
      _stub.contactAdd(r, options: await _approved('ContactAdd'));
  Future<ContactRemoveResponse> contactRemove(ContactRemoveRequest r) async =>
      _stub.contactRemove(r, options: await _approved('ContactRemove'));
  Future<ContactListResponse> contactList(ContactListRequest r) async =>
      _stub.contactList(r, options: await _approved('ContactList'));

  Future<PaymentRequestCreateResponse> paymentRequestCreate(PaymentRequestCreateRequest r) async =>
      _stub.paymentRequestCreate(r, options: await _approved('PaymentRequestCreate'));
  Future<PaymentRequestListResponse> paymentRequestList(PaymentRequestListRequest r) async =>
      _stub.paymentRequestList(r, options: await _approved('PaymentRequestList'));
  Future<PaymentRequestDeclineResponse> paymentRequestDecline(PaymentRequestDeclineRequest r) async =>
      _stub.paymentRequestDecline(r, options: await _approved('PaymentRequestDecline'));

  /// Enrol a device for wake signals. The cosigner forwards this to the runtime and keeps nothing —
  /// it has no push channel of its own, and `deviceCount` returns a number rather than the tokens
  /// because it is not meant to be able to enumerate a tenant's devices.
  Future<void> registerDevice(cs.RegisterDeviceRequest r) async =>
      _stub.registerDevice(r, options: await _approved('RegisterDevice'));
  Future<void> forgetDevice(cs.ForgetDeviceRequest r) async =>
      _stub.forgetDevice(r, options: await _approved('ForgetDevice'));
  Future<int> deviceCount(cs.DeviceCountRequest r) async =>
      (await _stub.deviceCount(r, options: await _approved('DeviceCount'))).devices;

  Future<void> shutdown() => _channel.shutdown();
}
