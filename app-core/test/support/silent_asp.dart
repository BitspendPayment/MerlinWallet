/// An ASP that takes an intent and then says nothing, ever.
///
/// What a half-open connection looks like, or an ASP that fell over between registering an intent
/// and running its batch: `RegisterIntent` answers, the event stream opens, and no event comes. A
/// real settle waits there for minutes by design — so nothing about the wait itself can tell the
/// wallet the ASP has gone. It is the case cancellation exists for.
library;

import 'dart:async';

import 'package:grpc/grpc.dart';
import 'package:protocol/ark_v1.dart' as ark;

import 'package:app_core/asp/asp_client.dart';

class SilentAsp extends AspClient {
  // Never dialled: everything a settle asks of the ASP before the wait is answered here.
  SilentAsp()
      : super(ClientChannel('127.0.0.1',
            port: 9, options: const ChannelOptions(credentials: ChannelCredentials.insecure())));

  int intentsRegistered = 0;

  /// Whether somebody is listening for events — and, afterwards, whether they stopped.
  bool listening = false;
  bool listenerLeft = false;

  @override
  Future<ArkInfo> getInfo({bool refresh = false}) async => const ArkInfo(
        signerPubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        forfeitPubkey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        forfeitAddress: 'bcrt1qq5rjlmqartxjyh6vnmjrhrqnc58q2hqr5asln0',
        checkpointTapscript: '',
        network: 'regtest',
        sessionDuration: 0,
        unilateralExitDelay: 512,
        boardingExitDelay: 144,
        vtxoMinAmount: 0,
        dust: 330,
      );

  @override
  Future<String> registerIntent(String proof, String message) async {
    intentsRegistered++;
    return 'intent-$intentsRegistered';
  }

  @override
  Stream<ark.GetEventStreamResponse> getEventStream(List<String> topics) {
    late final StreamController<ark.GetEventStreamResponse> events;
    events = StreamController(
      onListen: () => listening = true,
      onCancel: () => listenerLeft = true,
    );
    return events.stream;
  }
}
