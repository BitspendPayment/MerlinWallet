/// A cosigner that lives in the test process.
///
/// The real one is a wasm component inside an enclave, and proving what `MpcClient` does with its
/// secrets should not need one. This speaks the same three parts of `cosigner.v1.Cosigner` the
/// wallet's own lifecycle needs — `Dkg`, `Sign`, `Recover` — over real gRPC on a loopback port,
/// playing the cosigner's half of each ceremony with the same threshold library the wallet uses.
/// `Send` and `Settle` need an ASP and are the e2e suite's.
///
/// It keeps the contract the real one keeps (`cosigner/src/handlers/recover.rs`,
/// `cosigner/tests/stream_contribution_test.rs`): what it dealt the wallet comes back on the first
/// round of `Sign` and from `Recover`, only to the identifier the ceremony recorded, and its own
/// share never leaves. And it can be told to misbehave, which the real one cannot.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:grpc/grpc.dart';
import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:protocol/protocol.dart';

import 'package:app_core/threshold/frost/commitment.dart' as frost_comm;
import 'package:app_core/threshold/frost/signing.dart' as frost;
import 'package:app_core/threshold_types.dart' as threshold;

/// How the fake should break the next `Sign`, if at all.
enum SignFault {
  none,

  /// Return a scalar that is not what was dealt.
  wrongShare,

  /// Return no share at all, as a cosigner from before this change would.
  noShare,

  /// Send the first round, then fail the stream.
  failAfterCommitments,

  /// Send the first round, then never answer: the stream stays open until somebody gives up.
  hangAfterCommitments,
}

class FakeCosigner extends cs.CosignerServiceBase {
  threshold.KeyPackage? _keyPackage;
  threshold.PublicKeyPackage? _publicKeyPackage;
  threshold.Identifier? _walletIdentifier;

  /// `f_cosigner(wallet identifier)`: what this cosigner dealt the wallet, and hands back.
  Uint8List? dealtShare;

  /// The cosigner's OWN share. Here so a test can show it is never what comes back.
  BigInt? get ownShare => _keyPackage?.secretShare;

  threshold.PublicKeyPackage? get publicKeyPackage => _publicKeyPackage;

  SignFault fault = SignFault.none;

  /// Completed by a test to let a `Sign` that is being held open carry on. See [holdSigns].
  Completer<void>? holdSigns;

  int signsOpened = 0;
  int signsInFlight = 0;
  int mostSignsAtOnce = 0;
  int recoversAnswered = 0;

  /// Completed by a test to let a `Recover` that is being held carry on: a cosigner that is slow
  /// to answer, so that something can happen while the wallet waits.
  Completer<void>? holdRecover;

  /// Completes when a held `Recover` has been asked, and is waiting.
  Completer<void> recoverWaiting = Completer<void>();

  /// Every identifier a `Sign` or `Recover` was asked with, as hex.
  final List<String> askedAs = [];

  Server? _server;

  Future<int> start() async {
    final server = Server.create(services: [this]);
    await server.serve(address: '127.0.0.1', port: 0);
    _server = server;
    return server.port!;
  }

  Future<void> stop() async => _server?.shutdown();

  static String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  // --- Dkg -------------------------------------------------------------------------------------

  @override
  Stream<cs.DkgServerMsg> dkg(ServiceCall call, Stream<cs.DkgClientMsg> request) async* {
    final inbound = StreamIterator(request);
    if (!await inbound.moveNext() || !inbound.current.hasOpen()) {
      throw GrpcError.invalidArgument('a session must open with DkgOpen');
    }
    if (_keyPackage != null) {
      throw GrpcError.failedPrecondition('this wallet already has a key');
    }
    final open = inbound.current.open;
    final walletId = threshold.Identifier.deserialize(Uint8List.fromList(open.identifier));
    final walletR1 = threshold.Round1Package.fromJson(jsonDecode(open.round1Package));

    final (r1Secret, r1Package) =
        threshold.dkgPart1(2, 2, threshold.newSecretKey(), [threshold.modNRandom()]);
    final ownId = r1Secret.identifier;

    yield cs.DkgServerMsg(
      seq: Int64(1),
      round1: cs.DkgRound1Out(round1Packages: {
        _hex(ownId.serialize()): jsonEncode(r1Package.toJson()),
        _hex(walletId.serialize()): open.round1Package,
      }),
    );

    if (!await inbound.moveNext() || !inbound.current.hasRound2()) {
      throw GrpcError.invalidArgument('expected DkgRound2');
    }
    final fromWallet = inbound.current.round2.round2PackagesForOthers[_hex(ownId.serialize())];
    if (fromWallet == null) throw GrpcError.invalidArgument('no round-2 package for the cosigner');

    final (r2Secret, dealt) = threshold.dkgPart2(r1Secret, {walletId: walletR1});
    final (keyPackage, publicKeyPackage) = threshold.dkgPart3(
      r1Secret,
      r2Secret,
      {walletId: walletR1},
      {walletId: threshold.Round2Package.fromJson(jsonDecode(fromWallet))},
    );

    _keyPackage = keyPackage;
    _publicKeyPackage = publicKeyPackage;
    _walletIdentifier = walletId;
    dealtShare = threshold.bigIntToBytes(dealt[walletId]!.secretShare);

    yield cs.DkgServerMsg(
      seq: Int64(2),
      complete: cs.DkgComplete(
        round2PackagesForMe: {_hex(ownId.serialize()): jsonEncode(dealt[walletId]!.toJson())},
        groupKey: _hex(threshold.elemSerializeCompressed(publicKeyPackage.verifyingKey.E)),
      ),
    );
  }

  // --- The contribution --------------------------------------------------------------------------

  /// As `dealt_share_for` in the real cosigner: only to the identifier the ceremony recorded.
  Uint8List _dealtShareFor(List<int> identifier) {
    askedAs.add(_hex(identifier));
    final expected = _walletIdentifier;
    final share = dealtShare;
    if (expected == null || share == null) {
      throw GrpcError.failedPrecondition('this wallet has no key yet');
    }
    if (identifier.length != 32) throw GrpcError.invalidArgument('identifier must be 32 bytes');
    if (threshold.Identifier.deserialize(Uint8List.fromList(identifier)) != expected) {
      throw GrpcError.permissionDenied("that passkey does not derive this wallet's owner key");
    }
    return share;
  }

  // --- Sign --------------------------------------------------------------------------------------

  @override
  Stream<cs.SignServerMsg> sign(ServiceCall call, Stream<cs.SignClientMsg> request) async* {
    signsOpened++;
    signsInFlight++;
    if (signsInFlight > mostSignsAtOnce) mostSignsAtOnce = signsInFlight;
    try {
      final inbound = StreamIterator(request);
      if (!await inbound.moveNext() || !inbound.current.hasOpen()) {
        throw GrpcError.invalidArgument('a session must open with SignOpen');
      }
      final open = inbound.current.open;
      if (!open.scriptPathSpend) throw GrpcError.invalidArgument('Sign is script-path only');
      final dealt = _dealtShareFor(open.identifier);
      await holdSigns?.future;

      final keyPackage = _keyPackage!;
      final message = Uint8List.fromList(open.messageToSign);
      final nonce = frost_comm.newNonce(keyPackage.secretShare);
      final ownId = _hex(keyPackage.identifier.serialize());

      yield cs.SignServerMsg(
        seq: Int64(1),
        commitments: cs.SignCommitments(
          commitments: {
            ownId: cs.Commitment(
              hiding: threshold.elemSerializeCompressed(nonce.commitments.hiding),
              binding: threshold.elemSerializeCompressed(nonce.commitments.binding),
            ),
          },
          messageToSign: message,
          walletDealtShare: switch (fault) {
            SignFault.wrongShare => Uint8List.fromList([...dealt]..[31] ^= 0x01),
            SignFault.noShare => const <int>[],
            _ => dealt,
          },
        ),
      );

      if (fault == SignFault.failAfterCommitments) {
        throw GrpcError.internal('the cosigner fell over mid-ceremony');
      }
      if (fault == SignFault.hangAfterCommitments) {
        // Until the client goes away: its share arrives and is ignored, and `moveNext` completes
        // false only when the stream is torn down.
        while (await inbound.moveNext()) {}
        return;
      }

      if (!await inbound.moveNext() || !inbound.current.hasShare()) {
        throw GrpcError.invalidArgument('expected SignShare');
      }
      final share = inbound.current.share;
      final walletId = _walletIdentifier!;
      final package = frost_comm.SigningPackage({
        keyPackage.identifier: nonce.commitments,
        walletId: frost_comm.SigningCommitments(
          threshold.elemDeserializeCompressed(Uint8List.fromList(share.bindingCommitment)),
          threshold.elemDeserializeCompressed(Uint8List.fromList(share.hidingCommitment)),
        ),
      }, message);
      final signature = frost.aggregate(
        package,
        {
          keyPackage.identifier: frost.sign(package, nonce, keyPackage),
          walletId: frost.SignatureShare(
              threshold.bytesToBigInt(Uint8List.fromList(share.signatureShare))),
        },
        _publicKeyPackage!,
      );
      yield cs.SignServerMsg(
        seq: Int64(2),
        complete: cs.SignComplete(
          rPoint: threshold.elemSerializeCompressed(signature.R),
          zScalar: threshold.bigIntToBytes(signature.Z),
        ),
      );
    } finally {
      signsInFlight--;
    }
  }

  // --- Recover -----------------------------------------------------------------------------------

  @override
  Future<cs.RecoverResponse> recover(ServiceCall call, cs.RecoverRequest request) async {
    final dealt = _dealtShareFor(request.identifier);
    if (holdRecover != null) {
      if (!recoverWaiting.isCompleted) recoverWaiting.complete();
      await holdRecover!.future;
    }
    recoversAnswered++;
    final package = _publicKeyPackage!;
    return cs.RecoverResponse(
      dealtShare: dealt,
      publicKeyPackageJson: jsonEncode(package.toJson()),
      groupKey: _hex(threshold.elemSerializeCompressed(package.verifyingKey.E)),
    );
  }

  // --- Everything else: not this fake's business -------------------------------------------------

  Never _no(String what) => throw GrpcError.unimplemented('the fake cosigner does not $what');

  @override
  Stream<cs.SendServerMsg> send(ServiceCall call, Stream<cs.SendClientMsg> request) => _no('send');
  // --- Settle, as far as the wait ------------------------------------------------------------------
  //
  // Not a settle: there is no transaction here and no ASP round. It is the *shape* of one up to
  // the point that matters for cancellation — the intent proof signed in-band, so the wallet has
  // rebuilt its share, then the intent registered, then `Idle`: "relay me the ASP's next event".
  // A real settle sits exactly there for minutes. What happens if the ASP never speaks again is
  // the test's business.

  int settlesOpened = 0;

  /// Completes when a settle has signed its intent proof and been told to wait on the ASP.
  Completer<void> settleWaitingOnAsp = Completer<void>();

  /// Completes when that settle's stream ends, however it ends.
  Completer<void> settleEnded = Completer<void>();

  @override
  Stream<cs.SettleServerMsg> settle(
      ServiceCall call, Stream<cs.SettleClientMsg> request) async* {
    settlesOpened++;
    try {
      final inbound = StreamIterator(request);
      if (!await inbound.moveNext() || !inbound.current.hasOpen()) {
        throw GrpcError.invalidArgument('a session must open with SettleOpen');
      }
      final dealt = _dealtShareFor(inbound.current.open.identifier);

      final keyPackage = _keyPackage!;
      final message = Uint8List.fromList(List<int>.generate(32, (i) => 0x51 ^ i));
      final nonce = frost_comm.newNonce(keyPackage.secretShare);
      yield cs.SettleServerMsg(
        seq: Int64(1),
        sighashes: cs.SettleSighashes(
          messagesToSign: [message],
          scriptPathSpend: true,
          cosignerCommitments: [
            cs.Commitment(
              hiding: threshold.elemSerializeCompressed(nonce.commitments.hiding),
              binding: threshold.elemSerializeCompressed(nonce.commitments.binding),
            ),
          ],
          cosignerIdentifier: _hex(keyPackage.identifier.serialize()),
          walletDealtShare: dealt,
        ),
      );

      if (!await inbound.moveNext() || !inbound.current.hasSigned()) {
        throw GrpcError.invalidArgument('expected SettleSigned');
      }
      // Aggregated, so that "the wallet rebuilt its share" is something this saw and not something
      // it assumed: a wrong share does not get this far.
      final half = inbound.current.signed.rounds.single;
      final walletId = _walletIdentifier!;
      final package = frost_comm.SigningPackage({
        keyPackage.identifier: nonce.commitments,
        walletId: frost_comm.SigningCommitments(
          threshold.elemDeserializeCompressed(Uint8List.fromList(half.binding)),
          threshold.elemDeserializeCompressed(Uint8List.fromList(half.hiding)),
        ),
      }, message);
      frost.aggregate(
        package,
        {
          keyPackage.identifier: frost.sign(package, nonce, keyPackage),
          walletId: frost.SignatureShare(threshold.bytesToBigInt(Uint8List.fromList(half.share))),
        },
        _publicKeyPackage!,
      );

      yield cs.SettleServerMsg(
        seq: Int64(2),
        register: cs.RegisterIntent(proof: 'proof', message: 'message', topics: ['topic']),
      );
      if (!await inbound.moveNext() || !inbound.current.hasRegistered()) {
        throw GrpcError.invalidArgument('expected IntentRegistered');
      }
      yield cs.SettleServerMsg(seq: Int64(3), idle: cs.SettleIdle());
      if (!settleWaitingOnAsp.isCompleted) settleWaitingOnAsp.complete();

      // The wallet is now waiting on the ASP, not on this. Nothing more is said.
      while (await inbound.moveNext()) {}
    } finally {
      if (!settleEnded.isCompleted) settleEnded.complete();
    }
  }
  @override
  Future<ContactAddResponse> contactAdd(ServiceCall call, ContactAddRequest request) =>
      _no('keep contacts');
  @override
  Future<ContactRemoveResponse> contactRemove(ServiceCall call, ContactRemoveRequest request) =>
      _no('keep contacts');
  @override
  Future<ContactListResponse> contactList(ServiceCall call, ContactListRequest request) =>
      _no('keep contacts');
  @override
  Future<PaymentRequestCreateResponse> paymentRequestCreate(
          ServiceCall call, PaymentRequestCreateRequest request) =>
      _no('take payment requests');
  @override
  Future<PaymentRequestListResponse> paymentRequestList(
          ServiceCall call, PaymentRequestListRequest request) =>
      _no('take payment requests');
  @override
  Future<PaymentRequestDeclineResponse> paymentRequestDecline(
          ServiceCall call, PaymentRequestDeclineRequest request) =>
      _no('take payment requests');
  @override
  Future<GetServerInfoResponse> getServerInfo(ServiceCall call, GetServerInfoRequest request) async =>
      GetServerInfoResponse(bitcoinNetwork: 'regtest');
  @override
  Future<cs.RegisterDeviceResponse> registerDevice(
          ServiceCall call, cs.RegisterDeviceRequest request) =>
      _no('wake devices');
  @override
  Future<cs.ForgetDeviceResponse> forgetDevice(ServiceCall call, cs.ForgetDeviceRequest request) =>
      _no('wake devices');
  @override
  Future<cs.DeviceCountResponse> deviceCount(ServiceCall call, cs.DeviceCountRequest request) =>
      _no('wake devices');
}
