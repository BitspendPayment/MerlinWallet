/// A wallet's whole life on a device that stores nothing secret.
///
/// `MpcClient` against a cosigner in this process (`support/fake_cosigner.dart`), over real gRPC:
/// made by DKG, signed with, reopened from disk, rebuilt on a second device — and at every step
/// the box on disk is read back, as a map and as raw bytes, and searched for every secret the
/// wallet has. Then the ways an operation can end badly, each of which must leave nothing held:
/// the wrong passkey, a cosigner that lies about its half, one that falls over, one that never
/// answers, a fingerprint prompt the owner dismisses.
@Tags(['ffi'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:grpc/grpc.dart';
import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:fixnum/fixnum.dart';
import 'package:hive/hive.dart';
import 'package:test/test.dart';

import 'package:app_core/asp/ark_info.dart' show IndexerVtxo;
import 'package:app_core/asp/asp_client.dart' show AspClient;
import 'package:app_core/client.dart';
import 'package:app_core/cosigner/connection.dart';
import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/passkey/operation_secrets.dart';
import 'package:app_core/passkey/seed_source.dart';
import 'package:app_core/passkey/share_reconstruction.dart';
import 'package:app_core/passkey/wallet_public_state.dart';
import 'package:app_core/persistence/wallet_store.dart';
import 'package:app_core/sessions/service_delivery.dart';
import 'package:app_core/threshold_types.dart' as threshold;

import 'support/ceremony.dart' show seed;
import 'support/fake_cosigner.dart';
import 'support/silent_asp.dart';

/// A passkey's PRF, observed: every buffer it ever handed out is kept, so a test can look at what
/// became of it. Nothing in the wallet keeps one; this does, on purpose.
///
/// And, like the phone's passkey, **one gesture at a time**: `PlatformPasskey` refuses a second
/// capture while a prompt is still showing, because two callers would be expecting the same
/// gesture's output. A stand-in without that rule cannot see the bugs the rule causes.
class ObservedSeedSource implements SeedSource {
  ObservedSeedSource(this._seed);
  final Uint8List _seed;
  final List<Uint8List> handedOut = [];
  bool _capturing = false;

  /// Fail the next capture *after* its approval has gone through — a passkey that signed the
  /// assertion and then returned no PRF output.
  bool failAfterApproving = false;

  @override
  Future<Uint8List> seedDuring(Future<void> Function() approve) async {
    if (_capturing) throw StateError('a seed is already being taken for another operation');
    _capturing = true;
    try {
      await approve();
      if (failAfterApproving) {
        failAfterApproving = false;
        throw StateError('the passkey returned no PRF output');
      }
      final copy = Uint8List.fromList(_seed);
      handedOut.add(copy);
      return copy;
    } finally {
      _capturing = false;
    }
  }
}

/// A service's pairing endpoint, as far as the wallet can tell: it takes the half, turns it down,
/// or never answers.
class ScriptedDelivery implements DeliverToService {
  ScriptedDelivery({this.refuse = false, this.hang = false});
  final bool refuse;
  final bool hang;
  final List<ServiceContribution> taken = [];

  /// Completes when the wallet first tries to deliver.
  final Completer<void> asked = Completer<void>();

  @override
  Future<void> deliver(String origin, ServiceContribution contribution) async {
    if (!asked.isCompleted) asked.complete();
    if (hang) return Completer<void>().future;
    if (refuse) throw ServiceDeliveryException('the service turned it down', refused: true);
    taken.add(contribution);
  }
}

class Device {
  Device(this.client, this.seeds, this.approvals, this.operations);
  final MpcClient client;
  final ObservedSeedSource seeds;

  /// Every path the approver was asked to approve, in order.
  final List<String> approvals;

  /// Every operation the client began.
  final List<WalletOperation> operations;
}

String hexOf(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

bool containsBytes(List<int> haystack, List<int> needle) {
  outer:
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

void main() {
  late Directory dir;
  late FakeCosigner cosigner;
  late int port;
  final opened = <MpcClient>[];
  var boxes = 0;

  /// A device holding [seedBytes]'s passkey, over the Hive box [storageId].
  ///
  /// [approve] stands in for the enclave gate: it is what a fingerprint prompt is, here.
  Device device(
    Uint8List seedBytes,
    String storageId, {
    Future<void> Function(String path)? approve,
    AspClient? asp,
  }) {
    final approvals = <String>[];
    final operations = <WalletOperation>[];
    final client = MpcClient.withConnection(
      CosignerConnection(
        ClientChannel('127.0.0.1',
            port: port,
            options: const ChannelOptions(credentials: ChannelCredentials.insecure())),
        approver: (path) async {
          approvals.add(path);
          await approve?.call(path);
          return {'authorization': 'Bearer ${approvals.length}'};
        },
      ),
      // Never dialled: nothing here talks to an ASP.
      aspHost: '127.0.0.1',
      aspPort: 9,
      storageId: storageId,
      asp: asp,
    );
    final seeds = ObservedSeedSource(seedBytes);
    client.setSeedSource(seeds);
    client.debugOnOperation = operations.add;
    opened.add(client);
    return Device(client, seeds, approvals, operations);
  }

  String newBox() => 'wallet_${boxes++}';

  /// Every secret this wallet has, in every form one could be written down in.
  Future<Map<String, List<int>>> secretsOf(Uint8List seedBytes) async {
    final polynomial = await walletPolynomial(Uint8List.fromList(seedBytes));
    final wallet = WalletPublicState.fromPublicKeyPackage(
        cosigner.publicKeyPackage!, identifierOf(polynomial),
        minSigners: 2);
    final share = reconstructWalletShare(
      polynomial: polynomial,
      dealtShare: cosigner.dealtShare!,
      wallet: wallet,
    ).secretShare;
    return {
      'the PRF seed': seedBytes,
      'a0 (the old onchainSecret)': threshold.bigIntToBytes(polynomial.a0.scalar),
      'a1': threshold.bigIntToBytes(polynomial.a1),
      'the signing share': threshold.bigIntToBytes(share),
      "the cosigner's dealt half": cosigner.dealtShare!,
    };
  }

  /// Nothing secret in the stored map, and nothing secret in the file it is stored in.
  Future<void> expectNothingSecretAtRest(String storageId, Uint8List seedBytes) async {
    final secrets = await secretsOf(seedBytes);

    final box = await Hive.openBox(storageId);
    final state = box.get('client_state');
    expect(state, isNotNull, reason: 'there should be a wallet to look at');
    expect(findForbiddenStateKey(state), isNull);
    expect((state as Map)['stateVersion'], walletStateVersion);
    final asText = state.toString().toLowerCase();

    // The file, not just the live value: Hive appends, so anything ever written is still in it.
    final raw = await File('${dir.path}/$storageId.hive').readAsBytes();
    final rawText = String.fromCharCodes(raw).toLowerCase();

    for (final secret in secrets.entries) {
      final asHex = hexOf(secret.value);
      expect(asText.contains(asHex), isFalse, reason: '${secret.key} is in the stored state');
      expect(rawText.contains(asHex), isFalse, reason: '${secret.key} is in the box file, as hex');
      expect(containsBytes(raw, secret.value), isFalse,
          reason: '${secret.key} is in the box file, as bytes');
    }
  }

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('merlin_lifecycle_');
    Hive.init(dir.path);
    cosigner = FakeCosigner();
    port = await cosigner.start();
  });

  tearDown(() async {
    for (final client in opened) {
      await client.close();
    }
    opened.clear();
    await cosigner.stop();
    await Hive.close();
    await dir.delete(recursive: true);
  });

  final message = Uint8List.fromList(List<int>.generate(32, (i) => 0xa0 ^ i));

  group('nothing secret at rest', () {
    test('after DKG', () async {
      final box = newBox();
      final d = device(seed(1), box);
      await d.client.doDkg();

      expect(d.client.isInitialized, isTrue);
      expect(d.approvals, ['/cosigner.v1.Cosigner/Dkg'], reason: 'one fingerprint to make a wallet');
      await expectNothingSecretAtRest(box, seed(1));
    });

    test('after signing, however many times', () async {
      final box = newBox();
      final d = device(seed(2), box);
      await d.client.doDkg();
      for (var i = 0; i < 3; i++) {
        await d.client.sign(message);
      }
      await expectNothingSecretAtRest(box, seed(2));
    });

    test('after recovery on a second device', () async {
      final first = device(seed(3), newBox());
      await first.client.doDkg();

      final box = newBox();
      final second = device(seed(3), box);
      await second.client.recover();
      expect(second.client.groupKeyHex, first.client.groupKeyHex);
      expect(second.approvals, ['/cosigner.v1.Cosigner/Recover']);
      await expectNothingSecretAtRest(box, seed(3));
    });

    test('the store refuses a share by any name it has had, at any depth', () async {
      final store = WalletStore(boxName: newBox());
      await store.init();
      for (final key in forbiddenStateKeys) {
        await expectLater(
          store.saveClientState({
            'stateVersion': walletStateVersion,
            'userId': 'aa',
            'wallet': {
              'keyPackage': {key: '00' * 32},
            },
          }),
          throwsArgumentError,
          reason: key,
        );
      }
      expect(await store.getClientState(), isNull, reason: 'a refused write writes nothing');
      await store.close();
    });
  });

  group('signing', () {
    test('rebuilds the share and makes a signature the group key verifies', () async {
      final d = device(seed(4), newBox());
      await d.client.doDkg();
      final signature = await d.client.sign(message);
      // `sign` verified it already; verified again here against the cosigner's own idea of the
      // key, so the two agree about which wallet this is.
      signature.verify(cosigner.publicKeyPackage!.verifyingKey, message);
    });

    test('costs one approval, and the operation is over when it returns', () async {
      final d = device(seed(5), newBox());
      await d.client.doDkg();
      d.approvals.clear();

      await d.client.sign(message);
      expect(d.approvals, ['/cosigner.v1.Cosigner/Sign']);
      expect(d.operations.last.isDisposed, isTrue);
      expect(d.operations.last.holdsSecrets, isFalse);
      expect(d.seeds.handedOut, everyElement(everyElement(0)),
          reason: 'every PRF output the passkey handed over has been overwritten');
      expect(d.client.operationInProgress, isFalse);
    });

    test("what comes back is the cosigner's dealt half, never its own share", () async {
      final d = device(seed(6), newBox());
      await d.client.doDkg();
      await d.client.sign(message);
      expect(cosigner.dealtShare, isNot(threshold.bigIntToBytes(cosigner.ownShare!)));
    });
  });

  group('restarting', () {
    test('a new process signs from public state, the passkey and the cosigner', () async {
      final box = newBox();
      final before = device(seed(7), box);
      await before.client.doDkg();
      final groupKey = before.client.groupKeyHex;
      await before.client.close();
      await Hive.close();
      Hive.init(dir.path);

      final after = device(seed(7), box);
      expect(await after.client.restoreState(), isTrue);
      expect(after.approvals, isEmpty, reason: 'opening the app asks for nothing');
      expect(after.client.groupKeyHex, groupKey);

      final signature = await after.client.sign(message);
      signature.verify(cosigner.publicKeyPackage!.verifyingKey, message);
      await expectNothingSecretAtRest(box, seed(7));
    });

    test('a recovered device signs exactly as the one that made the wallet does', () async {
      final first = device(seed(8), newBox());
      await first.client.doDkg();
      final second = device(seed(8), newBox());
      await second.client.recover();

      (await first.client.sign(message)).verify(cosigner.publicKeyPackage!.verifyingKey, message);
      (await second.client.sign(message)).verify(cosigner.publicKeyPackage!.verifyingKey, message);
    });

    test('state from before this build is refused, not read and not replaced', () async {
      final box = newBox();
      final legacy = await Hive.openBox(box);
      await legacy.put('client_state', {
        'userId': 'aa',
        'onchainSecret': '11' * 32,
        'shareBlinded': true,
        'spendingPolicies': {
          'keyPackage': {'secretShare': '22' * 32},
        },
      });
      await legacy.close();

      final d = device(seed(9), box);
      await expectLater(d.client.restoreState(), throwsA(isA<IncompatibleWalletStateException>()));
      await expectLater(d.client.recover(), throwsA(isA<IncompatibleWalletStateException>()));
      expect(d.approvals, isEmpty, reason: 'nothing is asked of the owner for a wallet unread');

      // The explicit way out. The file goes, so what was appended to it goes with it.
      await d.client.resetLocalState();
      expect(File('${dir.path}/$box.hive').existsSync(), isFalse);
      expect(await d.client.restoreState(), isFalse);
    });
  });

  group('what must be refused', () {
    test('a passkey that is not this wallet\'s: before anything is opened or sent', () async {
      final box = newBox();
      final owner = device(seed(10), box);
      await owner.client.doDkg();
      await owner.client.close();

      final thief = device(seed(11), box);
      expect(await thief.client.restoreState(), isTrue);
      await expectLater(thief.client.sign(message), throwsA(isA<WrongPasskey>()));

      expect(cosigner.signsOpened, 0, reason: 'a wrong passkey never reaches the cosigner');
      expect(thief.seeds.handedOut.single, everyElement(0));
      expect(thief.operations, isEmpty, reason: 'no operation ever held anything');
      // The approval it did obtain was dropped rather than left for the next call to find.
      await expectLater(thief.client.sign(message), throwsA(isA<WrongPasskey>()));
      expect(thief.approvals, hasLength(2), reason: 'each attempt asked afresh');
    });

    test('a cosigner that returns a share it did not deal', () async {
      final d = device(seed(12), newBox());
      await d.client.doDkg();

      cosigner.fault = SignFault.wrongShare;
      await expectLater(d.client.sign(message), throwsA(isA<ShareMismatch>()));
      expect(d.operations.last.isDisposed, isTrue);
      expect(d.operations.last.holdsSecrets, isFalse);

      // Nothing about the wallet was damaged by it.
      cosigner.fault = SignFault.none;
      (await d.client.sign(message)).verify(cosigner.publicKeyPackage!.verifyingKey, message);
    });

    test('a cosigner from before this change, which returns no share', () async {
      final d = device(seed(13), newBox());
      await d.client.doDkg();
      cosigner.fault = SignFault.noShare;
      await expectLater(d.client.sign(message), throwsA(isA<ContributionProtocolException>()));
      expect(d.operations.last.holdsSecrets, isFalse);
    });

    test("an authenticated stranger cannot recover this wallet's half", () async {
      // The enclave gives each tenant its own instance; this is what one instance says to a wallet
      // that is not the one it holds — which is all an authenticated stranger can be to it. The
      // same rule guards `Sign`, `Send` and `Renew`, and is proved on the wire for all of them in
      // `cosigner/tests/stream_contribution_test.rs`: from this client a stranger cannot even ask,
      // because a passkey that is not the wallet's is refused before a stream is opened (above).
      final owner = device(seed(14), newBox());
      await owner.client.doDkg();

      final stranger = device(seed(15), newBox());
      await expectLater(
        stranger.client.recover(),
        throwsA(isA<GrpcError>().having((e) => e.code, 'code', StatusCode.permissionDenied)),
      );
      expect(cosigner.recoversAnswered, 0);
      expect(stranger.client.isInitialized, isFalse);
      expect(stranger.operations.last.holdsSecrets, isFalse);
    });
  });

  group('an operation that does not finish', () {
    test('the cosigner fails mid-ceremony', () async {
      final d = device(seed(16), newBox());
      await d.client.doDkg();
      cosigner.fault = SignFault.failAfterCommitments;

      await expectLater(d.client.sign(message), throwsA(anything));
      final operation = d.operations.last;
      expect(operation.isDisposed, isTrue);
      expect(operation.holdsSecrets, isFalse, reason: 'the share it had rebuilt is let go');
      expect(d.seeds.handedOut, everyElement(everyElement(0)));
      expect(d.client.operationInProgress, isFalse, reason: 'the next operation is not blocked');
    });

    test('it is cancelled while the cosigner is silent', () async {
      final d = device(seed(17), newBox());
      await d.client.doDkg();
      cosigner.fault = SignFault.hangAfterCommitments;

      final signing = d.client.sign(message);
      await expectLater(signing.timeout(const Duration(milliseconds: 600)),
          throwsA(isA<TimeoutException>()));
      // Still running: a timeout on the future is not a cancellation of the work. The share is
      // rebuilt by now and the operation is holding it.
      expect(d.client.operationInProgress, isTrue);
      expect(d.operations.last.holdsSecrets, isTrue);

      // Cancelling it for real — what leaving the screen does. Closing the connection would not:
      // a graceful shutdown waits for the call to finish, and this one never will.
      await d.client.cancelOperation();
      await expectLater(signing, throwsA(anything));
      expect(d.operations.last.isDisposed, isTrue);
      expect(d.operations.last.holdsSecrets, isFalse);
      expect(d.client.operationInProgress, isFalse);
    });

    test('a renewal is cancelled while the ASP is silent: the share goes, and so does its turn',
        () async {
      // The wait a cosigner-only cancel could not reach. By the time a renewal is waiting for the
      // ASP's batch it has signed its intent proof, so it is holding a rebuilt share — and it is
      // parked on the ASP's event stream, not on the cosigner. An ASP that never speaks again
      // would have kept that share in memory, and the lock against every later operation, forever.
      final asp = SilentAsp();
      final d = device(seed(20), newBox(), asp: asp);
      await d.client.doDkg();
      d.approvals.clear();

      final renewing = d.client.board(
        cs.BoardingUtxo(txid: 'ab' * 32, vout: 0, amountSats: Int64(50000)),
      );
      // Whatever becomes of it is looked at below; until then it is not an unhandled error.
      renewing.ignore();

      await cosigner.boardWaitingOnAsp.future.timeout(const Duration(seconds: 10));
      // Give the driver its turn to go from `Idle` to the event stream.
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(asp.intentsRegistered, 1);
      expect(asp.listening, isTrue, reason: 'the renewal is parked on the ASP, not the cosigner');
      final operation = d.operations.last;
      expect(operation.holdsSecrets, isTrue, reason: 'the intent proof was signed: a share exists');
      expect(d.client.operationInProgress, isTrue);
      // One fingerprint, approved for the stream boarding opens: the seed rides it, so an approval
      // asked for under any other method would be a second prompt.
      expect(d.approvals, ['/cosigner.v1.Cosigner/Board']);

      // A second operation, queued behind it. It must not be stuck there.
      final queued = d.client.sign(message);

      await d.client.cancelOperation();

      await expectLater(renewing, throwsA(isA<OperationCancelled>()));
      expect(operation.isDisposed, isTrue);
      expect(operation.holdsSecrets, isFalse, reason: 'a silent ASP keeps no share alive');
      expect(d.seeds.handedOut.take(2), everyElement(everyElement(0)));

      // The driver really unwound, rather than being left parked with the share in its frame:
      // it let go of the ASP's stream and the cosigner saw its own end.
      await cosigner.boardEnded.future.timeout(const Duration(seconds: 10));
      expect(asp.listenerLeft, isTrue);

      // And the turn passed on: the operation that was waiting runs, and signs.
      (await queued.timeout(const Duration(seconds: 10)))
          .verify(cosigner.publicKeyPackage!.verifyingKey, message);
      expect(d.client.operationInProgress, isFalse);
    });

    test('it is cancelled while the fingerprint prompt is showing, and answered later', () async {
      // A prompt cannot be taken off the screen from here. Cancelling must still end the turn —
      // and when the owner does touch the sensor, that seed must start nothing: no stream, no
      // signature, and no approval left behind for the next operation to trip over.
      final prompt = Completer<void>();
      var hold = false;
      final d = device(seed(21), newBox(), approve: (_) async {
        if (hold) await prompt.future;
      });
      await d.client.doDkg();
      d.operations.clear();

      hold = true;
      final signing = d.client.sign(message);
      signing.ignore();
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(d.client.operationInProgress, isTrue);

      await d.client.cancelOperation();
      await expectLater(signing, throwsA(isA<OperationCancelled>()));
      expect(d.client.operationInProgress, isFalse, reason: 'the turn does not wait for a finger');

      // The owner answers the stale prompt.
      hold = false;
      prompt.complete();
      await Future<void>.delayed(const Duration(milliseconds: 300));
      expect(d.operations, isEmpty, reason: 'a cancelled operation never begins');
      expect(cosigner.signsOpened, 0, reason: 'and never reaches the cosigner');
      expect(d.seeds.handedOut.last, everyElement(0), reason: 'the late seed is overwritten');

      // The next operation is a clean one: its own approval, exactly once.
      d.approvals.clear();
      (await d.client.sign(message)).verify(cosigner.publicKeyPackage!.verifyingKey, message);
      expect(d.approvals, ['/cosigner.v1.Cosigner/Sign']);
    });

    /// Whether the next `Sign` stream opened on this device's connection asks for an approval of
    /// its own. Opened raw, past `MpcClient` — which always approves ahead and so always overwrites
    /// whatever is cached, hiding exactly the thing being looked for.
    Future<bool> nextSignStreamAsksForApproval(Device d) async {
      final before = d.approvals.length;
      final duplex = d.client.cosigner.openSign();
      // Listening is what makes the connection fetch the stream's approval — from the cache, or
      // by asking. Nothing is sent, so nothing will ever come back: the read is only started.
      final read = duplex.next('anything').then<void>((_) {}, onError: (_) {});
      await Future<void>.delayed(const Duration(milliseconds: 300));
      await duplex.close();
      await read;
      return d.approvals.length > before;
    }

    for (final passkeyFails in [false, true]) {
      test(
          'an approval that lands after the cancel is not left for the next stream to use'
          '${passkeyFails ? ', even when the passkey then fails' : ''}', () async {
        // The gesture the owner makes on a stale prompt approves a call they already cancelled.
        // The turn's cleanup ran before that approval existed, so something else has to drop it —
        // or the next stream to that method opens on it, with no prompt at all.
        final stalePrompt = Completer<void>();
        var prompts = 0;
        final d = device(seed(passkeyFails ? 27 : 26), newBox(), approve: (_) async {
          if (++prompts == 2) await stalePrompt.future;
        });
        await d.client.doDkg();

        final cancelled = d.client.sign(message)..ignore();
        await Future<void>.delayed(const Duration(milliseconds: 200));
        await d.client.cancelOperation();
        await expectLater(cancelled, throwsA(isA<OperationCancelled>()));

        d.seeds.failAfterApproving = passkeyFails;
        stalePrompt.complete();
        await Future<void>.delayed(const Duration(milliseconds: 300));

        expect(await nextSignStreamAsksForApproval(d), isTrue,
            reason: 'a stream rode the approval of a cancelled operation');
      });
    }

    test('dropping a late approval does not take a newer operation\'s with it', () async {
      // The other way to get this wrong: the stale operation's cleanup discarding by method name
      // after the queued operation — same method — has obtained its own approval, which would
      // cost the owner a second fingerprint for one signature.
      final stalePrompt = Completer<void>();
      var prompts = 0;
      final d = device(seed(28), newBox(), approve: (_) async {
        if (++prompts == 2) await stalePrompt.future;
      });
      await d.client.doDkg();

      final cancelled = d.client.sign(message)..ignore();
      await Future<void>.delayed(const Duration(milliseconds: 200));
      final queued = d.client.sign(message);
      await d.client.cancelOperation();
      await expectLater(cancelled, throwsA(isA<OperationCancelled>()));

      stalePrompt.complete();
      await queued;
      expect(prompts, 3, reason: 'DKG, the stale prompt, and exactly one for the queued signature');
    });

    test('an operation queued behind a cancelled prompt waits for it, and then runs', () async {
      // The case the test above does not reach, because it answers the stale prompt first. The
      // turn is released on cancel, but the passkey is still mid-gesture — so the next operation
      // asking for its own at once would be refused: "a seed is already being taken".
      final stalePrompt = Completer<void>();
      var prompts = 0;
      final d = device(seed(23), newBox(), approve: (_) async {
        // Only the first prompt after DKG is left unanswered.
        if (++prompts == 2) await stalePrompt.future;
      });
      await d.client.doDkg();

      final cancelled = d.client.sign(message);
      cancelled.ignore();
      await Future<void>.delayed(const Duration(milliseconds: 200));
      final queued = d.client.sign(message);

      await d.client.cancelOperation();
      await expectLater(cancelled, throwsA(isA<OperationCancelled>()));

      // The queued operation has its turn now, and the old prompt is still up. It waits.
      await Future<void>.delayed(const Duration(milliseconds: 300));
      expect(d.client.operationInProgress, isTrue);
      expect(prompts, 2, reason: 'no second gesture is asked of a passkey that is mid-gesture');
      expect(cosigner.signsOpened, 0);

      stalePrompt.complete();
      (await queued.timeout(const Duration(seconds: 10)))
          .verify(cosigner.publicKeyPackage!.verifyingKey, message);
      expect(prompts, 3, reason: 'its own approval, once the stale one was out of the way');
      expect(cosigner.signsOpened, 1, reason: 'the cancelled operation never reached the cosigner');
      expect(d.seeds.handedOut, everyElement(everyElement(0)));
    });

    test('an operation waiting behind a stale prompt can itself be cancelled', () async {
      // The owner must not have to answer a prompt for something they cancelled in order to get
      // out of the thing queued behind it.
      final stalePrompt = Completer<void>();
      var prompts = 0;
      final d = device(seed(24), newBox(), approve: (_) async {
        if (++prompts == 2) await stalePrompt.future;
      });
      await d.client.doDkg();

      final first = d.client.sign(message)..ignore();
      await Future<void>.delayed(const Duration(milliseconds: 200));
      final second = d.client.sign(message)..ignore();
      await d.client.cancelOperation();
      await expectLater(first, throwsA(isA<OperationCancelled>()));

      await Future<void>.delayed(const Duration(milliseconds: 200));
      await d.client.cancelOperation();
      await expectLater(second, throwsA(isA<OperationCancelled>()));
      expect(d.client.operationInProgress, isFalse);

      stalePrompt.complete();
      await Future<void>.delayed(const Duration(milliseconds: 200));
      (await d.client.sign(message)).verify(cosigner.publicKeyPackage!.verifyingKey, message);
      expect(cosigner.signsOpened, 1);
    });

    test('a cancelled recovery stays cancelled when the cosigner answers anyway', () async {
      // Recovery waits on one unary call with the polynomial in hand. Cancelling ends the turn —
      // but the reply still arrives, and a callback that carried on would rebuild the share, adopt
      // the wallet and save it: reported as cancelled, and done regardless.
      final owner = device(seed(25), newBox());
      await owner.client.doDkg();

      final box = newBox();
      final newPhone = device(seed(25), box);
      cosigner.holdRecover = Completer<void>();
      final recovering = newPhone.client.recover()..ignore();
      await cosigner.recoverWaiting.future.timeout(const Duration(seconds: 10));

      await newPhone.client.cancelOperation();
      await expectLater(recovering, throwsA(isA<OperationCancelled>()));
      expect(newPhone.client.isInitialized, isFalse);

      // The cosigner gets round to answering.
      cosigner.holdRecover!.complete();
      await Future<void>.delayed(const Duration(milliseconds: 500));

      expect(newPhone.client.isInitialized, isFalse, reason: 'a late reply adopts nothing');
      expect(newPhone.client.groupKeyHex, isNull);
      expect(newPhone.operations.last.holdsSecrets, isFalse);
      final stored = await Hive.openBox(box);
      expect(stored.get('client_state'), isNull, reason: 'and saves nothing');

      // Not wedged by it: the same device recovers when asked again.
      cosigner.holdRecover = null;
      await newPhone.client.recover();
      expect(newPhone.client.groupKeyHex, owner.client.groupKeyHex);
    });

    test('cancelling with nothing running is nothing', () async {
      final d = device(seed(22), newBox());
      await d.client.doDkg();
      await d.client.cancelOperation();
      await d.client.sign(message);
    });

    test('the owner dismisses the fingerprint prompt', () async {
      var dismiss = false;
      final d = device(seed(18), newBox(), approve: (_) async {
        if (dismiss) throw StateError('the owner cancelled');
      });
      await d.client.doDkg();

      dismiss = true;
      await expectLater(d.client.sign(message), throwsStateError);
      expect(d.seeds.handedOut, hasLength(1), reason: 'only DKG ever got a seed');
      expect(d.operations, hasLength(1));
      expect(cosigner.signsOpened, 0);
      expect(d.client.operationInProgress, isFalse);

      dismiss = false;
      await d.client.sign(message);
    });
  });

  group('setting an escrow up for a service', () {
    final platform = threshold.Identifier.derive(Uint8List.fromList('the platform'.codeUnits));
    const policy = {'op': 'always'};
    final deadline = DateTime.now().add(const Duration(hours: 1));

    test('mints, pairs and strikes the deal on one approval, and the operation is over when it '
        'returns', () async {
      final box = newBox();
      final d = device(seed(40), box);
      await d.client.doDkg();
      d.approvals.clear();
      final delivery = ScriptedDelivery();

      final set = await d.client.setUpEscrow(
            serviceIdentifier: platform, policy: policy, deadline: deadline, delivery: delivery);
      expect(d.approvals, ['/cosigner.v1.Cosigner/Escrow']);
      expect(delivery.taken, hasLength(1), reason: "the wallet's half went to the service");
      expect(cosigner.pairingsConfirmed, 1);
      expect(cosigner.dealsStruck, [jsonEncode(policy)], reason: 'the deal rode the open');
      expect(set.agreed, 'the deal ${jsonEncode(policy)}', reason: 'and came back as agreed');
      expect(d.client.escrows.map((e) => e.escrowKeyHex), [set.escrow.escrowKeyHex]);
      expect(d.operations.last.isDisposed, isTrue);
      expect(d.operations.last.holdsSecrets, isFalse,
          reason: 'the escrow share it minted went with the operation');
      expect(d.seeds.handedOut, everyElement(everyElement(0)));
      await expectNothingSecretAtRest(box, seed(40));
    });

    test('a delivery that fails is not confirmed, and the escrow it minted is kept', () async {
      final d = device(seed(41), newBox());
      await d.client.doDkg();
      final delivery = ScriptedDelivery(refuse: true);

      await expectLater(
        d.client.setUpEscrow(
            serviceIdentifier: platform, policy: policy, deadline: deadline, delivery: delivery),
        throwsA(isA<ServiceDeliveryException>()),
      );
      expect(cosigner.pairingsConfirmed, 0,
          reason: 'a pairing whose wallet half never arrived must not be vouched for');
      expect(d.client.escrows, hasLength(1),
          reason: 'the escrow exists at the cosigner, so this wallet remembers it');
      expect(d.operations.last.holdsSecrets, isFalse);
      expect(d.client.operationInProgress, isFalse);
    });

    test('a delivery that never ends is cancelled, and takes the escrow share with it', () async {
      final d = device(seed(42), newBox());
      await d.client.doDkg();
      final delivery = ScriptedDelivery(hang: true);

      final setting = d.client.setUpEscrow(
            serviceIdentifier: platform, policy: policy, deadline: deadline, delivery: delivery);
      await delivery.asked.future;
      expect(d.operations.last.holdsSecrets, isTrue,
          reason: 'the minted share is held while the service is waited on');

      // Listened to before cancelling, so the error it ends with is caught when it arrives.
      final outcome = expectLater(setting, throwsA(isA<OperationCancelled>()));
      await d.client.cancelOperation();
      await outcome;
      expect(cosigner.pairingsConfirmed, 0);
      expect(d.operations.last.isDisposed, isTrue);
      expect(d.operations.last.holdsSecrets, isFalse);
      expect(d.client.operationInProgress, isFalse, reason: 'its turn is released');
    });
  });

  group('opening the app', () {
    // Every entry to the app asks for the passkey once, and that one approval re-arms the renewal
    // the cosigner runs on its own. The app unlocks on the approval — a refresh's round after it
    // takes minutes — so what it is told, and when, is what keeps a lock honest.

    /// A VTXO the wallet holds, as the indexer would report it — enough to ask for a renewal.
    IndexerVtxo held() => IndexerVtxo(
          txid: 'cd' * 32,
          vout: 0,
          amountSats: 50000,
          script: '',
          isSpent: false,
          createdAt: 0,
          expiresAt: 4102444800,
          exitDelay: 512,
        );

    test('is told the approval was given, before the renewal opens its stream', () async {
      final d = device(seed(60), newBox(), asp: SilentAsp());
      await d.client.doDkg();
      d.approvals.clear();

      List<String>? approvedWith;
      int? streamsWhenTold;
      await expectLater(
        d.client.protectFunds(
          over: [held()],
          onApproved: () {
            approvedWith = List.of(d.approvals);
            streamsWhenTold = cosigner.renewsOpened;
          },
        ),
        throwsA(isA<GrpcError>()),
      );

      expect(approvedWith, ['/cosigner.v1.Cosigner/Renew'], reason: 'told once it was given');
      expect(streamsWhenTold, 0, reason: 'and before the renewal opened its stream');
      expect(cosigner.renewsOpened, 1, reason: 'the renewal itself went on after it');
      expect(d.operations.last.isDisposed, isTrue);
      expect(d.operations.last.holdsSecrets, isFalse);
    });

    test('a dismissed prompt is not an approval', () async {
      var dismiss = false;
      final d = device(seed(61), newBox(), asp: SilentAsp(), approve: (_) async {
        if (dismiss) throw StateError('the owner cancelled');
      });
      await d.client.doDkg();

      dismiss = true;
      var told = false;
      await expectLater(
        d.client.protectFunds(over: [held()], onApproved: () => told = true),
        throwsStateError,
      );
      expect(told, isFalse, reason: 'an app must stay locked when the owner says no');
      expect(cosigner.renewsOpened, 0);
    });

    test("a passkey that is not this wallet's is not an approval", () async {
      final box = newBox();
      final owner = device(seed(62), box);
      await owner.client.doDkg();
      await owner.client.close();

      final thief = device(seed(63), box, asp: SilentAsp());
      expect(await thief.client.restoreState(), isTrue);
      var told = false;
      await expectLater(
        thief.client.protectFunds(over: [held()], onApproved: () => told = true),
        throwsA(isA<WrongPasskey>()),
      );
      expect(told, isFalse, reason: "a stranger's fingerprint unlocks nothing");
      expect(cosigner.renewsOpened, 0, reason: 'and reaches no cosigner');
      expect(thief.operations, isEmpty, reason: 'no operation ever held anything');
    });

    test('checking the passkey is one gesture, and asks the cosigner nothing', () async {
      final d = device(seed(64), newBox());
      await d.client.doDkg();
      d.approvals.clear();
      final gestures = d.seeds.handedOut.length;

      await d.client.verifyPasskey();

      expect(d.approvals, isEmpty, reason: 'no call is approved, so it works offline');
      expect(d.seeds.handedOut, hasLength(gestures + 1), reason: 'one gesture');
      expect(d.seeds.handedOut, everyElement(everyElement(0)));
      expect(d.operations.last.isDisposed, isTrue);
      expect(d.operations.last.holdsSecrets, isFalse);
      expect(d.client.operationInProgress, isFalse);
    });

    test("checking the passkey refuses one that is not this wallet's", () async {
      final box = newBox();
      final owner = device(seed(65), box);
      await owner.client.doDkg();
      await owner.client.close();

      final thief = device(seed(66), box);
      expect(await thief.client.restoreState(), isTrue);
      await expectLater(thief.client.verifyPasskey(), throwsA(isA<WrongPasskey>()));
      expect(thief.seeds.handedOut.single, everyElement(0));
      expect(thief.operations, isEmpty);
    });

    test('checking the passkey waits its turn', () async {
      final d = device(seed(67), newBox());
      await d.client.doDkg();

      cosigner.holdSigns = Completer<void>();
      final signing = d.client.sign(message);
      // Long enough for the sign to have taken its gesture and opened its stream.
      await Future<void>.delayed(const Duration(milliseconds: 300));
      final gestures = d.seeds.handedOut.length;

      final checking = d.client.verifyPasskey();
      await Future<void>.delayed(const Duration(milliseconds: 300));
      expect(d.seeds.handedOut, hasLength(gestures),
          reason: 'no gesture is asked for while another operation holds the turn');

      cosigner.holdSigns!.complete();
      await signing;
      await checking;
      expect(d.seeds.handedOut, hasLength(gestures + 1));
    });
  });

  group('two operations at once', () {
    test('take turns, and the second is approved only once it has its turn', () async {
      final d = device(seed(19), newBox());
      await d.client.doDkg();
      d.approvals.clear();

      cosigner.holdSigns = Completer<void>();
      final first = d.client.sign(message);
      final second = d.client.sign(message);

      // Long enough for the second to have asked, had it been going to.
      await Future<void>.delayed(const Duration(milliseconds: 400));
      expect(d.approvals, hasLength(1),
          reason: 'an approval lasts under a minute, so it is not taken while waiting in line');
      expect(d.operations, hasLength(2), reason: 'DKG, and the first sign — not the second');
      expect(cosigner.signsOpened, 1);

      cosigner.holdSigns!.complete();
      await first;
      await second;
      expect(d.approvals, hasLength(2));
      expect(cosigner.mostSignsAtOnce, 1, reason: "one operation's secrets at a time");
      expect(d.operations, everyElement(predicate<WalletOperation>((o) => !o.holdsSecrets)));
    });
  });
}
