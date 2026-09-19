/// The wallet, against a cosigner running as a Wasm guest inside a real enclave.
///
/// This replaces `ark_e2e_test.dart`, which spawned a native cosigner binary on a loopback port.
/// There is no such binary: the cosigner is a component with no listener, so the only way to run it
/// is to give it a host. See [EnclaveHarness] for what that buys and what it costs.
///
/// Every call here goes through the real path — TLS, a per-request nonce, and a WebAuthn assertion
/// exchanged for a single-use token bound to that exact method and path. Nothing reaches the guest
/// without one.
///
/// ```console
/// $ make cosigner-wasm
/// $ dart test test/enclave_ark_test.dart                    # boots an enclave, ~minutes
/// $ MERLIN_ENCLAVE_RUN=~/enclave-runtime/target/qemu-nitro/merlin dart test …   # attaches
/// ```
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:app_core/ark/ark.dart' as ark;
import 'package:app_core/asp/asp_client.dart' show IndexerVtxo;
import 'package:app_core/asp/exit_chain.dart' show ChainKind;
import 'package:blockchain_utils/blockchain_utils.dart' show SegwitBech32Encoder;
import 'package:app_core/client.dart';
import 'package:app_core/enclave/attestation.dart';
import 'package:app_core/enclave/authenticator.dart';
import 'package:app_core/enclave/gate.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:app_core/passkey/seed_source.dart';
import 'package:protocol/protocol.dart' show PaymentIntent, PaymentRequestCreateRequest;
import 'package:e2e/boarding_poll.dart';
import 'package:e2e/enclave_harness.dart';
import 'package:e2e/logger.dart';
import 'package:e2e/regtest_helper.dart';
import 'package:test/test.dart';

/// arkd, on the host. The guest has no egress at all — **the client** drives the Ark protocol and
/// relays each event in — so the ASP is reached directly and nothing about the docker stack had to
/// change for the enclave.
const aspHost = '127.0.0.1';
const aspPort = 7070;

extension on List<IndexerVtxo> {
  /// `listVtxos` returns a bare list now. It was `ListVtxosResponse`, which carried the total too —
  /// computed by a cosigner that was watching the ASP for us, and cannot.
  int get totalSats => fold(0, (sum, v) => sum + v.amountSats);
}

/// Mine a block every few seconds for as long as [body] runs.
///
/// The boarding transaction needs a confirmation before the ASP will accept it as an input, and the
/// commitment transaction needs one before its VTXOs are spendable. arkd schedules its own rounds,
/// but nothing moves on-chain on regtest unless somebody mines.
Future<T> whileMining<T>(RegtestHelper btc, Future<T> Function() body) async {
  var mining = true;
  final miner = Timer.periodic(const Duration(seconds: 3), (_) async {
    if (!mining) return;
    try {
      await btc.generateToAddress(1, await btc.getNewAddress());
    } catch (_) {
      // A missed block delays the round; it does not fail it.
    }
  });
  try {
    return await body();
  } finally {
    mining = false;
    miner.cancel();
  }
}

/// Poll until [check] holds, or fail naming what was being waited for.
Future<T> eventually<T>(
  String what,
  Future<T> Function() read,
  bool Function(T) check, {
  Duration timeout = const Duration(minutes: 3),
}) async {
  final deadline = DateTime.now().add(timeout);
  late T last;
  while (DateTime.now().isBefore(deadline)) {
    last = await read();
    if (check(last)) return last;
    await Future<void>.delayed(const Duration(seconds: 2));
  }
  fail('timed out after $timeout waiting for $what; last saw $last');
}

void main() {
  EnclaveHarness? harness;

  setUpAll(() async {
    harness = await EnclaveHarness.start();
    Log.info('enclave up: pcr16=${harness!.pcr16.substring(0, 16)}…'
        '${harness!.attached ? ' (attached)' : ''}');
  });

  tearDownAll(() async => harness?.stop());

  group('the component serves', () {
    test('GetServerInfo reports the configured network', () async {
      final alice = await harness!.wallet('info_alice', aspHost: aspHost, aspPort: aspPort);
      try {
        final info = await alice.client.getServerInfo();
        // regtest is the cosigner's default, and it is what it has to fall back to: the image's
        // environment is all `S3FS_*`, which the runtime strips, so BITCOIN_NETWORK never arrives.
        expect(info.bitcoinNetwork, 'regtest');
      } finally {
        await alice.close();
      }
    });
  });

  group('attestation', () {
    test('every approval attests the enclave, down to the component it serves', () async {
      final alice = await harness!.wallet('attest_alice', aspHost: aspHost, aspPort: aspPort);
      try {
        await alice.client.getServerInfo();
        final attested = alice.gate.attested!;
        final served = File('${harness!.runDir}/guests/guest.wasm').readAsBytesSync();
        expect(attested.guestSha256, crypto.sha256.convert(served).toString(),
            reason: 'user_data names the component the enclave measured and serves');
      } finally {
        await alice.close();
      }
    });

    test('an enclave serving another component is refused before anything is sent', () async {
      final enclave = harness!.enclave;
      final real = await harness!.wallet('pinned_alice', aspHost: aspHost, aspPort: aspPort);
      await real.close();
      final wrongGuest = EnclavePins(
        trustRoot: enclave.pins.trustRoot,
        pcr0: enclave.pins.pcr0,
        // PCR0 alone cannot catch this: the right runtime, serving something else.
        pcr16: '00' * 48,
      );
      final gate = EnclaveGate(
        endpoint: enclave.endpoint,
        pins: wrongGuest,
        origin: enclave.origin,
        authenticator: SoftwareAuthenticator.fromStateJson(
          File('${harness!.runDir}/pinned_alice-${harness!.runId}.json').readAsStringSync(),
          rpId: enclave.rpId,
        ),
      );
      try {
        await expectLater(gate.mint(method: 'POST', path: '/cosigner.v1.Cosigner/GetServerInfo'),
            throwsA(isA<AttestationException>()));
        expect(gate.attested, isNull, reason: 'nothing a refused document said is kept');
      } finally {
        gate.close();
      }
    });

    test('a cosigner channel refuses a certificate the gate did not attest', () async {
      final enclave = harness!.enclave;
      final state = File('${harness!.runDir}/elsewhere_alice-${harness!.runId}.json');
      await enclave.enrol(state);
      final real = enclave.gate(state);
      final gate = _PinnedElsewhere(real);
      real.close();
      final client = MpcClient.enclave(gate: gate, aspHost: aspHost, aspPort: aspPort);
      try {
        await expectLater(
          client.getServerInfo(),
          // The socket served the real certificate, which is not the pinned one.
          throwsA(predicate((e) => '$e'.contains('not the attested'))),
        );
      } finally {
        await client.close();
        gate.close();
      }
    });
  });

  group('DKG', () {
    test('a ceremony over one stream produces a key both sides derive', () async {
      final alice = await harness!.wallet('dkg_alice', aspHost: aspHost, aspPort: aspPort);
      try {
        await alice.client.doDkg();
        final key = alice.client.groupKeyHex;
        expect(key, isNotNull);
        expect(key!.length, 66, reason: 'a compressed point, hex');

        // Not self-certifying: `DkgSession` derives the group key from the wallet's own public key
        // package and throws if the cosigner's answer differs, so reaching here means both sides
        // arrived at the same key independently.
        expect(alice.client.userId, isNotNull);

        // And never a second one. A DKG over a wallet that has a key would replace it and strand
        // everything held under the old one, so the cosigner refuses before dealing anything.
        await expectLater(alice.client.doDkg(), throwsA(anything),
            reason: 'a second DKG on the same wallet must be refused');
        expect(alice.client.groupKeyHex, key, reason: 'and the refusal must not touch the key');
      } finally {
        await alice.close();
      }
    });

    /// Enrolling for wakes rides the ceremony: a `RegisterDevice` of its own would be a second
    /// passkey approval straight after onboarding, for nothing the user asked for.
    test('the ceremony enrols the device token it carries, with no call of its own', () async {
      final dana = await harness!.wallet('dkg_dana', aspHost: aspHost, aspPort: aspPort);
      try {
        const token = 'e2e-dkg-device-token-0123456789abcdef';
        final enrolled = <String>[];
        dana.client.onDeviceEnrolled = enrolled.add;
        dana.client.offerDeviceToken(token);

        await dana.client.doDkg();

        expect(enrolled, [token], reason: 'the cosigner should report the token enrolled');
        expect(await dana.client.deviceCount(), 1);
      } finally {
        await dana.close();
      }
    });

    test('two passkeys are two tenants, with two wallets', () async {
      final alice = await harness!.wallet('tenant_alice', aspHost: aspHost, aspPort: aspPort);
      final bob = await harness!.wallet('tenant_bob', aspHost: aspHost, aspPort: aspPort);
      try {
        await alice.client.doDkg();
        await bob.client.doDkg();

        // Different tenants, different filesystems, different seals. Under the old suite these two
        // shared one process and were kept apart by a client-side storage id; here the runtime
        // resolves a tenant from each caller's own token and hands it a scoped filesystem, so this
        // is the runtime's isolation being checked rather than ours.
        expect(alice.client.groupKeyHex, isNot(equals(bob.client.groupKeyHex)));
      } finally {
        await alice.close();
        await bob.close();
      }
    });
  });

  group('addresses', () {
    test('the wallet derives its own, and they are stable', () async {
      final alice = await harness!.wallet('addr_alice', aspHost: aspHost, aspPort: aspPort);
      try {
        await alice.client.doDkg();

        // Straight from the ASP. The cosigner used to relay `GetArkInfo` from its own connection;
        // it has no socket, so the client asks arkd itself and passes what it learns back in on
        // each SendOpen/SettleOpen.
        final info = await alice.client.getArkInfo();
        expect(info.signerPubkey, isNotEmpty);
        expect(info.network, 'regtest');
        expect(info.unilateralExitDelay, greaterThan(0));
        expect(info.boardingExitDelay, greaterThan(0));
        expect(info.boardingExitDelay, isNot(equals(info.unilateralExitDelay)),
            reason: 'the mixed-delay tests depend on these differing');

        // Derived here, over FFI, from the wallet's own key and the ASP's — not fetched. The two
        // RPCs that used to serve these are gone. Reimplementing the derivation in Dart was never
        // an option: two divergent VTXO taptrees already exist in this repository, and a third
        // guess means funds at an address nobody can spend.
        final ark = await alice.client.getArkAddress();
        final boarding = await alice.client.getBoardingAddress();
        expect(ark, startsWith('tark1'), reason: 'regtest Ark address');
        expect(boarding, startsWith('bcrt1p'), reason: 'regtest boarding address');

        expect(await alice.client.getArkAddress(), ark, reason: 'derivation is a function');
        expect(await alice.client.getBoardingAddress(), boarding);
      } finally {
        await alice.close();
      }
    });

    test('a fresh wallet holds nothing', () async {
      final bob = await harness!.wallet('fresh_bob', aspHost: aspHost, aspPort: aspPort);
      try {
        await bob.client.doDkg();
        final vtxos = await bob.client.listVtxos();
        // Both scripts are queried, always — a wallet holds a mixed set, and asking for one makes
        // the other bucket invisible, which is indistinguishable from empty.
        expect(vtxos, isEmpty);
      } finally {
        await bob.close();
      }
    });
  });

  // ===============================================================================================
  // Money. Every test here moves funds, and every one stops mid-stream for the wallet to sign — the
  // path that deadlocked inside the enclave until FROST moved in-band. Each uses its own wallet
  // names, so its own tenants: nothing one test leaves behind can be scanned by another, which was
  // a standing hazard in the old suite, where test ids were reused across cases.
  // ===============================================================================================

  late RegtestHelper btc;

  setUpAll(() async {
    try {
      await RegtestHelper().createWallet('default');
    } catch (e) {
      if (!e.toString().contains('already')) rethrow;
    }
    btc = RegtestHelper(rpcUrl: 'http://127.0.0.1:18443/wallet/default');
  });

  Future<Wallet> wallet(String name) =>
      harness!.wallet(name, aspHost: aspHost, aspPort: aspPort);

  /// Fund [w]'s boarding address with [btcAmount], settle it into Ark, and return what it holds.
  Future<List<IndexerVtxo>> boardAndSettle(Wallet w, double btcAmount) async {
    final boarding = await w.client.getBoardingAddress();
    await btc.sendToAddress(boarding, btcAmount);
    await btc.generateToAddress(1, await btc.getNewAddress());
    final minSats = (btcAmount * 1e8).round();
    final deposits = await pollBoardingUtxos(boarding, minSats);
    expect(deposits, isNotEmpty, reason: '${w.name}: electrs should index the deposit');
    final commitment = await whileMining(btc, () => settleBoarding(w.client, deposits));
    expect(commitment, isNotEmpty, reason: '${w.name}: the settle should return a commitment');
    return eventually(
      '${w.name}: the boarded VTXO to be indexed',
      w.client.listVtxos,
      // Less the ASP's boarding fee, which is small next to any amount used here.
      (List<IndexerVtxo> v) => v.totalSats > minSats * 0.9,
    );
  }

  /// Send, then wait until both sides see exactly what they should.
  Future<void> sendAndSettleBalances(Wallet from, Wallet to, int amount) async {
    final fromBefore = (await from.client.listVtxos()).totalSats;
    final toBefore = (await to.client.listVtxos()).totalSats;
    final txid = await whileMining(
        btc, () async => from.client.sendVtxo(await to.client.getArkAddress(), amount));
    expect(txid, isNotEmpty);

    await eventually("${to.name} to receive $amount", to.client.listVtxos,
        (List<IndexerVtxo> v) => v.totalSats == toBefore + amount);
    final left = await eventually("${from.name}'s change to land", from.client.listVtxos,
        (List<IndexerVtxo> v) => v.totalSats == fromBefore - amount);
    for (final v in left) {
      expect(v.script, isNotEmpty, reason: 'every VTXO sits under a script');
    }
  }

  /// The exits are the point of the whole arrangement: a spend of each VTXO through its own exit
  /// leaf, signed by the 2-of-2 while the cosigner is here, kept by the wallet. If the cosigner
  /// never answers again, these are the money — so they are checked to be complete, correct and
  /// re-issued whenever the set of VTXOs changes.
  group('the way out', () {
    test('every seal signs an exit for every VTXO it covers', () async {
      final erin = await wallet('exit_erin');
      try {
        await erin.client.doDkg();

        // Where the exits pay: an address in bitcoind's wallet, which this wallet cannot spend.
        final exitAddress = await btc.getNewAddress();
        await erin.client.setExitAddress(exitAddress);

        final held = await boardAndSettle(erin, 0.005);
        final vtxo = held.single;

        final exits = erin.client.exits;
        expect(exits, hasLength(1), reason: 'one exit per held VTXO');
        final exit = exits.single;
        expect(exit.outpoint, '${vtxo.txid}:${vtxo.vout}');
        expect(exit.amountSats, vtxo.amountSats,
            reason: 'an exit pays the whole VTXO — it carries an anchor instead of a fee');
        expect(exit.sequence, greaterThan(0), reason: "it waits out the VTXO's exit delay");
        expect(exit.rawTx.length, greaterThan(200),
            reason: 'a signed transaction, not a stub');

        // The exit is the last hop. Everything above it — the batch tree, down from a commitment
        // transaction already on-chain — has to be published first, and the indexer is where those
        // come from. Without this the wallet would be showing a signed transaction that spends an
        // output nobody can see.
        final chain = await erin.client.exitChain(exit);
        expect(chain.missing, isEmpty, reason: 'the indexer should know the whole path');
        expect(chain.hops.first.kind, ChainKind.commitment,
            reason: 'a path starts at something already on-chain');
        expect(chain.hops.last.kind, ChainKind.exit);
        expect(chain.hops.last.rawTx, exit.rawTx);
        expect(chain.hops.length, greaterThanOrEqualTo(3),
            reason: 'commitment, at least one tree transaction, and the exit');
        for (final hop in chain.toPublish) {
          expect(hop.rawTx, isNotNull,
              reason: '${hop.kind.name} ${hop.txid} has to be broadcastable, not just named');
          expect(hop.rawTx, isNotEmpty);
        }
        Log.info('exit path: ${chain.hops.map((h) => h.kind.name).join(' -> ')}');

        // Spending the VTXO makes its exit meaningless, and the seal on the way out replaces it.
        final bob = await wallet('exit_bob');
        await bob.client.doDkg();
        final bobAddress = await bob.client.getArkAddress();
        await whileMining(btc, () => erin.client.sendVtxo(bobAddress, 10000));
        final after = erin.client.exits;
        expect(after.map((e) => e.outpoint), isNot(contains(exit.outpoint)),
            reason: 'the spent VTXO\'s exit is gone');
        expect(after, isNotEmpty, reason: "the change VTXO has an exit of its own");
        expect(after.single.amountSats, lessThan(vtxo.amountSats));

        // Bob received, and nothing of his has been sealed yet: he holds money with no exit until
        // he protects it. That gap is what the Exit tab shows, and what `protectFunds` closes.
        expect(bob.client.exits, isEmpty);
        await bob.client.setExitAddress(await btc.getNewAddress());
        final sealed = await bob.client.protectFunds();
        expect(sealed.exits, hasLength(1));
        expect(bob.client.exits.single.amountSats, 10000);
      } finally {
        await erin.close();
      }
    }, timeout: const Timeout(Duration(minutes: 10)));

    /// The claim every other exit test rests on: that these transactions actually spend.
    ///
    /// Everything else checks shape — the right outpoint, the right amount, a signature that
    /// verifies against our own arithmetic. This one hands the transaction to bitcoind and sees
    /// the money arrive, which is the only way to know the leaf, the timelock, the witness and the
    /// 2-of-2's signature are all what consensus expects.
    ///
    /// The VTXO here is synthetic: an ordinary on-chain output carrying this wallet's VTXO script,
    /// funded by bitcoind. A real VTXO lives in a batch tree whose branch would have to be
    /// published first — a later piece of work — and that branch would change nothing about the
    /// hop being proven here, which is the last one.
    test('a signed exit really spends, and bitcoind agrees', () async {
      final alice = await wallet('exit_spend');
      try {
        await alice.client.doDkg();
        final exitAddress = await btc.getNewAddress();
        await alice.client.setExitAddress(exitAddress);

        // An output under this wallet's own VTXO script: same owner key, same ASP key, same exit
        // delay, so the exit leaf the cosigner signs against is the one that guards it.
        final info = await alice.client.getArkInfo();
        final script = ark.vtxoScriptPubkeyHex(
          ownerXOnlyHex: alice.client.groupXOnlyPubKey!,
          aspPubkeyHex: info.signerPubkey,
          exitDelay: info.unilateralExitDelay,
          network: info.network,
        );
        final program = Uint8List.fromList([
          for (var i = 4; i < script.length; i += 2)
            int.parse(script.substring(i, i + 2), radix: 16),
        ]);
        final vtxoAddress = SegwitBech32Encoder.encode('bcrt', 1, program);

        final fundingTxid = await btc.sendToAddress(vtxoAddress, 0.002);
        await btc.generateToAddress(1, await btc.getNewAddress());
        final funding = await btc.getRawTransaction(fundingTxid);
        final output = (funding['vout'] as List)
            .cast<Map<String, dynamic>>()
            .firstWhere((o) => (o['scriptPubKey'] as Map)['hex'] == script);
        final amountSats = ((output['value'] as num) * 1e8).round();
        final fundedAt = (funding['blocktime'] as num).toInt();

        // The cosigner signs its exit. It never asked the ASP whether this VTXO is real — it
        // derives the script from its own key, so an output that is not ours is one it cannot
        // produce a spendable signature for anyway.
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final sealed = await alice.client.protectFunds(over: [
          IndexerVtxo(
            txid: fundingTxid,
            vout: (output['n'] as num).toInt(),
            amountSats: amountSats,
            script: script,
            isSpent: false,
            createdAt: now,
            expiresAt: now + 86400,
            exitDelay: info.unilateralExitDelay,
          )
        ]);
        final exit = sealed.exits.single;
        expect(exit.amountSats, amountSats);

        // Too early: the timelock is the whole point of an exit, so it must actually bind.
        final tooEarly = await btc.testMempoolAccept([exit.rawTx]);
        expect(tooEarly.single['allowed'], isFalse,
            reason: 'an exit must not be spendable before its delay');
        expect('${tooEarly.single['reject-reason']}', contains('non-BIP68'),
            reason: 'and the reason must be the timelock, not something else');

        // Wait it out. The delay is in seconds, so what has to pass is the chain's median time —
        // mined blocks follow the node's clock.
        await btc.setMockTime(fundedAt + info.unilateralExitDelay + 3600);
        await btc.generateToAddress(12, await btc.getNewAddress());
        expect(await btc.medianTime(), greaterThan(fundedAt + info.unilateralExitDelay));

        // Consensus: mined directly, because an exit pays no fee and a node will not relay it
        // alone. What this proves is that the script, the sequence, the witness and the FROST
        // signature are all valid — the parts nobody could add later.
        final exitTxid = (await btc.decodeRawTransaction(exit.rawTx))['txid'] as String;
        await btc.generateBlock(await btc.getNewAddress(), [exit.rawTx]);
        final mined = await btc.getRawTransaction(exitTxid);
        expect(mined['confirmations'], greaterThanOrEqualTo(1),
            reason: 'the exit is in a block');

        // And the money is where the owner said it should go.
        final paid = (mined['vout'] as List)
            .cast<Map<String, dynamic>>()
            .firstWhere((o) => ((o['scriptPubKey'] as Map)['address'] ?? '') == exitAddress);
        expect(((paid['value'] as num) * 1e8).round(), amountSats,
            reason: 'an exit pays the whole VTXO — the fee comes from whoever bumps it');
        Log.info('exit $exitTxid paid $amountSats sats to $exitAddress');
      } finally {
        await alice.close();
      }
    }, timeout: const Timeout(Duration(minutes: 10)));

    /// A wallet that never set one still works — it simply has nothing to fall back on.
    test('a wallet with no exit address still seals a delegate', () async {
      final dana = await wallet('exit_dana');
      try {
        await dana.client.doDkg();
        await boardAndSettle(dana, 0.005);
        expect(dana.client.delegateStatus, isNotNull);
        expect(dana.client.exits, isEmpty);
      } finally {
        await dana.close();
      }
    }, timeout: const Timeout(Duration(minutes: 10)));
  });

  group('the full flow', () {
    /// Board, settle, then three sends — the third spending down the change of the second, which is a
    /// different input than the boarded VTXO the first one spent.
    test('board, settle, and three sends Alice to Bob', () async {
      final alice = await wallet('flow_alice');
      final bob = await wallet('flow_bob');
      try {
        await alice.client.doDkg();
        await bob.client.doDkg();

        // A token that arrives after onboarding — FCM rotated it — rides the next seal.
        const token = 'e2e-seal-device-token-0123456789abcdef';
        final enrolled = <String>[];
        alice.client.onDeviceEnrolled = enrolled.add;
        alice.client.offerDeviceToken(token);

        final held = await boardAndSettle(alice, 0.01);
        expect(enrolled, [token], reason: 'the settle\'s seal should carry the token and enrol it');
        expect(await alice.client.deviceCount(), 1);
        expect(held, hasLength(1));
        final vtxo = held.single;
        expect(vtxo.exitDelay, greaterThan(0),
            reason: 'tagged from the script it came under — the cosigner refuses a VTXO without it');
        expect(vtxo.script, isNotEmpty);
        // Straight from the indexer, so present at once. It used to land asynchronously, backfilled
        // by a subscription the cosigner ran; nothing runs one now.
        expect(vtxo.expiresAt, greaterThan(0));

        // The settle sealed a delegate on its way out, on the same stream and approval: over the one
        // VTXO held, valid from its expiry less the margin.
        final boarded = alice.client.delegateStatus;
        expect(boarded, isNotNull, reason: 'the settle should seal a delegate before closing');
        expect(boarded!.covered, {'${vtxo.txid}:${vtxo.vout}'});
        expect(boarded.validAt,
            DateTime.fromMillisecondsSinceEpoch(vtxo.expiresAt * 1000).subtract(boarded.margin));
        expect(await alice.client.unprotectedVtxos(), isEmpty);

        await sendAndSettleBalances(alice, bob, 100000);
        await sendAndSettleBalances(alice, bob, 50000);
        // Spends the change the previous send produced — a unilateral-delay VTXO, not the boarded one.
        await sendAndSettleBalances(alice, bob, 20000);

        expect((await bob.client.listVtxos()).totalSats, 170000);

        // Each send sealed a new delegate over what was left, so Alice's change is covered with no
        // call of its own.
        expect(alice.client.delegateStatus, isNotNull);
        expect(await alice.client.unprotectedVtxos(), isEmpty,
            reason: 'a send should seal a delegate over its change before closing');

        // Bob only received. No delegate covers those funds until he seals one — one call, and then
        // one does.
        expect(bob.client.delegateStatus, isNull);
        expect(await bob.client.unprotectedVtxos(), hasLength(3));
        final sealed = await bob.client.protectFunds();
        expect(sealed.covered, hasLength(3));
        expect(await bob.client.unprotectedVtxos(), isEmpty);
      } finally {
        await alice.close();
        await bob.close();
      }
    }, timeout: const Timeout(Duration(minutes: 15)));
  });

  group('the delegate', () {
    /// The point of a delegate: the wallet signs a refresh while it is here, and the cosigner runs it
    /// when it comes due — registering with the ASP itself, from a background task, over the one
    /// origin the enclave lets it reach. Nothing on this side does anything but wait.
    test('the cosigner refreshes the funds itself when the delegate comes due', () async {
      final erin = await wallet('delegate_erin');
      try {
        await erin.client.doDkg();
        final held = await boardAndSettle(erin, 0.005);
        final before = held.single;
        final delegate = erin.client.delegateStatus!;
        expect(delegate.covered, {'${before.txid}:${before.vout}'});

        final due = delegate.validAt.difference(DateTime.now());
        if (due > const Duration(minutes: 12)) {
          markTestSkipped('the delegate comes due in $due — this enclave was booted with a '
              'production-like margin; the harness and `make up-enclave` use 15060s');
          return;
        }
        Log.info('delegate due in ${due.inSeconds}s; waiting for the cosigner to run it');

        // Only mining, which regtest needs for anything to confirm. No call from this client.
        final refreshed = await whileMining(
          btc,
          () => eventually(
            'the cosigner to refresh ${before.txid}:${before.vout} on its own',
            erin.client.listVtxos,
            (List<IndexerVtxo> v) {
              final unspent = v.where((x) => !x.isSpent).toList();
              return unspent.length == 1 &&
                  unspent.single.txid != before.txid &&
                  unspent.single.amountSats <= before.amountSats &&
                  unspent.single.amountSats > before.amountSats * 0.9;
            },
            timeout: due + const Duration(minutes: 6),
          ),
        );
        final after = refreshed.where((x) => !x.isSpent).single;
        expect(after.expiresAt, greaterThan(before.expiresAt),
            reason: 'a refresh is a new VTXO in a new batch, with a later expiry');

        // The refreshed VTXO has no delegate of its own until the wallet is next here to sign one.
        expect(await erin.client.unprotectedVtxos(), hasLength(1));
        final resealed = await erin.client.protectFunds();
        expect(resealed.covered, {'${after.txid}:${after.vout}'});
      } finally {
        await erin.close();
      }
    }, timeout: const Timeout(Duration(minutes: 20)));
  });

  group('contacts', () {
    test('add, list and remove, on the wallet\'s own cosigner', () async {
      final alice = await wallet('contacts_alice');
      final bob = await wallet('contacts_bob');
      try {
        await alice.client.doDkg();
        await bob.client.doDkg();
        final bobKey = bob.client.groupKeyHex!;

        await alice.client.contactAdd(bobKey, 'Bob');
        final listed = await alice.client.contactList();
        expect(listed, hasLength(1));
        expect(_hex(listed.single.verifyingKey), bobKey);
        expect(listed.single.label, 'Bob');

        await alice.client.contactRemove(bobKey);
        expect(await alice.client.contactList(), isEmpty);
      } finally {
        await alice.close();
        await bob.close();
      }
    });
  });

  group('request to pay', () {
    /// Bob bills Alice, and Alice pays it.
    ///
    /// Carried **out of band**, because it has to be: the runtime resolves a tenant from the caller's
    /// own token and strips any tenant header a client sends, so Bob cannot reach Alice's cosigner.
    /// So Bob *writes* a request — signed by his group key, with his own cosigner — and Alice's app
    /// *receives* it into hers. Here the bytes cross in memory; in the app they would be a QR code.
    test('Bob bills Alice, Alice pays, and the request is fulfilled', () async {
      final alice = await wallet('rtp_alice');
      final bob = await wallet('rtp_bob');
      final carol = await wallet('rtp_carol');
      try {
        await alice.client.doDkg();
        await bob.client.doDkg();
        await carol.client.doDkg();
        await boardAndSettle(alice, 0.01);
        final aliceKey = alice.client.groupKeyHex!;
        final bobKey = bob.client.groupKeyHex!;
        final bobArk = await bob.client.getArkAddress();

        // Travel as bytes, the way a request really would.
        Future<PaymentIntent> deliver(PaymentRequestCreateRequest written) =>
            alice.client.receivePaymentRequest(
                PaymentRequestCreateRequest.fromBuffer(written.writeToBuffer()));

        // Not a contact yet: refused.
        await expectLater(
          deliver(await bob.client.writePaymentRequest(aliceKey, 1000, memo: 'not yet')),
          throwsA(anything),
          reason: 'a request from someone not on the allowlist must be refused',
        );

        await alice.client.contactAdd(bobKey, 'Bob');
        final written = await bob.client.writePaymentRequest(aliceKey, 5000, memo: 'invoice 1');
        final intent = await deliver(written);
        expect(intent.status, 'pending');
        expect(intent.amountSats.toInt(), 5000);
        expect(intent.memo, 'invoice 1');

        // The one that matters. Derived by Alice's cosigner from the key that SIGNED — never supplied
        // by Bob, or a contact could redirect the payment, and never a share key, whose address is
        // not his wallet's. The old share-key lookup would have failed exactly here.
        expect(intent.toArkAddress, bobArk,
            reason: "the payee address must be Bob's own — anything else is funds he cannot spend");
        expect(_hex(intent.fromVerifyingKey), bobKey);

        // The same request, delivered again, is one request.
        await expectLater(deliver(written), throwsA(anything),
            reason: 'a replayed request must be refused');

        // A genuine request Bob wrote to Carol cannot be cashed in at Alice.
        await expectLater(
          deliver(await bob.client.writePaymentRequest(carol.client.groupKeyHex!, 2000)),
          throwsA(anything),
          reason: 'a request written for another wallet must be refused',
        );

        final inbox = await alice.client.paymentRequests();
        expect(inbox.map((i) => i.id), contains(intent.id));

        final bobBefore = (await bob.client.listVtxos()).totalSats;
        final payTxid = await whileMining(btc,
            () => alice.client.sendVtxo(intent.toArkAddress, intent.amountSats.toInt()));
        expect(payTxid, isNotEmpty);

        final paid = (await alice.client.paymentRequests()).firstWhere((i) => i.id == intent.id);
        expect(paid.status, 'fulfilled', reason: 'the settled send must mark the request fulfilled');
        expect(paid.arkTxid, payTxid);
        await eventually('Bob to be paid', bob.client.listVtxos,
            (List<IndexerVtxo> v) => v.totalSats == bobBefore + 5000);

        // Declined stays visible — the payer refused it; they did not un-know about it.
        final unwanted =
            await deliver(await bob.client.writePaymentRequest(aliceKey, 777, memo: 'not today'));
        await alice.client.declinePaymentRequest(unwanted.id);
        final afterDecline = await alice.client.paymentRequests();
        expect(afterDecline.firstWhere((i) => i.id == unwanted.id).status, 'declined');

        // Revoking the contact drops what is pending and shuts the gate.
        final pending = await deliver(
            await bob.client.writePaymentRequest(aliceKey, 500, memo: 'will be revoked'));
        await alice.client.contactRemove(bobKey);
        expect((await alice.client.paymentRequests()).where((i) => i.id == pending.id), isEmpty);
        await expectLater(
          deliver(await bob.client.writePaymentRequest(aliceKey, 100, memo: 'after revoke')),
          throwsA(anything),
        );
      } finally {
        await alice.close();
        await bob.close();
        await carol.close();
      }
    }, timeout: const Timeout(Duration(minutes: 15)));
  });

  group('a gated share', () {
    /// The share stored blinded, reconstructed from a seed for each signature. A right seed signs a
    /// settle the ASP accepts; a wrong one cannot spend.
    test('the right seed signs; a wrong seed cannot spend', () async {
      final seed = Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 3) & 0xff));
      final wrong = Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 4) & 0xff));

      final alice = await wallet('gated_alice');
      final bob = await wallet('gated_bob');
      try {
        // Wired before DKG, so the share is never stored in the clear.
        alice.client.setSeedSource(FixedSeedSource(seed));
        await alice.client.doDkg();
        await bob.client.doDkg();
        expect(alice.client.isShareGated, isTrue);

        final held = await boardAndSettle(alice, 0.01);
        expect(held, hasLength(1),
            reason: 'a VTXO means the reconstructed share signed validly, twice, in-band');

        alice.client.setSeedSource(FixedSeedSource(wrong));
        await expectLater(
          alice.client.sendVtxo(await bob.client.getArkAddress(), 1000),
          throwsA(anything),
          reason: 'a wrong seed reconstructs the wrong share, which the cosigner refuses',
        );
      } finally {
        await alice.close();
        await bob.close();
      }
    }, timeout: const Timeout(Duration(minutes: 15)));
  });

  group('a mixed exit-delay set', () {
    /// A send spending a boarded VTXO and a received one together, in both orders.
    ///
    /// They sit under different scripts — boarded keeps the boarding delay, received uses the
    /// unilateral one — and a send that reused one input's spend info for every input produces a
    /// wrong prevout the ASP rejects. Which order they happen to sit in decided which input broke,
    /// so both orders are exercised.
    test('a send spends boarded and received VTXOs together, in both orders', () async {
      final alice = await wallet('mixed_alice');
      final bob = await wallet('mixed_bob');
      try {
        await alice.client.doDkg();
        await bob.client.doDkg();
        final info = await alice.client.getArkInfo();
        expect(info.boardingExitDelay, isNot(equals(info.unilateralExitDelay)),
            reason: 'with equal delays this test cannot detect the bug — check the arkd config');

        await boardAndSettle(alice, 0.002);
        await boardAndSettle(bob, 0.003);

        // Alice receives, so she now holds one of each.
        await sendAndSettleBalances(bob, alice, 150000);
        final mixed = await alice.client.listVtxos();
        expect(mixed.map((v) => v.exitDelay).toSet(), hasLength(2),
            reason: 'Alice must hold a boarded AND a received VTXO');

        // Spends across both delays: more than either VTXO alone.
        await sendAndSettleBalances(alice, bob, 250000);

        // Reverse: the change is already held, and a fresh boarding arrives after it.
        await boardAndSettle(alice, 0.002);
        final reversed = await alice.client.listVtxos();
        expect(reversed.map((v) => v.exitDelay).toSet(), hasLength(2));
        await sendAndSettleBalances(alice, bob, reversed.totalSats - 10000);
      } finally {
        await alice.close();
        await bob.close();
      }
    }, timeout: const Timeout(Duration(minutes: 20)));
  });

  group('a wallet reopened from storage', () {
    /// A client restored from its own storage can still spend.
    ///
    /// Both halves of the key have to survive: the wallet's share out of its Hive box, and the
    /// cosigner's out of its seal. The cosigner half is proven by every request here — it reopens
    /// from the seal each time, with nothing kept between requests — and this proves the client
    /// half with a fresh object that has never seen DKG.
    test('can still spend after the client is rebuilt', () async {
      final first = await wallet('restore_carol');
      final dave = await wallet('restore_dave');
      String key;
      try {
        await first.client.doDkg();
        await dave.client.doDkg();
        key = first.client.groupKeyHex!;
        await boardAndSettle(first, 0.005);
      } finally {
        await first.close();
      }

      final reopened = await wallet('restore_carol');
      try {
        expect(await reopened.client.restoreState(), isTrue);
        expect(reopened.client.groupKeyHex, key, reason: 'the same wallet, not a new one');
        await sendAndSettleBalances(reopened, dave, 100000);
      } finally {
        await reopened.close();
        await dave.close();
      }
    }, timeout: const Timeout(Duration(minutes: 15)));
  });
}

String _hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// A gate whose approvals are real but whose pin names some other certificate — what an intercepted
/// channel looks like from the client's side.
class _PinnedElsewhere extends EnclaveGate {
  _PinnedElsewhere(EnclaveGate real)
      : super(
          endpoint: real.endpoint,
          pins: real.pins,
          origin: real.origin,
          authenticator: real.authenticator,
        );

  static final _elsewhere = AttestedConnection(
    certificateSha256: '00' * 32,
    guestSha256: '00' * 32,
    timestamp: DateTime.now(),
  );

  @override
  AttestedConnection? get attested => _elsewhere;

  @override
  Future<AttestedConnection> attest() async => _elsewhere;
}
