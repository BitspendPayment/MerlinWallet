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

import 'dart:math';
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:app_core/ark/ark.dart' as ark;
import 'package:app_core/asp/asp_client.dart' show IndexerVtxo;
import 'package:app_core/asp/exit_chain.dart' show ChainKind;
import 'package:blockchain_utils/blockchain_utils.dart' show SegwitBech32Encoder;
import 'package:app_core/client.dart';
import 'package:app_core/threshold_types.dart' as ark_threshold;
import 'package:app_core/sessions/service_delivery.dart' show RewritingDelivery;
import 'package:e2e/escrow_service.dart';
import 'package:app_core/enclave/attestation.dart';
import 'package:app_core/enclave/authenticator.dart';
import 'package:app_core/enclave/gate.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:app_core/passkey/key_derivation.dart' show walletPolynomial;
import 'package:app_core/passkey/seed_source.dart';
import 'package:app_core/passkey/share_reconstruction.dart' show WrongPasskey;
import 'package:app_core/persistence/wallet_store.dart' show forbiddenStateKeys;
import 'package:app_core/threshold_types.dart' as threshold;
import 'package:e2e/boarding_poll.dart';
import 'package:e2e/e2e_profile.dart';
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
  EscrowService? service;

  setUpAll(() async {
    // Before the enclave: the image has to name where this service is, and it cannot be told
    // afterwards.
    // The service, its port and its origin as the image names them: `lib/e2e_profile.dart`, the
    // one place they are decided, because a prebuilt bundle has to have been packed with them.
    service = EscrowService(identifier: serviceIdentifier);
    await service!.start(port: servicePort);
    harness = await startE2eEnclave();
    Log.info('enclave up: pcr16=${harness!.pcr16.substring(0, 16)}…'
        '${harness!.attached ? ' (attached)' : ''}');
    if (harness!.attached) {
      Log.info('attached: escrow pairing needs SERVICE_ORIGINS in that image — '
          '$serviceOrigins');
    }
  });

  tearDownAll(() async => service?.stop());

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
        // each SendOpen/RenewOpen.
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

  Future<Wallet> wallet(String name) => harness!.wallet(name, aspHost: aspHost, aspPort: aspPort);

  /// Fund [w]'s boarding address with [btcAmount], settle it into Ark, and return what it holds.
  Future<List<IndexerVtxo>> boardAndRenew(Wallet w, double btcAmount) async {
    final boarding = await w.client.getBoardingAddress();
    await btc.sendToAddress(boarding, btcAmount);
    await btc.generateToAddress(1, await btc.getNewAddress());
    final minSats = (btcAmount * 1e8).round();
    final deposits = await pollBoardingUtxos(boarding, minSats);
    expect(deposits, isNotEmpty, reason: '${w.name}: electrs should index the deposit');
    final commitment = await whileMining(btc, () => renewBoarding(w.client, deposits));
    expect(commitment, isNotEmpty, reason: '${w.name}: the renewal should return a commitment');
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
    test('every renewal signs an exit for every VTXO it covers', () async {
      final erin = await wallet('exit_erin');
      try {
        await erin.client.doDkg();

        // Where the exits pay: an address in bitcoind's wallet, which this wallet cannot spend.
        final exitAddress = await btc.getNewAddress();
        await erin.client.setExitAddress(exitAddress);

        final held = await boardAndRenew(erin, 0.005);
        final vtxo = held.single;

        final exits = erin.client.exits;
        expect(exits, hasLength(1), reason: 'one exit per held VTXO');
        final exit = exits.single;
        expect(exit.outpoint, '${vtxo.txid}:${vtxo.vout}');
        expect(exit.amountSats, vtxo.amountSats,
            reason: 'an exit pays the whole VTXO — it carries an anchor instead of a fee');
        expect(exit.sequence, greaterThan(0), reason: "it waits out the VTXO's exit delay");
        expect(exit.rawTx.length, greaterThan(200), reason: 'a signed transaction, not a stub');

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

        // Spending the VTXO makes its exit meaningless, and the renewal on the way out replaces it.
        final bob = await wallet('exit_bob');
        await bob.client.doDkg();
        final bobAddress = await bob.client.getArkAddress();
        await whileMining(btc, () => erin.client.sendVtxo(bobAddress, 10000));
        final after = erin.client.exits;
        expect(after.map((e) => e.outpoint), isNot(contains(exit.outpoint)),
            reason: 'the spent VTXO\'s exit is gone');
        expect(after, isNotEmpty, reason: "the change VTXO has an exit of its own");
        expect(after.single.amountSats, lessThan(vtxo.amountSats));

        // Bob received, and has renewed nothing yet: he holds money with no exit until
        // he protects it. That gap is what the Exit tab shows, and what `protectFunds` closes.
        expect(bob.client.exits, isEmpty);
        await bob.client.setExitAddress(await btc.getNewAddress());
        final renewed = await bob.client.protectFunds();
        expect(renewed.exits, hasLength(1));
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
        final renewed = await alice.client.protectFunds(over: [
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
        final exit = renewed.exits.single;
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
        expect(mined['confirmations'], greaterThanOrEqualTo(1), reason: 'the exit is in a block');

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
    test('a wallet with no exit address still renews its delegate', () async {
      final dana = await wallet('exit_dana');
      try {
        await dana.client.doDkg();
        await boardAndRenew(dana, 0.005);
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

        // A token that arrives after onboarding — FCM rotated it — rides the next renewal.
        const token = 'e2e-renew-device-token-0123456789abcdef';
        final enrolled = <String>[];
        alice.client.onDeviceEnrolled = enrolled.add;
        alice.client.offerDeviceToken(token);

        final held = await boardAndRenew(alice, 0.01);
        expect(enrolled, [token], reason: 'the renewal should carry the token and enrol it');
        expect(await alice.client.deviceCount(), 1);
        expect(held, hasLength(1));
        final vtxo = held.single;
        expect(vtxo.exitDelay, greaterThan(0),
            reason:
                'tagged from the script it came under — the cosigner refuses a VTXO without it');
        expect(vtxo.script, isNotEmpty);
        // Straight from the indexer, so present at once. It used to land asynchronously, backfilled
        // by a subscription the cosigner ran; nothing runs one now.
        expect(vtxo.expiresAt, greaterThan(0));

        // Boarding renewed the delegate on its way out, on the same stream and approval: over the
        // one VTXO held, valid from its expiry less the margin.
        final boarded = alice.client.delegateStatus;
        expect(boarded, isNotNull, reason: 'boarding should renew the delegate before closing');
        expect(boarded!.covered, {'${vtxo.txid}:${vtxo.vout}'});
        expect(boarded.validAt,
            DateTime.fromMillisecondsSinceEpoch(vtxo.expiresAt * 1000).subtract(boarded.margin));
        expect(await alice.client.unprotectedVtxos(), isEmpty);

        await sendAndSettleBalances(alice, bob, 100000);
        await sendAndSettleBalances(alice, bob, 50000);
        // Spends the change the previous send produced — a unilateral-delay VTXO, not the boarded one.
        await sendAndSettleBalances(alice, bob, 20000);

        expect((await bob.client.listVtxos()).totalSats, 170000);

        // Each send renewed the delegate over what was left, so Alice's change is covered with no
        // call of its own.
        expect(alice.client.delegateStatus, isNotNull);
        expect(await alice.client.unprotectedVtxos(), isEmpty,
            reason: 'a send should renew the delegate over its change before closing');

        // Bob only received. No delegate covers those funds until he protects them — one call, and
        // then one does.
        expect(bob.client.delegateStatus, isNull);
        expect(await bob.client.unprotectedVtxos(), hasLength(3));
        final renewed = await bob.client.protectFunds();
        expect(renewed.covered, hasLength(3));
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
        final held = await boardAndRenew(erin, 0.005);
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
        final renewed = await erin.client.protectFunds();
        expect(renewed.covered, {'${after.txid}:${after.vout}'});
      } finally {
        await erin.close();
      }
    }, timeout: const Timeout(Duration(minutes: 20)));
  });

  group('nothing secret at rest', () {
    /// No share is stored: each operation rebuilds one from the passkey's seed and the half the
    /// cosigner returns on the stream it approved. A right seed signs a renewal the ASP accepts —
    /// every round of it, off one reconstruction — and leaves nothing of itself on disk; a wrong
    /// one is refused on the device, before anything is opened.
    test('the right seed signs and leaves nothing behind; a wrong seed cannot spend', () async {
      final seed = Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 3) & 0xff));
      final wrong = Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 4) & 0xff));

      final alice = await wallet('atrest_alice');
      final bob = await wallet('atrest_bob');
      try {
        // Wired before DKG: the wallet's polynomial is derived from this.
        alice.client.setSeedSource(FixedSeedSource(seed));
        await alice.client.doDkg();
        await bob.client.doDkg();

        final held = await boardAndRenew(alice, 0.01);
        expect(held, hasLength(1),
            reason: 'a VTXO means the rebuilt share signed validly, twice, in-band — the intent '
                'proof and the commitment — and then the delegate, all off one contribution');

        // What is on disk after a DKG, a boarding and its delegate. The file, not the live value:
        // Hive appends, so anything ever written is still in it.
        final polynomial = await walletPolynomial(Uint8List.fromList(seed));
        final raw = await harness!.stateFileOf(alice).readAsBytes();
        final rawText = String.fromCharCodes(raw).toLowerCase();
        for (final key in forbiddenStateKeys) {
          expect(rawText.contains(key.toLowerCase()), isFalse, reason: '"$key" is on disk');
        }
        for (final secret in {
          'the seed': seed,
          'a0': threshold.bigIntToBytes(polynomial.a0.scalar),
          'a1': threshold.bigIntToBytes(polynomial.a1),
        }.entries) {
          expect(rawText.contains(_hex(secret.value)), isFalse,
              reason: '${secret.key} is on disk, as hex');
          expect(_containsBytes(raw, secret.value), isFalse,
              reason: '${secret.key} is on disk, as bytes');
        }

        alice.client.setSeedSource(FixedSeedSource(wrong));
        await expectLater(
          alice.client.sendVtxo(await bob.client.getArkAddress(), 1000),
          throwsA(isA<WrongPasskey>()),
          reason: 'a wrong seed derives another wallet, and is refused before a stream is opened',
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

        await boardAndRenew(alice, 0.002);
        await boardAndRenew(bob, 0.003);

        // Alice receives, so she now holds one of each.
        await sendAndSettleBalances(bob, alice, 150000);
        final mixed = await alice.client.listVtxos();
        expect(mixed.map((v) => v.exitDelay).toSet(), hasLength(2),
            reason: 'Alice must hold a boarded AND a received VTXO');

        // Spends across both delays: more than either VTXO alone.
        await sendAndSettleBalances(alice, bob, 250000);

        // Reverse: the change is already held, and a fresh boarding arrives after it.
        await boardAndRenew(alice, 0.002);
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
    /// What has to survive is public on the wallet's side — who it is, out of its Hive box — and
    /// secret only on the cosigner's, out of its seal. The cosigner half is proven by every request
    /// here: it reopens from the seal each time, with nothing kept between requests. This proves
    /// the client half with a fresh object that has never seen DKG and holds no share: it spends
    /// from its stored public state, its passkey and the enclave, and nothing else.
    test('can still spend after the client is rebuilt', () async {
      final first = await wallet('restore_carol');
      final dave = await wallet('restore_dave');
      String key;
      try {
        await first.client.doDkg();
        await dave.client.doDkg();
        key = first.client.groupKeyHex!;
        await boardAndRenew(first, 0.005);
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

  group('a wallet on a new phone', () {
    /// The passkey is the whole wallet: nothing else crosses from the old device.
    ///
    /// The share this client rebuilds is half derived from the passkey's PRF and half handed back
    /// by the cosigner, which sealed it at the ceremony. Reporting the same group key would not
    /// prove the share is right — that is public. Spending does: a FROST signature the cosigner
    /// accepts and the ASP mines cannot be made with a share that is off by anything at all.
    test('the passkey alone brings it back, and it can still spend', () async {
      final erin = await wallet('recover_erin');
      final frank = await wallet('recover_frank');
      late String key;
      late int held;
      try {
        await erin.client.doDkg();
        await frank.client.doDkg();
        key = erin.client.groupKeyHex!;
        held = (await boardAndRenew(erin, 0.005)).totalSats;
      } finally {
        await erin.close();
      }

      // A new phone: the same passkey, an empty store.
      final newPhone =
          await harness!.newDeviceFor('recover_erin', aspHost: aspHost, aspPort: aspPort);
      try {
        expect(await newPhone.client.restoreState(), isFalse,
            reason: 'this device has never held the wallet');

        await newPhone.client.recover();

        expect(newPhone.client.groupKeyHex, key, reason: 'the same wallet, not a new one');
        expect(newPhone.client.userId, isNotNull);
        expect((await newPhone.client.listVtxos()).totalSats, held,
            reason: 'the balance was never on the old phone either — it comes from the ASP');

        await sendAndSettleBalances(newPhone, frank, 100000);
      } finally {
        await newPhone.close();
        await frank.close();
      }
    }, timeout: const Timeout(Duration(minutes: 20)));

    /// The failure that matters: a PRF that answers differently on this device.
    ///
    /// Nothing in WebAuthn promises a synced passkey yields the same PRF output everywhere, and a
    /// wallet rebuilt from the wrong half would look fine until the first payment failed. So the
    /// cosigner checks the identifier the caller derived against the one the ceremony recorded, and
    /// refuses rather than answer.
    test('a passkey whose PRF answers differently is refused, not half-served', () async {
      final gina = await wallet('recover_gina');
      try {
        await gina.client.doDkg();
      } finally {
        await gina.close();
      }

      final newPhone =
          await harness!.newDeviceFor('recover_gina', aspHost: aspHost, aspPort: aspPort);
      try {
        newPhone.client.setSeedSource(FixedSeedSource(Uint8List.fromList(List.filled(32, 0xab))));
        await expectLater(
          newPhone.client.recover(),
          throwsA(predicate((e) => '$e'.contains('does not derive this wallet'))),
        );
        expect(newPhone.client.groupKeyHex, isNull, reason: 'a refused recovery saves nothing');
      } finally {
        await newPhone.close();
      }
    }, timeout: const Timeout(Duration(minutes: 10)));

    /// One tenant cannot have another wallet's half — not even knowing that wallet's seed.
    ///
    /// The worst case for the identifier check: Mallory is a real, authenticated tenant, and has
    /// somehow learnt Heidi's PRF output, so she derives Heidi's identifier exactly. What she cannot
    /// do is ask Heidi's cosigner. Her passkey resolves to her own tenant and her own instance,
    /// whose seal holds her wallet and never Heidi's — so the identifier she sends matches nothing
    /// there, and she is refused. The contribution is bound to the tenant by the runtime, and to
    /// the wallet by the cosigner; this is both, against a real enclave.
    test("an authenticated tenant cannot retrieve another wallet's contribution", () async {
      final heidiSeed = Uint8List.fromList(List<int>.generate(32, (i) => (i * 11 + 5) & 0xff));
      final heidi = await wallet('tenant_heidi');
      final mallory = await wallet('tenant_mallory');
      try {
        heidi.client.setSeedSource(FixedSeedSource(heidiSeed));
        await heidi.client.doDkg();
        await mallory.client.doDkg();
      } finally {
        await heidi.close();
        await mallory.close();
      }

      // Mallory's passkey — her tenant — on a device with nothing stored, deriving as Heidi.
      final asHeidi =
          await harness!.newDeviceFor('tenant_mallory', aspHost: aspHost, aspPort: aspPort);
      try {
        asHeidi.client.setSeedSource(FixedSeedSource(heidiSeed));
        await expectLater(
          asHeidi.client.recover(),
          throwsA(predicate((e) => '$e'.contains('does not derive this wallet'))),
        );
        expect(asHeidi.client.isInitialized, isFalse);
        expect(await asHeidi.client.restoreState(), isFalse,
            reason: 'a refused recovery writes nothing');
      } finally {
        await asHeidi.close();
      }
    }, timeout: const Timeout(Duration(minutes: 10)));
  });

  group('pairing a service into an escrow', () {
    // The wallet sends where the enclave sent — but the enclave's address for this host is not one
    // the test process can route to. See `RewritingDelivery`.
    final delivery = RewritingDelivery();

    /// Wait for the cosigner to agree a pairing is finished.
    ///
    /// Finishing needs BOTH parties, and they speak by different routes. The wallet's word rides
    /// the RPC it just made; the service's travels the other way — an event on the connection the
    /// runtime holds, one `on-message` invocation, and that invocation needs the tenant lock the
    /// pairing call was holding. So "ready" arrives shortly *after* the call that caused it
    /// returns, which is what asynchronous agreement looks like and not a bug to design away.
    Future<String> readyWithin(Wallet w, String escrowKeyHex,
        {Duration limit = const Duration(seconds: 30)}) async {
      final deadline = DateTime.now().add(limit);
      while (true) {
        final listed = await w.client.escrowStatus();
        final row =
            listed.firstWhere((e) => e.escrowKey.toLowerCase() == escrowKeyHex.toLowerCase());
        if (row.serviceReady) return 'ready';
        if (DateTime.now().isAfter(deadline)) {
          // Which of the two is missing, and what the cosigner said to the service, because
          // "not ready" alone does not say whose word never arrived.
          return 'not ready: service_confirmed=${row.serviceConfirmed} '
              'wallet_confirmed=${row.walletConfirmed}; '
              'the cosigner replied ${service!.replies}';
        }
        await Future<void>.delayed(const Duration(milliseconds: 250));
      }
    }

    /// Both deliveries, for real: the cosigner's half leaves the enclave over its allowlisted
    /// egress, the wallet's leaves this device over HTTP, and neither party ever holds both.
    ///
    /// The unit tests for pairing hand the service both halves in memory, which is precisely why
    /// they could not notice that the wallet never sent its own. This one can: the service assembles
    /// only what actually arrived, and then signs with it.
    test('both halves arrive by their own routes, and the pair can sign', () async {
      final alice = await wallet('pair_alice');
      try {
        await alice.client.doDkg();
        final passkey = alice.gate.authenticator as SoftwareAuthenticator;
        final before = passkey.counter;

        final set = await alice.client.setUpEscrow(
          serviceIdentifier: serviceIdentifier,
          policy: const {'op': 'always'},
          deadline: DateTime.now().add(const Duration(hours: 1)),
          delivery: delivery,
        );
        final escrow = set.escrow, pairing = set.pairing;
        expect(passkey.counter - before, 1,
            reason: 'minting, pairing and striking the deal are one approval');

        // The service has both halves and checked the share they sum to. Nothing about that came
        // from the wallet's say-so — it assembled and verified for itself.
        expect(service!.isReady(escrow.escrowKeyHex, pairing.attemptIdHex), isTrue,
            reason: 'the service must hold a finished share, not one half of one');
        expect(pairing.serviceOrigin, 'http://192.168.127.254:$servicePort',
            reason: 'the wallet delivers where the enclave delivered, not where it chose');

        final share = service!.shareFor(escrow.escrowKeyHex, pairing.attemptIdHex)!;
        expect(
          share.keyPackage.verifyingShare.toLowerCase(),
          pairing.serviceVerifyingShareHex.toLowerCase(),
        );

        // The pairing signs for the escrow key itself — a refresh preserves it, so money already in
        // the escrow is reachable through this pairing too.
        expect(
          _hex(ark_threshold.elemSerializeCompressed(share.publicKeyPackage.verifyingKey.E))
              .toLowerCase(),
          escrow.escrowKeyHex.toLowerCase(),
        );

        // And the cosigner agrees it is finished, which is what makes it usable. Both parties had
        // to say so: the wallet over the RPC, the service over the connection the runtime holds.
        expect(await readyWithin(alice, escrow.escrowKeyHex), 'ready',
            reason: 'the service confirms over the stream, and only then is a pairing usable');
        final listed = await alice.client.escrowStatus();
        final row = listed
            .firstWhere((e) => e.escrowKey.toLowerCase() == escrow.escrowKeyHex.toLowerCase());
        expect(
            row.serviceIdentifier.toLowerCase(), _hex(serviceIdentifier.serialize()).toLowerCase());
        expect(row.hasSession(), isTrue, reason: 'the deal was struck with the pairing');

        // The connection outlives the call that opened it. That is the whole reason the half went
        // on a stream rather than in a POST: the service has to be able to speak first later.
        expect(service!.isHolding(_streamIdFor(serviceIdentifier)), isTrue);
      } finally {
        await alice.close();
      }
    }, timeout: const Timeout(Duration(minutes: 15)));

    /// A pairing whose wallet half never arrives is NOT usable — and says so rather than looking
    /// finished. This is the failure the old code had permanently and silently.
    test('a pairing with only the cosigner half is refused as unfinished', () async {
      final bob = await wallet('pair_bob');
      try {
        await bob.client.doDkg();

        service!.rejectWalletDeliveries = true;
        await expectLater(
          bob.client.setUpEscrow(
            serviceIdentifier: serviceIdentifier,
            policy: const {'op': 'always'},
            deadline: DateTime.now().add(const Duration(hours: 1)),
            delivery: delivery,
          ),
          throwsA(anything),
          reason: 'a pairing the service cannot complete must not report success',
        );
        service!.rejectWalletDeliveries = false;
        // Minted before the pairing failed, so this wallet still knows it holds it.
        final escrow = bob.client.escrows.single;

        // The cosigner sealed it pending, not ready. Given time to converge rather than checked
        // instantly, so this cannot pass merely by being quick: neither party has anything to say,
        // and after the wait it is still not ready.
        expect(await readyWithin(bob, escrow.escrowKeyHex, limit: const Duration(seconds: 3)),
            isNot('ready'),
            reason: 'one half is not a pairing, and must not be reported as one');

        // And no deal: it is struck only once the wallet's half is delivered, and nothing else
        // ever commits an escrow — so this one is its owner's, and never anybody's to be paid from.
        final row = (await bob.client.escrowStatus()).firstWhere(
            (e) => e.escrowKey.toLowerCase() == escrow.escrowKeyHex.toLowerCase());
        expect(row.hasSession(), isFalse,
            reason: 'an escrow whose service cannot sign must not be committed to a deal');
      } finally {
        await bob.close();
      }
    }, timeout: const Timeout(Duration(minutes: 15)));

    /// An escrow is set up with its deal on ONE approval — minted, paired, committed — and funded
    /// by an ordinary send to its address, on one more.
    test('an escrow is set up, dealt and funded on one approval', () async {
      final grace = await wallet('fund_grace');
      try {
        await grace.client.doDkg();
        await boardAndRenew(grace, 0.005);
        final passkey = grace.gate.authenticator as SoftwareAuthenticator;
        final deadline = DateTime.now().add(const Duration(hours: 1));
        Future<int> heldBy(String escrowKeyHex) async =>
            (await grace.client.vtxosAtArkAddress(escrowKeyHex.substring(2)))
                .where((v) => !v.isSpent)
                .toList()
                .totalSats;

        final before = passkey.counter;
        String? toldBeforeFunding;
        final set = await whileMining(
          btc,
          () => grace.client.setUpEscrow(
            serviceIdentifier: serviceIdentifier,
            policy: const {'op': 'always'},
            deadline: deadline,
            delivery: delivery,
            fundSats: 20000,
            beforeFunding: (escrowKeyHex) async => toldBeforeFunding = escrowKeyHex,
          ),
        );
        expect(passkey.counter - before, 1,
            reason: 'the escrow, its deal and its funding are one approval');
        expect(set.agreed, isNotEmpty, reason: 'the owner is told what she agreed to');
        final key = set.escrow.escrowKeyHex;
        expect(toldBeforeFunding, key, reason: 'the escrow is known before any money moves to it');
        expect(set.fundTxid, isNotEmpty);
        expect(await readyWithin(grace, key), 'ready');

        final row = (await grace.client.escrowStatus())
            .firstWhere((e) => e.escrowKey.toLowerCase() == key.toLowerCase());
        expect(row.session.open, isTrue, reason: 'the escrow is committed to the deal');
        expect(row.session.deadlineSecs.toInt(), deadline.millisecondsSinceEpoch ~/ 1000);

        // The price went to the escrow the cosigner minted, at the address its key gives.
        await eventually(
            'the escrow to hold what was sent', () => heldBy(key), (int s) => s == 20000);
      } finally {
        await grace.close();
      }
    }, timeout: const Timeout(Duration(minutes: 15)));

    /// A release, the whole way round: the service asks over the connection the runtime holds, the
    /// cosigner judges it against sealed policy and sealed accounting, signs, and answers on the
    /// same connection.
    ///
    /// What this proves is the PATH and the DECISIONS — that a service which cannot call in can
    /// still be paid, that one payment reference buys one release, and that a lost reply can be
    /// asked for again without being charged twice. That the signature itself is a valid BIP-340
    /// signature over the escrow key is proved where it can be checked properly, in
    /// `cosigner/tests/release_test.rs`, which combines both halves and verifies.
    test('a service is paid over the connection, and one payment pays once', () async {
      final erin = await wallet('release_erin');
      try {
        await erin.client.doDkg();
        // The deal: what the service may take, and until when. Short, because this test waits it
        // out — the only way a deal ends — and long enough to be paired and asked within.
        final deadline = DateTime.now().add(const Duration(seconds: 45));
        final set = await erin.client.setUpEscrow(
          serviceIdentifier: serviceIdentifier,
          policy: const {'op': 'always'},
          deadline: deadline,
          delivery: delivery,
        );
        final escrow = set.escrow, pairing = set.pairing;
        expect(await readyWithin(erin, escrow.escrowKeyHex), 'ready');
        final share = service!.shareFor(escrow.escrowKeyHex, pairing.attemptIdHex)!;

        // Several wallets have now paired with this one service, and the enclave derives its
        // stream id from the SERVICE — so every one of them opened a connection under the same
        // local name. They must still be separate connections here, or one wallet's answer goes
        // down another's socket. What keeps them apart is the tenant the runtime puts on the wire;
        // see `StreamRecord::wire_id`.
        expect(service!.heldUnder(_streamIdFor(serviceIdentifier)), greaterThan(1),
            reason: 'one connection per wallet, all announcing the same local id');
        expect(share.streamId, endsWith('-${_streamIdFor(serviceIdentifier)}'),
            reason: 'the wire name is the tenant and then the id the guest chose');

        // One VTXO in, one payout and change out — so two things to sign, and two commitments.
        final inputs = [
          {
            'txid': '11' * 32,
            'vout': 0,
            'amount_sats': 200000,
            'exit_delay': 512,
          }
        ];
        final commitments = List.generate(2, (_) => _commitment());

        final signed = await service!.requestRelease(
          share: share,
          requestId: 'e2e-release-1',
          toArkAddress: await erin.client.getArkAddress(),
          amountSats: 50000,
          inputs: inputs,
          paymentReference: 'e2e_payment_1',
          commitments: commitments,
        );
        expect(signed['kind'], 'release-signed',
            reason: 'an allowed release must be signed: $signed');
        expect((signed['halves'] as List), hasLength(2),
            reason: 'one half per sighash — the ark tx input and its checkpoint');
        expect(signed['ark_tx'], isNotEmpty,
            reason: 'the service submits what was approved, not a rebuild of it');
        expect((signed['checkpoint_txs'] as List), hasLength(1));
        expect(signed['already_counted'], isFalse);

        // The same request again — what a service whose reply was lost does. Signed afresh, with
        // fresh commitments, and NOT charged a second time.
        final retry = await service!.requestRelease(
          share: share,
          requestId: 'e2e-release-1',
          toArkAddress: await erin.client.getArkAddress(),
          amountSats: 50000,
          inputs: inputs,
          paymentReference: 'e2e_payment_1',
          commitments: List.generate(2, (_) => _commitment()),
        );
        expect(retry['kind'], 'release-signed');
        expect(retry['already_counted'], isTrue,
            reason: 'a retry is answered again and counted once');

        // The same PAYMENT under a new request id. A replayed authorization verifies every time,
        // because it really did succeed — so what stops it paying twice is the sealed record.
        final replay = await service!.requestRelease(
          share: share,
          requestId: 'e2e-release-2',
          toArkAddress: await erin.client.getArkAddress(),
          amountSats: 50000,
          inputs: inputs,
          paymentReference: 'e2e_payment_1',
          commitments: List.generate(2, (_) => _commitment()),
        );
        expect(replay['kind'], 'release-refused');
        expect(replay['reason'], contains('already been released against'));

        // And once the deal runs out, nothing more comes out of it.
        //
        // Waited for rather than ended: a deal has no ending but its deadline. There is no way for
        // the owner to cut one short, deliberately — a commitment she could revoke would leave a
        // service that had already paid a merchant holding the loss.
        //
        // Nothing is written when a deal lapses, so this is the only honest way to test it: the
        // seal is identical either side of the deadline, and only the clock moved.
        await _untilPast(deadline);
        final afterwards = await service!.requestRelease(
          share: share,
          requestId: 'e2e-release-3',
          toArkAddress: await erin.client.getArkAddress(),
          amountSats: 50000,
          inputs: inputs,
          paymentReference: 'e2e_payment_2',
          commitments: List.generate(2, (_) => _commitment()),
        );
        expect(afterwards['kind'], 'release-refused');
        expect(afterwards['reason'], contains('deal is over'));

        // The other half of the same swap — the owner being able to take it back — needs an escrow
        // that actually holds something. This one spends synthetic inputs, so a reclaim of real
        // money is not proved end to end yet.
      } finally {
        await erin.close();
      }
    }, timeout: const Timeout(Duration(minutes: 15)));

    /// A service this image was not built to reach is refused before anything is dealt.
    test('a service the image does not name is refused before anything is dealt', () async {
      final dave = await wallet('pair_dave');
      try {
        await dave.client.doDkg();
        final stranger =
            ark_threshold.Identifier.derive(Uint8List.fromList('nobody-the-image-knows'.codeUnits));

        await expectLater(
          dave.client.setUpEscrow(
            serviceIdentifier: stranger,
            policy: const {'op': 'always'},
            deadline: DateTime.now().add(const Duration(hours: 1)),
            delivery: delivery,
          ),
          throwsA(predicate((e) => '$e'.contains('does not know that service'))),
        );
        expect(dave.client.escrows, isEmpty, reason: 'refused before an escrow was minted');
      } finally {
        await dave.close();
      }
    }, timeout: const Timeout(Duration(minutes: 10)));
  });
}

/// Wait until the clock is past [deadline], with a second to spare.
Future<void> _untilPast(DateTime deadline) async {
  final remaining = deadline.difference(DateTime.now());
  if (remaining.isNegative) return;
  await Future<void>.delayed(remaining + const Duration(seconds: 1));
}

String _hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// One party's FROST commitments for one message: two points, each from a one-time nonce.
///
/// The service commits first, so these go out with the request — which is what lets the cosigner
/// make its own nonce and its share inside a single invocation, and never write a nonce down.
Map<String, String> _commitment() {
  final n = ark_threshold.secp256k1Curve.n;
  String point() {
    final k = ark_threshold.bytesToBigInt(
            Uint8List.fromList(List<int>.generate(32, (_) => _random.nextInt(256)))) %
        n;
    return ark_threshold.elemBaseMul(k == BigInt.zero ? BigInt.one : k);
  }

  return {'hiding': point(), 'binding': point()};
}

final _random = Random.secure();

/// The id the enclave opens its connection to a service under.
///
/// Derived the same way `cosigner::escrow::service_stream_id` derives it, and duplicated
/// here on purpose: a test that computed it by asking the thing it is testing would prove nothing.
String _streamIdFor(ark_threshold.Identifier identifier) =>
    'svc-${_hex(identifier.serialize()).toLowerCase().substring(0, 40)}';

bool _containsBytes(List<int> haystack, List<int> needle) {
  outer:
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

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
