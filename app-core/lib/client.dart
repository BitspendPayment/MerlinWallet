import 'dart:async';
import 'dart:convert';
import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:app_core/ark/ark.dart' as ark_addr;
import 'package:app_core/ark/exit.dart' as ark_exit;
import 'package:app_core/asp/asp_client.dart';
import 'package:app_core/asp/exit_chain.dart';
import 'package:app_core/asp/history.dart';
import 'enclave/gate.dart';
import 'package:app_core/cosigner/connection.dart';
import 'package:app_core/sessions/dkg_session.dart';
import 'package:app_core/sessions/escrow_session.dart';
import 'package:app_core/sessions/pairing_session.dart';
import 'package:app_core/sessions/reclaim_session.dart';
import 'package:app_core/sessions/service_delivery.dart';
import 'package:app_core/sessions/send_session.dart';
import 'package:app_core/sessions/renew_session.dart';
import 'package:app_core/sessions/sign_session.dart';
import 'package:app_core/sessions/delegate.dart';
import 'package:app_core/sessions/exit_plan.dart' show ExitTx;
import 'package:app_core/passkey/escrow_public_state.dart';
import 'package:app_core/passkey/seed_source.dart';
import 'package:app_core/passkey/operation_secrets.dart';
import 'package:app_core/passkey/share_reconstruction.dart';
import 'package:app_core/passkey/wallet_public_state.dart';
import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:app_core/threshold/core/dkg.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;
// `ArkInfo` is hidden: the proto one is the wire shape, and `asp/ark_info.dart` has the value type
// the wallet actually passes around. `SendSession.arkInfoToProto` converts at the boundary.
import 'package:protocol/protocol.dart' hide ArkInfo;
import 'package:hive/hive.dart';
import 'package:synchronized/synchronized.dart';
import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:convert/convert.dart';

import 'package:app_core/persistence/wallet_store.dart';

class MpcClient {
  /// The cosigner: seven ceremony streams and eight single-round calls.
  final CosignerConnection _conn;

  /// Randomness for what must never repeat: an escrow's context, a pairing attempt's id.
  static final _secureRandom = Random.secure();

  /// The ASP. The wallet's own now — the cosigner renounced its socket, so whoever calls it drives
  /// the Ark protocol and relays what it learns.
  final AspClient _asp;
  // Store
  late final WalletStore _store;

  // User ID for this client instance (persisted or derived after DKG)
  List<int>? _userId;
  String? get userId => _userId == null ? null : hex.encode(_userId!);

  /// The FROST group x-only public key (64 hex chars).
  /// This is the owner key for Ark VTXOs — NOT the same as userId.
  String? get groupXOnlyPubKey {
    final pkp = _wallet?.publicKeyPackage;
    if (pkp == null) return null;
    final compressed = threshold.elemSerializeCompressed(pkp.verifyingKey.E);
    final compressedHex = hex.encode(compressed);
    // Strip 02/03 prefix to get x-only
    return compressedHex.length == 66 ? compressedHex.substring(2) : compressedHex;
  }

  /// The FROST group verifying key, COMPRESSED (66 hex) — the wallet's public IDENTITY. Neither
  /// [userId] (a share key) nor [groupXOnlyPubKey] (same key, parity stripped, for taproot).
  String? get groupKeyHex {
    final pkp = _wallet?.publicKeyPackage;
    if (pkp == null) return null;
    return hex.encode(threshold.elemSerializeCompressed(pkp.verifyingKey.E));
  }

  List<int>? get groupKeyBytes {
    final h = groupKeyHex;
    return h == null ? null : hex.decode(h);
  }

  final int _maxSigners;
  final int _minSigners;

  /// Where the wallet's seed comes from: the passkey's PRF in the app, a stand-in in tests.
  ///
  /// Every operation that signs asks it for the seed around its own approval, turns the seed into
  /// the wallet's polynomial, adds the half of the share the cosigner returns on the stream, and
  /// lets all of it go when the operation ends — see [_withOperation]. Nothing else needs a
  /// secret: requests are approved by the enclave's passkey gate, not by anything a share signs.
  SeedSource? _seedSource;

  /// Wire the seed source. Before DKG to create a wallet, before recovery to rebuild one, and
  /// before anything that signs.
  void setSeedSource(SeedSource source) => _seedSource = source;

  /// Everything this device keeps about the wallet's key, all of it public. Null before DKG,
  /// recovery or restore. **There is no private counterpart**: no share, no blinded share, no
  /// dealer secret is held between operations or written anywhere — see
  /// `passkey/wallet_public_state.dart`.
  WalletPublicState? _wallet;

  /// A wallet whose cosigner runs inside an enclave, reached through [gate].
  ///
  /// The gate attests the enclave on every approval and the channel only talks to a socket serving
  /// the certificate it attested — see `CosignerConnection.enclave`.
  ///
  /// The ASP is a separate party and takes none of that: it is arkd, reached directly.
  ///
  /// [storageId] names the Hive box the wallet's public state lives in; [encryptionCipher]
  /// encrypts it (`HiveAesCipher`), and without one it is stored in the clear. Nothing in it is
  /// key material either way.
  MpcClient.enclave({
    required EnclaveGate gate,
    required String aspHost,
    required int aspPort,
    bool aspSecure = false,
    int maxSigners = 2,
    int minSigners = 2,
    String? storageId,
    HiveCipher? encryptionCipher,
  }) : this.withConnection(
          CosignerConnection.enclave(gate),
          aspHost: aspHost,
          aspPort: aspPort,
          aspSecure: aspSecure,
          maxSigners: maxSigners,
          minSigners: minSigners,
          storageId: storageId,
          encryptionCipher: encryptionCipher,
        );

  /// A wallet over a cosigner connection built some other way.
  ///
  /// [asp] replaces the ASP dialled at [aspHost]:[aspPort] with one the caller built — for a test
  /// that needs an ASP to misbehave in a way a real one will not on request, such as going quiet
  /// in the middle of a batch.
  MpcClient.withConnection(
    CosignerConnection connection, {
    required String aspHost,
    required int aspPort,
    bool aspSecure = false,
    int maxSigners = 2,
    int minSigners = 2,
    String? storageId,
    HiveCipher? encryptionCipher,
    AspClient? asp,
  })  : _conn = connection,
        _asp = asp ?? AspClient.connect(aspHost, aspPort, secure: aspSecure),
        _maxSigners = maxSigners,
        _minSigners = minSigners {
    _store = WalletStore(
      boxName: storageId ?? 'mpc_wallet_state_default',
      cipher: encryptionCipher,
    );
  }

  /// The ASP, for a caller that needs to ask it something directly — chiefly polling for receives.
  AspClient get asp => _asp;

  /// The cosigner connection. Exposed for a test harness to drive a raw stream with.
  CosignerConnection get cosigner => _conn;

  /// Hang up on both. Neither is usable afterwards.
  Future<void> close() async {
    await _conn.shutdown();
    await _asp.shutdown();
  }

  /// Initializes persistence for the client.
  ///
  /// [path] is the directory where client state will be stored.
  /// If [path] is null, defaults to `$HOME/.mpc_wallet/client`.
  ///
  /// This must be called before creating MpcClient instances.
  static Future<void> initPersistence({String? path}) async {
    String storePath;
    if (path != null) {
      storePath = path;
    } else {
      final home = Platform.environment['HOME'] ?? Directory.current.path;
      storePath = p.join(home, '.mpc_wallet', 'client');
    }

    final dir = Directory(storePath);
    if (!dir.existsSync()) {
      dir.createSync(recursive: true);
    }
    Hive.init(storePath);
  }

  // Real 2-of-2: a completed DKG yields the normal policy; there is no recovery policy.
  bool get isInitialized => _wallet != null;

  /// Restores client state from persistence.
  /// [debugState] can be provided to inject state for testing (bypassing store).
  /// Returns true if state was found and restored.
  ///
  /// Throws [IncompatibleWalletStateException] when this device holds state from before shares
  /// were rebuilt per operation. It is neither read nor replaced: see [resetLocalState].
  Future<bool> restoreState({Map<String, dynamic>? debugState}) async {
    // WalletStore relies on Hive.init being called previously — see [initPersistence].
    await _store.init();

    final state =
        debugState != null ? validateClientState(debugState) : await _store.getClientState();
    // Before the early return: a device with nothing stored holds nothing, escrows included.
    _escrows.clear();
    if (state == null) return false;

    _userId = hex.decode(state['userId'] as String);
    final wallet = state['wallet'];
    _wallet = wallet is Map ? WalletPublicState.fromJson(Map<String, dynamic>.from(wallet)) : null;
    _escrows.addAll([
      for (final e in (state['escrows'] as List? ?? const []))
        EscrowPublicState.fromJson(Map<String, dynamic>.from(e as Map)),
    ]);

    final delegate = state['delegate'];
    _delegate =
        delegate is Map ? DelegateStatus.fromJson(Map<String, dynamic>.from(delegate)) : null;
    final exitScript = state['exitScriptPubkey'];
    _exitScriptPubkeyHex = exitScript is String && exitScript.isNotEmpty ? exitScript : null;

    return true;
  }

  /// Everything persisted, and all of it public. `WalletStore.saveClientState` refuses a map that
  /// holds a share by any of the names one has had, so this cannot regress quietly.
  Future<void> _saveState() async {
    final state = <String, dynamic>{
      'stateVersion': walletStateVersion,
      'userId': hex.encode(_userId!),
    };
    if (_wallet != null) state['wallet'] = _wallet!.toJson();
    if (_escrows.isNotEmpty) {
      state['escrows'] = [for (final e in _escrows) e.toJson()];
    }
    if (_delegate != null) state['delegate'] = _delegate!.toJson();
    if (_exitScriptPubkeyHex != null) state['exitScriptPubkey'] = _exitScriptPubkeyHex;
    await _store.saveClientState(state);
  }

  /// Delete everything this device stores about the wallet, file included.
  ///
  /// The way out of an [IncompatibleWalletStateException], and the only one: there is no
  /// migration. **It deletes no key** — none is stored — so a wallet with a passkey is restored
  /// afterwards with [recover]. What does not come back is what only this device had: the exit
  /// address, and the pre-signed exits, until the next delegate renewal reissues them.
  Future<void> resetLocalState() async {
    await _store.destroy();
    _userId = null;
    _wallet = null;
    _escrows.clear();
    _delegate = null;
    _exitScriptPubkeyHex = null;
  }

  // --- The operation ---------------------------------------------------------------------------

  /// One at a time. See [_withOperation].
  final Lock _operations = Lock();

  /// Whether an operation that holds the wallet's secrets is running — a renewal can be minutes. A
  /// second one started now waits its turn, and is approved only once it has it.
  bool get operationInProgress => _operations.locked;

  /// Called with each operation as it begins. For tests, which have no other way to see that an
  /// operation that failed or was cancelled let go of what it held.
  void Function(WalletOperation operation)? debugOnOperation;

  /// Run [run] with the wallet's secrets, and take them away again.
  ///
  /// The whole lifetime of a secret on this device is this method:
  ///
  ///  1. **Wait for a turn.** Operations that sign are serialized. The runtime runs one stream
  ///     per tenant anyway, so a second one could only ever have burnt a fingerprint and then
  ///     hung; and one operation's secrets are never in memory beside another's.
  ///  2. **[prepare]** — the slow, secret-free reads (the ASP's parameters, the indexer's set) —
  ///     *before* the approval, because an approval is good for under a minute and a turn can
  ///     take longer than that to come.
  ///  3. **Approve, and take the seed from the same gesture** (`SeedSource.seedDuring`). One
  ///     fingerprint: the approval is kept for the stream [run] is about to open
  ///     (`CosignerConnection.approveAhead`), and the PRF output becomes the polynomial.
  ///  4. **[run]**, with a [WalletOperation] that turns the cosigner's contribution into a key
  ///     package when the stream brings it, and holds it for that stream's rounds only.
  ///  5. **Dispose**, in a `finally` — success, failure, cancellation alike — and drop an
  ///     approval nothing used.
  ///
  /// The whole of it is cancellable, from the first read to the last round — see
  /// [cancelOperation]. That matters most where it is least obvious: a renewal spends minutes
  /// waiting on the ASP with the share already rebuilt, and an ASP that went quiet would otherwise
  /// hold the share in memory and this lock against every later operation, indefinitely.
  ///
  /// [forWallet] is false for the two operations that have no wallet to check the passkey
  /// against yet: DKG, which makes one, and recovery, which finds one.
  Future<T> _withOperation<P, T>(
    String method, {
    required Future<P> Function() prepare,
    required Future<T> Function(WalletOperation operation, P prepared) run,
    bool forWallet = true,
    WalletPublicState? escrow,
    Uint8List? escrowContext,
    Uint8List? pairingContext,
  }) {
    return _operations.synchronized(() async {
      // For this turn only: a cancel is of the operation running, never of one still in line.
      final cancel = _cancel = CancelSignal();
      try {
        // Raced as a whole, so the turn ends wherever the work is parked — including somewhere
        // no driver thought to guard.
        return await cancel.guard(_runOperation(method, cancel,
            prepare: prepare,
            run: run,
            forWallet: forWallet,
            escrow: escrow,
            escrowContext: escrowContext,
            pairingContext: pairingContext));
      } finally {
        // Here rather than in [_runOperation], and that is the point: a cancel ends this frame
        // at once, while the work it was racing may take a moment to unwind — or, parked on a
        // fingerprint prompt, a long one. The secrets, the approval and the turn are given up
        // now, before the next operation can start, not whenever that happens.
        _operation?.dispose();
        _operation = null;
        // Spent if a stream opened; still there if the operation ended before one did.
        _conn.discardApproval(method);
        _cancel = null;
      }
    });
  }

  /// The running operation's cancel signal, and the operation itself once it has begun. Null
  /// between operations.
  CancelSignal? _cancel;
  WalletOperation? _operation;

  Future<T> _runOperation<P, T>(
    String method,
    CancelSignal cancel, {
    required Future<P> Function() prepare,
    required Future<T> Function(WalletOperation operation, P prepared) run,
    required bool forWallet,
    WalletPublicState? escrow,
    Uint8List? escrowContext,
    Uint8List? pairingContext,
  }) async {
    final source = _seedSource;
    if (source == null) {
      throw StateError(
        'a wallet is derived from its passkey — no seed source is wired, so there is nothing '
        'to derive a key from',
      );
    }
    final wallet = _wallet;
    if (forWallet && wallet == null) throw StateError('no wallet key yet — run DKG first');

    final prepared = await cancel.guard(prepare());

    // A prompt an earlier, cancelled operation left on the screen — see [_takeSeed]. A passkey
    // answers one gesture at a time, so this one's cannot be asked for until that one is over.
    // Cancellable like any other wait: the owner is not made to answer a stale prompt to get out.
    final stale = _promptInFlight;
    if (stale != null) await cancel.guard(stale);

    final taking = _takeSeed(source, method, cancel);
    // Everything [_takeSeed] does, cleanup included, and never an error: it is waited on by
    // whoever comes next, who has no interest in how it went.
    final settled = taking.then<void>((_) {}, onError: (_) {});
    _promptInFlight = settled;
    settled.whenComplete(() {
      if (identical(_promptInFlight, settled)) _promptInFlight = null;
    });
    final seed = await taking;
    // Takes the seed and overwrites it; refuses a passkey that is not this wallet's before
    // anything is opened or sent.
    final operation = await WalletOperation.begin(
      seed,
      wallet: forWallet ? wallet : null,
      escrow: escrow,
      cancel: cancel,
      escrowContext: escrowContext,
      pairingContext: pairingContext,
    );
    if (cancel.isCancelled) {
      operation.dispose();
      throw const OperationCancelled();
    }
    // Disposed by [_withOperation] when the turn ends, however it ends.
    _operation = operation;
    debugOnOperation?.call(operation);
    return run(operation, prepared);
  }

  /// A seed being taken — a fingerprint prompt on the screen, usually — and its cleanup. Outlives
  /// the turn that asked for it when that turn is cancelled, which is the only reason it is kept.
  Future<void>? _promptInFlight;

  /// The seed for [method]'s operation, from the gesture that approves it.
  ///
  /// A fingerprint prompt cannot be taken off the screen from here: the platform offers no way to
  /// withdraw one. So a cancel while it is showing ends the turn at once and leaves this waiting,
  /// and when the owner does answer, the turn is somebody else's — the seed is overwritten, the
  /// approval it minted is dropped, and nothing is begun. The next operation waits for exactly
  /// that ([_promptInFlight]) before asking for a gesture of its own, because a passkey that is
  /// mid-gesture cannot start another.
  ///
  /// **The late approval is dropped here, and only here.** The turn's own cleanup ran when it was
  /// cancelled — before this approval existed — so it cannot be what removes it; left in the cache
  /// it would let the next stream to this method open on a gesture the owner made for something
  /// they had already cancelled. It is dropped whether the seed arrived or the passkey failed
  /// after approving. It cannot take a newer operation's approval with it: whoever is next waits
  /// for this to finish ([_promptInFlight]) before asking for its own.
  Future<Uint8List> _takeSeed(SeedSource source, String method, CancelSignal cancel) async {
    final Uint8List seed;
    try {
      seed = await source.seedDuring(() => _conn.approveAhead(method));
    } catch (_) {
      if (cancel.isCancelled) _conn.discardApproval(method);
      rethrow;
    }
    if (cancel.isCancelled) {
      seed.fillRange(0, seed.length, 0);
      _conn.discardApproval(method);
      throw const OperationCancelled();
    }
    return seed;
  }

  /// Refuse to change anything on behalf of an operation whose turn is over.
  ///
  /// A cancel ends the turn at once, but the work it was racing unwinds in its own time — and a
  /// callback that was waiting on an answer still has it delivered. Without this a cancelled
  /// recovery would go on, when the cosigner's reply arrived, to adopt the wallet and save it:
  /// reported as cancelled, and done anyway. Called before every change an operation makes to
  /// this client or its store. The turn's end disposes the operation, which is what this reads.
  void _stillRunning(WalletOperation operation) {
    if (operation.isDisposed) throw const OperationCancelled();
  }

  /// Cancel the operation in flight, if there is one. It fails with [OperationCancelled], lets go
  /// of the share it rebuilt, and gives up its turn — now, wherever it is waiting.
  ///
  /// Two things have to happen, because an operation waits on two kinds of party:
  ///
  ///  * **The cosigner.** Its streams are ended, so a driver parked on the cosigner's next message
  ///    is told the stream closed. [close] alone does not do this — it is graceful, and waits.
  ///  * **Everybody else.** A renewal spends most of its life waiting on the ASP — the batch
  ///    schedule, the event stream — and a send on `SubmitTx`; closing the cosigner interrupts
  ///    none of it. Those waits go through the operation's `CancelSignal`, so they end here too.
  ///    Without that an ASP that went quiet would keep the share in memory, and the lock against
  ///    every later operation, for as long as it stayed quiet.
  ///
  /// Operations still waiting their turn are untouched: they hold nothing yet, and run next.
  ///
  /// **What cancelling a renewal costs is the ASP's business, not this method's.** A round
  /// abandoned after the intent is registered is a round the ASP was counting on; arkd may hold
  /// that against the wallet. This is for an owner who has decided to stop, not something to call
  /// on a timer.
  Future<void> cancelOperation() async {
    _cancel?.cancel();
    await _conn.cancelOpenStreams();
  }

  static Future<void> _nothingToPrepare() async {}

  threshold.PublicKeyPackage? get publicKey => _wallet?.publicKeyPackage;

  /// What this device knows about the wallet's key. Public, all of it.
  WalletPublicState? get walletPublicState => _wallet;

  // --- SERVER METADATA ---

  /// Fetch the server's deployment metadata (Bitcoin network).
  /// Unauthenticated; safe to call before DKG completes.
  Future<GetServerInfoResponse> getServerInfo() => _conn.getServerInfo();

  // --- DKG ---

  /// Run the DKG ceremony, and keep what it made public.
  ///
  /// 2-of-2 {wallet, cosigner}: both deal, both hold a share, both are needed to sign. The wallet
  /// deals a polynomial derived from its passkey, and **keeps nothing of what comes back but the
  /// public half** — not the share, not the dealer secret. Its share is rebuilt, for each operation
  /// that signs, from that same polynomial and the scalar the cosigner dealt and sealed.
  ///
  /// So before anything is saved this proves that it can be: the share is rebuilt the way every
  /// later operation will rebuild it, from the polynomial and the cosigner's round-2 package, and
  /// compared with the one the ceremony computed. A wallet that could not sign is found out here,
  /// while it is a failed onboarding and not an unspendable balance.
  ///
  /// One approval, which is also where the seed comes from.
  Future<void> doDkg() async {
    await _store.init();
    await _withOperation('Dkg', forWallet: false, prepare: _nothingToPrepare,
        run: (operation, _) async {
      final polynomial = operation.takePolynomial();
      final result = await DkgSession(_conn).run(
        maxSigners: _maxSigners,
        minSigners: _minSigners,
        polynomial: polynomial,
        deviceToken: _deviceToken ?? '',
      );
      final wallet = WalletPublicState.fromPublicKeyPackage(
        result.dkg.publicKeyPackage,
        result.dkg.keyPackage.identifier,
        minSigners: _minSigners,
      );
      final rebuilt = reconstructWalletShare(
        polynomial: polynomial,
        dealtShare: result.dealtShare,
        wallet: wallet,
      );
      _stillRunning(operation);
      if (rebuilt.secretShare != result.dkg.keyPackage.secretShare) {
        throw StateError(
          'the share this passkey and the cosigner rebuild is not the one the ceremony made — '
          'this wallet could never sign, and is not saved',
        );
      }
      _adopt(wallet);
      await _saveState();
      _deviceTokenCarried(result.deviceEnrolled);
    });
  }

  void _adopt(WalletPublicState wallet) {
    _wallet = wallet;
    _userId = threshold.elemSerializeCompressed(wallet.verifyingShare).toList();
  }

  // --- Recovery ---

  /// Rebuild this wallet on a device that has never seen it, from its passkey alone.
  ///
  /// A share is the sum of both dealers' polynomials at the wallet's identifier:
  ///
  /// ```text
  ///   s = f_wallet(id) + f_cosigner(id)
  /// ```
  ///
  /// The first term is derived here, from the same passkey PRF the wallet was made with — so the
  /// same passkey gives the same polynomial, and therefore the same `id`. The second is the scalar
  /// the cosigner sealed at DKG and hands back; it is half a key and nothing else. Neither side
  /// could do this alone, which is the point.
  ///
  /// The rebuilt share is checked against the verifying share in the ceremony's public key package
  /// — `s·G` must be it — and a wallet that fails that check is refused rather than saved. **The
  /// share itself is not saved either.** What recovery leaves on this device is the public half,
  /// exactly as DKG does; every later operation rebuilds the share the same way this just did, so a
  /// recovered wallet and a freshly made one are the same thing.
  ///
  /// This is the one check that leans on the cosigner: a new device has nothing of its own to
  /// compare the key package with. The group key it names is what the owner's addresses are
  /// derived from, so a substituted package shows up as a wallet that is not theirs.
  ///
  /// Throws if this device already holds a wallet.
  Future<void> recover() async {
    // Asked of the store, not of memory: a device with a wallet in Hive is not a device to recover
    // onto. State from before this build throws here instead — see [resetLocalState].
    if (await restoreState()) {
      throw StateError('this device already holds a wallet; nothing to recover');
    }

    await _withOperation('Recover', forWallet: false, prepare: _nothingToPrepare,
        run: (operation, _) async {
      final polynomial = operation.takePolynomial();
      final resp = await operation.cancel.guard(
          _conn.recover(cs.RecoverRequest(identifier: operation.identifier.serialize())));
      // The polynomial was taken out of the operation, so disposing it did not take it from this
      // frame. If the turn ended while the cosigner was answering, stop here: nothing is rebuilt
      // from a reply nobody is waiting for, and nothing is saved.
      _stillRunning(operation);

      // The one time the public half comes from the cosigner rather than from this device, so the
      // two things it said are checked against each other, and then the share against both.
      final wallet = publicStateFromRecovery(
        publicKeyPackage: threshold.PublicKeyPackage.fromJson(
            jsonDecode(resp.publicKeyPackageJson) as Map<String, dynamic>),
        claimedGroupKeyHex: resp.groupKey,
        identifier: operation.identifier,
        minSigners: _minSigners,
      );
      // Rebuilt to be checked, not to be kept: what is saved is what it was checked against.
      reconstructWalletShare(polynomial: polynomial, dealtShare: resp.dealtShare, wallet: wallet);

      // The escrows, the same way: public state only, checked on first use — the halves a share
      // is rebuilt from ride the stream that signs with it. One minted before its context was
      // recorded cannot be rebuilt by any passkey, and is left out rather than kept as a key this
      // device could see and never spend from.
      final escrows = [
        for (final e in resp.escrows)
          EscrowPublicState.fromSummary(e,
              walletIdentifier: operation.identifier, minSigners: _minSigners),
      ].whereType<EscrowPublicState>().toList();

      _stillRunning(operation);
      _adopt(wallet);
      _escrows
        ..clear()
        ..addAll(escrows);
      await _saveState();
    });
  }

  // --- Escrow ---
  //
  // A second 2-of-2 over a key of its own, so money can be committed to a deal without committing
  // the wallet. See `sessions/escrow_session.dart`.

  /// Mint an escrow key: one reshare with the cosigner, `V' = V + Δ_wallet + Δ_cosigner`.
  ///
  /// The wallet's own key is untouched, and nothing is escrowed by minting — an escrow holds money
  /// only once money is sent to the address this returns. What the device keeps is public: the
  /// escrow key, this wallet's place in it, and the package a rebuilt share is checked against.
  /// The share itself is rebuilt per operation, from the passkey and one scalar the cosigner
  /// sealed, exactly as the wallet's own share is.
  ///
  /// The delta is derived under a context drawn fresh here. It must never repeat for one wallet —
  /// two escrows on one delta are two points on one line — and the cosigner refuses a repeat, so a
  /// failure to draw properly is loud rather than silent.
  ///
  /// One approval, which is also where the seed comes from.
  Future<EscrowPublicState> createEscrow() async => (await _mintEscrow()).escrow;

  /// Mint an escrow, pair [serviceIdentifier] into it and commit it to a deal, on ONE approval.
  ///
  /// Pairing is a second 2-of-2 over the same key: afterwards `{service, cosigner}` can sign the
  /// escrow as well as `{wallet, cosigner}`. The wallet and the service share no pairing, so they
  /// cannot sign together; the cosigner is in both, which is what makes its policy the thing an
  /// escrow rests on.
  ///
  /// The deal: until [deadline] the service may release from the escrow, judged against [policy],
  /// and this wallet may **not** take it back; afterwards those swap. There is no way to end it
  /// early: a commitment the owner can revoke is not one, and [deadline] is the whole of her
  /// control. Nothing in Bitcoin enforces that — both pairings sign the same key — so what holds it
  /// up is the cosigner declining to co-sign with the wrong party at the wrong time, in attested
  /// code. See `cosigner/src/escrow.rs`. One escrow, one deal: the next deal mints the next
  /// escrow. `agreed` is the policy rendered as a sentence — what the owner actually agreed to.
  ///
  /// Nothing is escrowed yet: money goes in by an ordinary send to [escrowArkAddress]. Fund it once
  /// the pairing is ready — the service can release nothing before.
  ///
  /// [serviceIdentifier] names a service the **image** knows. The wallet never names a URL: the
  /// cosigner resolves one from its measured image, delivers its own half there, and returns the
  /// origin so this wallet sends its half to the same place. A service this enclave was not built
  /// to reach is refused before anything is minted.
  ///
  /// The escrow is saved the moment it exists, before anything is dealt on it, so a pairing that
  /// fails leaves an escrow this wallet knows it holds — unpaired, and set up anew next time.
  ///
  /// Returns once the service has both halves and this wallet has confirmed. The pairing is usable
  /// a moment later, when the service's own confirmation reaches the cosigner — it cannot while
  /// this stream holds the tenant.
  Future<({EscrowPublicState escrow, PairingResult pairing, String agreed})> setUpEscrow({
    required threshold.Identifier serviceIdentifier,
    required Map<String, dynamic> policy,
    required DateTime deadline,
    DeliverToService? delivery,
  }) async {
    final set = await _mintEscrow(
      pairWith: (service: serviceIdentifier, policy: policy, deadline: deadline),
      delivery: delivery,
    );
    return (escrow: set.escrow, pairing: set.pairing!, agreed: set.agreed!);
  }

  Future<({EscrowPublicState escrow, PairingResult? pairing, String? agreed})> _mintEscrow({
    ({
      threshold.Identifier service,
      Map<String, dynamic> policy,
      DateTime deadline,
    })? pairWith,
    DeliverToService? delivery,
  }) async {
    final context = _random16();
    // Both drawn before the approval: the operation reads the passkey once, before the escrow key
    // exists, so the slope is derived under the escrow's context — see `pairingSlope`.
    final attempt = pairWith == null ? null : _random16();
    return _withOperation<void,
        ({EscrowPublicState escrow, PairingResult? pairing, String? agreed})>(
      'Escrow',
      escrowContext: context,
      pairingContext: attempt == null ? null : Uint8List.fromList([...context, ...attempt]),
      prepare: _nothingToPrepare,
      run: (operation, _) async {
        final wallet = _wallet!;
        EscrowPublicState? escrow;
        final result = await EscrowSession(_conn).run(
          walletId: operation.identifier,
          walletPkp: wallet.publicKeyPackage,
          resolveWallet: operation.keyPackage,
          delta: operation.takeEscrowDelta(),
          context: context,
          pair: pairWith == null
              ? null
              : (
                  service: pairWith.service,
                  attemptId: attempt!,
                  slope: operation.takePairingSlope(),
                  delivery: delivery ?? HttpServiceDelivery(),
                  cancel: operation.cancel,
                  policy: pairWith.policy,
                  deadline: pairWith.deadline,
                ),
          onMinted: (minted) async {
            // The share lives in the operation, so it is let go with it — never in this frame.
            operation.holdEscrowKeyPackage(minted.keyPackage);
            escrow = EscrowPublicState(
              escrowKeyHex: minted.escrowKeyHex,
              wallet: WalletPublicState.fromPublicKeyPackage(
                minted.publicKeyPackage,
                minted.keyPackage.identifier,
                minSigners: _minSigners,
              ),
              contextHex: hex.encode(context),
            );
            _stillRunning(operation);
            _escrows.add(escrow!);
            await _saveState();
          },
        );
        _stillRunning(operation);
        return (escrow: escrow!, pairing: result.pairing, agreed: result.agreed);
      },
    );
  }

  static Uint8List _random16() =>
      Uint8List.fromList(List<int>.generate(16, (_) => _secureRandom.nextInt(256)));

  /// Take back what is left of an escrow, once its deal is over.
  ///
  /// `{wallet, cosigner}` signing the escrow key — the pairing the service is not in. Refused while
  /// the deal is live: until it closes, the money is committed, and an escrow its owner can empty
  /// at will commits nothing to anybody.
  ///
  /// [vtxos] is what the escrow's address holds, from the indexer. Where the money goes is **not**
  /// sent: the cosigner derives this wallet's own address from the key it already holds, and
  /// reports it back so the owner sees where it went.
  Future<ReclaimResult> reclaimEscrow({
    required String escrowKeyHex,
    required List<IndexerVtxo> vtxos,
    ArkInfo? info,
  }) async {
    final escrow = _escrows.firstWhere(
      (e) => e.escrowKeyHex.toLowerCase() == escrowKeyHex.toLowerCase(),
      orElse: () => throw StateError('this wallet holds no escrow $escrowKeyHex'),
    );
    final arkInfo = info ?? await _asp.getInfo();

    // A reclaim is a send — of the escrow's key, to this wallet — on the `Send` stream.
    return _withOperation<void, ReclaimResult>(
      'Send',
      escrow: escrow.wallet,
      escrowContext: Uint8List.fromList(hex.decode(escrow.contextHex)),
      prepare: _nothingToPrepare,
      run: (operation, _) async {
        final result = await ReclaimSession(_conn, _asp).run(
          escrowKeyHex: escrow.escrowKeyHex,
          vtxos: vtxos,
          info: arkInfo,
          escrowPubKey: escrow.wallet.publicKeyPackage,
          identifier: operation.identifier.serialize(),
          // Rebuilt inside the operation, so it is let go with it — never in a closure here.
          resolveEscrow: operation.escrowKeyPackage,
          cancel: operation.cancel,
        );
        _stillRunning(operation);
        return result;
      },
    );
  }

  /// What a key's Ark address holds, from the indexer.
  ///
  /// For a key this wallet does not spend from alone — an escrow's, say. Reading rather than
  /// remembering: this device keeps the public shape of an escrow, never a view of the chain.
  Future<List<IndexerVtxo>> vtxosAtArkAddress(String ownerXOnlyHex, {ArkInfo? info}) async {
    final arkInfo = info ?? await _asp.getInfo();
    final script = ark_addr.vtxoScriptPubkeyHex(
      ownerXOnlyHex: ownerXOnlyHex,
      aspPubkeyHex: arkInfo.signerPubkey,
      exitDelay: arkInfo.unilateralExitDelay,
      network: arkInfo.network,
    );
    return _asp.getVtxosByScripts([script]);
  }

  /// The Ark address an escrow is paid at — where its funding goes, and what the indexer is asked
  /// about to find what it holds.
  ///
  /// Derived from the escrow's own key, exactly as the cosigner derives it.
  Future<String> escrowArkAddress(String escrowKeyHex, {ArkInfo? info}) async {
    final escrow = _escrows.firstWhere(
      (e) => e.escrowKeyHex.toLowerCase() == escrowKeyHex.toLowerCase(),
      orElse: () => throw StateError('this wallet holds no escrow $escrowKeyHex'),
    );
    final arkInfo = info ?? await _asp.getInfo();
    final key = escrow.escrowKeyHex.toLowerCase();
    return ark_addr.arkAddress(
      ownerXOnlyHex: key.length == 66 ? key.substring(2) : key,
      aspPubkeyHex: arkInfo.signerPubkey,
      exitDelay: arkInfo.unilateralExitDelay,
      network: arkInfo.network,
    );
  }

  /// What the cosigner holds for this wallet's escrows, including any live deal. Asked rather than
  /// remembered: this device keeps the public shape of an escrow, never the state of its deal.
  Future<List<cs.EscrowSummary>> escrowStatus() async =>
      (await _conn.escrowList()).escrows;

  /// The escrow keys this wallet has minted, oldest first. Public throughout.
  List<EscrowPublicState> get escrows => List.unmodifiable(_escrows);

  final List<EscrowPublicState> _escrows = [];

  // --- The way out ---
  //
  // Where this wallet's money goes if the cosigner is never heard from again. Every delegate
  // renewal signs one exit per VTXO to it, and the wallet keeps them — see
  // `sessions/exit_plan.dart`. Without an address there is nothing to pre-sign to, which is why the
  // app asks for one before it opens.

  String? _exitScriptPubkeyHex;

  /// The scriptPubKey exits pay, hex. Empty until an address is set.
  String get exitScriptPubkeyHex => _exitScriptPubkeyHex ?? '';

  bool get hasExitAddress => (_exitScriptPubkeyHex ?? '').isNotEmpty;

  /// Set the address unilateral exits pay to, checked against the ASP's network.
  ///
  /// Throws if it is not an address, or belongs to another chain — a mistake here is only
  /// discovered on the day nothing else works, so it is caught on the day it is typed. Exits
  /// already signed still pay the old address; the next delegate renewal reissues them to this
  /// one.
  Future<void> setExitAddress(String address) async {
    final info = await _asp.getInfo();
    _exitScriptPubkeyHex =
        ark_exit.onchainScriptPubkey(address: address.trim(), network: info.network);
    await _saveState();
  }

  /// Forget the exit address. The exits already signed are kept — they are still spendable.
  Future<void> clearExitAddress() async {
    _exitScriptPubkeyHex = null;
    await _saveState();
  }

  /// The exits this wallet holds, newest issue first: one per VTXO the last delegate renewal
  /// covered.
  List<ExitTx> get exits => _delegate?.exits ?? const [];

  /// The whole path one exit has to take: every transaction from the commitment on-chain down to
  /// the VTXO, and then the pre-signed exit itself.
  ///
  /// The transactions above the exit are the ASP's and the round's, already signed, and the
  /// indexer hands them back on request — so this is a read, not a signature, and costs no
  /// approval. What it is for is honesty: the exit alone is not enough, and the owner should be
  /// able to see what else has to be published and whether it is all there.
  Future<ExitChain> exitChain(ExitTx exit) async {
    final parts = exit.outpoint.split(':');
    final txid = parts.first;
    final vout = int.tryParse(parts.length > 1 ? parts[1] : '0') ?? 0;
    final links = await _asp.getVtxoChain(txid, vout);
    // Everything but the commitment has to be published, so everything but the commitment is
    // worth fetching. The commitment is already on-chain.
    final wanted = [
      for (final l in links)
        if (l.kind != ChainKind.commitment) l.txid,
    ];
    final raw = await _asp.getVirtualTxs(wanted);
    return ExitChain.fromLinks(
      outpoint: exit.outpoint,
      vtxoTxid: txid,
      links: links,
      rawTxs: raw,
      exit: ExitHop(
        txid: exit.txid,
        kind: ChainKind.exit,
        depth: 0, // Replaced by `fromLinks`: the exit is always last.
        rawTx: exit.rawTx,
      ),
    );
  }

  // --- Wakes ---
  //
  // The cosigner wakes this device when a sealed delegate needs it, and for that has to be given the
  // device's push token. Not with a `RegisterDevice` of its own — every call is a passkey approval —
  // but carried on a call the user already made: the DKG, or the next delegate renewal.

  String? _deviceToken;

  /// Called with a token once the cosigner has enrolled it, so the caller can stop offering it.
  void Function(String token)? onDeviceEnrolled;

  /// Carry [token] on the next DKG or delegate renewal, until one enrolls it. Null offers nothing —
  /// the token is already enrolled, or there is none.
  void offerDeviceToken(String? token) => _deviceToken = token;

  void _deviceTokenCarried(bool enrolled) {
    final token = _deviceToken;
    if (!enrolled || token == null) return;
    _deviceToken = null;
    onDeviceEnrolled?.call(token);
  }

  PublicKeyPackage? getTweakedPublicKeyPackage(List<int>? merkle_root) {
    final publicKeyPackage = _wallet?.publicKeyPackage;
    return publicKeyPackage?.tweak(merkle_root);
  }

  PublicKeyPackage? getPublicKeyPackage() {
    return _wallet?.publicKeyPackage;
  }


  // --- SIGNING ---

  /// A signature by the group key over [message], untweaked, made with the cosigner.
  ///
  /// One approval. There was an `applyTweak` here that offered a taproot key-path signature; the
  /// cosigner signs untweaked and checks every share, so that path could never have aggregated,
  /// and nothing called it. See `sessions/sign_session.dart`.
  Future<threshold.Signature> sign(Uint8List message, {List<int>? fullTransaction}) =>
      _withOperation('Sign',
          prepare: _nothingToPrepare,
          run: (operation, _) => SignSession(_conn).sign(
                message: message,
                identifier: operation.identifier.serialize(),
                resolve: operation.keyPackage,
                groupPubKey: _wallet!.publicKeyPackage,
                fullTransaction: fullTransaction,
              ));

  // --- ARK ---
  //
  // The cosigner answered all of this once, by relaying its own ASP connection and deriving from a
  // key the caller already held. It has no socket now, so the wallet asks the ASP itself and
  // derives its own addresses through the FFI — which is parity-tested against the same ark-core
  // code the cosigner signs with.

  /// This wallet's group key, x-only, as address derivation wants it.
  String get _ownerXOnly {
    final pkp = _wallet?.publicKeyPackage;
    if (pkp == null) throw StateError('No key yet — run DKG first.');
    final hex = _hexOf(threshold.elemSerializeCompressed(pkp.verifyingKey.E));
    // Compressed is 33 bytes; x-only drops the parity prefix.
    return hex.length == 66 ? hex.substring(2) : hex;
  }

  /// The ASP's published parameters.
  Future<ArkInfo> getArkInfo() => _asp.getInfo();

  /// Where this wallet receives off-chain.
  Future<String> getArkAddress() async {
    final info = await _asp.getInfo();
    return ark_addr.arkAddress(
      ownerXOnlyHex: _ownerXOnly,
      aspPubkeyHex: info.signerPubkey,
      exitDelay: info.unilateralExitDelay,
      network: info.network,
    );
  }

  /// Where this wallet receives on-chain, to be boarded.
  Future<String> getBoardingAddress() async {
    final info = await _asp.getInfo();
    return ark_addr.boardingAddress(
      ownerXOnlyHex: _ownerXOnly,
      aspPubkeyHex: info.signerPubkey,
      exitDelay: info.boardingExitDelay,
      network: info.network,
    );
  }

  /// The wallet's Ark transactions — receives, sends, boardings and renewals — newest first, rebuilt
  /// from every VTXO its scripts ever held. Asks the ASP's indexer, never the cosigner, so it costs no
  /// passkey prompt. See `asp/history.dart`.
  Future<List<ArkTransaction>> arkHistory() async =>
      arkHistoryOf(await listVtxos(includeSpent: true));

  /// What this wallet holds, from the ASP's indexer — or, with [includeSpent], everything it ever
  /// held.
  ///
  /// Both scripts — a boarded VTXO keeps the boarding delay while received and refreshed ones use
  /// the unilateral delay, so they sit under different ones, and asking for a single script makes
  /// the other bucket invisible.
  Future<List<IndexerVtxo>> listVtxos({bool includeSpent = false}) async {
    final info = await _asp.getInfo();
    return _asp.getOwnedVtxos(
      unilateralScript: ark_addr.vtxoScriptPubkeyHex(
        ownerXOnlyHex: _ownerXOnly,
        aspPubkeyHex: info.signerPubkey,
        exitDelay: info.unilateralExitDelay,
        network: info.network,
      ),
      boardingScript: ark_addr.vtxoScriptPubkeyHex(
        ownerXOnlyHex: _ownerXOnly,
        aspPubkeyHex: info.signerPubkey,
        exitDelay: info.boardingExitDelay,
        network: info.network,
      ),
      info: info,
      includeSpent: includeSpent,
    );
  }

  static String _hexOf(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// Send [amountSats] off-chain to [recipientArkAddress]. Returns the ark txid.
  ///
  /// The wallet no longer builds the transaction — the cosigner does, and hands back sighashes to
  /// FROST-sign. What the wallet does instead is talk to the ASP: `SubmitTx`, then `FinalizeTx`,
  /// then tell the cosigner it was accepted so the send is recorded only once it is real.
  Future<String> sendVtxo(String recipientArkAddress, int amountSats) async =>
      (await _send(recipientArkAddress, amountSats)).arkTxid;

  Future<SendResult> _send(String recipientArkAddress, int amountSats) {
    return _withOperation('Send',
        prepare: () async => (info: await _asp.getInfo(), vtxos: await listVtxos()),
        run: (operation, prepared) async {
      final result = await SendSession(_conn, _asp).send(
        recipientArkAddress: recipientArkAddress,
        amountSats: amountSats,
        vtxos: prepared.vtxos,
        info: prepared.info,
        identifier: operation.identifier.serialize(),
        resolve: operation.keyPackage,
        groupPubKey: _wallet!.publicKeyPackage,
        cancel: operation.cancel,
        readHeld: listVtxos,
        deviceToken: _deviceToken ?? '',
        exitScriptPubkeyHex: exitScriptPubkeyHex,
        ownerXOnlyHex: _ownerXOnly,
      );
      _stillRunning(operation);
      _deviceTokenCarried(result.delegate?.deviceEnrolled ?? false);
      // A send spends what the old delegate covered, so the cosigner dropped it: the delegate now
      // is whatever this send renewed, or none.
      await _recordDelegate(result.delegate);
      return result;
    });
  }

  // --- The delegate ----------------------------------------------------------------------------

  DelegateStatus? _delegate;

  /// The delegate last renewed for this wallet — what the cosigner will refresh on its own, and
  /// when. Null until a send, a renewal or [protectFunds] renewed it. See `sessions/delegate.dart`.
  DelegateStatus? get delegateStatus => _delegate;

  /// Held VTXOs no sealed delegate covers: arrived since it was renewed (a receive), or produced
  /// by the cosigner running it. Answered from the indexer alone; asks the cosigner nothing.
  Future<List<IndexerVtxo>> unprotectedVtxos() async {
    final held = (await listVtxos()).where((v) => !v.isSpent).toList();
    final delegate = _delegate;
    return delegate == null ? held : held.where((v) => !delegate.covers(v)).toList();
  }

  /// Renew the delegate over everything held now, so the cosigner refreshes it on its own before
  /// it expires.
  ///
  /// [over] replaces the indexer's answer with a set the caller names. Only a test has any business
  /// doing that — it is how an exit can be proven against bitcoind, by renewing over an output
  /// that carries this wallet's VTXO script but that no ASP ever made.
  ///
  /// One approval — for funds that arrived without an operation of ours; a send or a renewal
  /// renews the delegate on its way out at no extra cost.
  Future<DelegateStatus> protectFunds({List<IndexerVtxo>? over}) {
    return _withOperation('Renew', prepare: () async {
      final info = await _asp.getInfo();
      final held =
          over ?? await heldOnceIndexed(listVtxos, timeout: const Duration(seconds: 10));
      if (held == null) {
        throw StateError(
            'the indexer has not reported every VTXO\'s expiry yet — try again shortly');
      }
      if (held.isEmpty) throw StateError('nothing is held, so there is nothing to protect');
      return (info: info, held: held);
    }, run: (operation, prepared) async {
      final renewed = await RenewSession(_conn, _asp).renewDelegate(
        info: prepared.info,
        identifier: operation.identifier.serialize(),
        resolve: operation.keyPackage,
        groupPubKey: _wallet!.publicKeyPackage,
        vtxos: prepared.held,
        deviceToken: _deviceToken ?? '',
        exitScriptPubkeyHex: exitScriptPubkeyHex,
        ownerXOnlyHex: _ownerXOnly,
      );
      _stillRunning(operation);
      _deviceTokenCarried(renewed.deviceEnrolled);
      await _recordDelegate(renewed);
      return renewed;
    });
  }

  Future<void> _recordDelegate(DelegateStatus? delegate) async {
    _delegate = delegate;
    await _saveState();
  }

  /// Board one on-chain output into Ark, on the `Board` stream. One per call: the cosigner builds
  /// its boarding intent proof for a single outpoint.
  Future<String> board(cs.BoardingUtxo utxo, {void Function(RenewPhase)? onProgress}) =>
      _renewOrBoard(boardingUtxo: utxo, onProgress: onProgress);

  /// The round boarding and a refresh share: [boardingUtxo] boards it, its absence refreshes what is
  /// held.
  Future<String> _renewOrBoard({
    cs.BoardingUtxo? boardingUtxo,
    void Function(RenewPhase)? onProgress,
  }) {
    // Named for the stream it opens: an approval obtained ahead is for one method's path.
    return _withOperation(boardingUtxo == null ? 'Renew' : 'Board',
        prepare: () async => (
              info: await _asp.getInfo(),
              vtxos: boardingUtxo == null ? await listVtxos() : const <IndexerVtxo>[],
            ),
        run: (operation, prepared) async {
      final result = await RenewSession(_conn, _asp).renew(
        info: prepared.info,
        identifier: operation.identifier.serialize(),
        resolve: operation.keyPackage,
        groupPubKey: _wallet!.publicKeyPackage,
        boardingUtxo: boardingUtxo,
        vtxos: prepared.vtxos,
        cancel: operation.cancel,
        onProgress: onProgress,
        readHeld: listVtxos,
        deviceToken: _deviceToken ?? '',
        exitScriptPubkeyHex: exitScriptPubkeyHex,
        ownerXOnlyHex: _ownerXOnly,
      );
      _stillRunning(operation);
      _deviceTokenCarried(result.delegate?.deviceEnrolled ?? false);
      // A refresh spends the old delegate's inputs; boarding leaves it standing. Either way the
      // delegate this renewal renewed, when it did, supersedes it.
      if (result.delegate != null || boardingUtxo == null) {
        await _recordDelegate(result.delegate);
      }
      return result.commitmentTxid;
    });
  }

  /// Refresh the held VTXOs before they expire.
  ///
  /// The `Renew` stream. There is no `storeOnly` any more: renewing
  /// the delegate arms a durable watch, and when its deadline arrives the cosigner either executes
  /// the delegate itself — where its image allowlists the ASP — or wakes this device, and then this
  /// is what runs.
  Future<String> renewHeld({void Function(RenewPhase)? onProgress}) =>
      _renewOrBoard(onProgress: onProgress);

  // --- Devices ----------------------------------------------------------------------------------
  //
  // The cosigner never sees a push token twice and has no channel to send on: it forwards these to
  // the runtime, which owns the FCM credentials and the registry. Enrolling is what makes the
  // cosigner's settle watch able to reach anybody — without it `wake` has no devices and the whole
  // watch runs and notifies nothing.
  //
  // Enrolling is deliberately an interactive call. It grants a standing ability to reach a device,
  // and background work must not be able to grant itself that.

  /// Enrol [token] so this wallet's cosigner can wake this device.
  Future<void> registerDevice(String token) async {
    await _conn.registerDevice(cs.RegisterDeviceRequest()
      ..token = token);
  }

  /// Stop waking the device behind [token] — a sign-out, or a token FCM rotated away.
  Future<void> forgetDevice(String token) async {
    await _conn.forgetDevice(cs.ForgetDeviceRequest()
      ..token = token);
  }

  /// How many devices are enrolled. A count, never the tokens: the cosigner is not meant to be
  /// able to enumerate them.
  Future<int> deviceCount() async {
    return _conn.deviceCount(cs.DeviceCountRequest());
  }
}
