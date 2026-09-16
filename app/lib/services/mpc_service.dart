import 'dart:async';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:hive/hive.dart';
import 'package:path_provider/path_provider.dart';
// `ArkInfo` also exists as a proto message; the ASP's value type is the one meant here.
import 'package:protocol/protocol.dart' hide ArkInfo;

import 'package:app_core/asp/asp_client.dart';
import 'package:app_core/bitcoin.dart';
import 'package:app_core/client.dart';
import 'package:app_core/cosigner/connection.dart' show CosignerException;
import 'package:app_core/enclave/attestation.dart';
import 'package:app_core/enclave/gate.dart';
import 'package:app_core/enclave/manifest.dart' as manifest;

import '../passkey/passkey_channel.dart';
import '../passkey/platform_passkey.dart';
import 'server_host.dart' as server_host;

class MpcService extends ChangeNotifier {
  MpcClient? _client;
  bool _isInitialized = false;
  Future<void>? _persistenceInitFuture;
  bool _dkgComplete = false;
  bool _isConnected = false;
  Box? _identityBox;

  String? _storageId;

  /// The wallet's passkey. It approves every cosigner call — enclave-runtime gates each request on
  /// a fresh assertion — and its PRF output blinds the FROST share. Null until onboarding registers
  /// one, and nothing reaches the cosigner before that.
  PlatformPasskey? _passkey;

  /// The enclave's front door for this host: attests it on every approval, and mints the approvals.
  EnclaveGate? _gate;

  /// Whether a passkey is registered for this wallet.
  bool get passkeyEnabled => _passkey?.isRegistered ?? false;

  MpcService();

  /// Future that completes when init() finishes. Await this before
  /// checking dkgComplete or calling restoreSession().
  late Future<void> initFuture;

  MpcClient? get client => _client;
  bool get isInitialized => _isInitialized;
  bool get dkgComplete => _dkgComplete;
  bool get isConnected => _isConnected;

  MpcBitcoinWallet? _wallet;
  MpcBitcoinWallet? get wallet => _wallet;


  BigInt _balance = BigInt.zero;
  BigInt get balance => _balance;
  List<WalletTransaction> get transactions => _wallet?.transactions ?? [];

  // --- Ark state ---
  //
  // `ArkInfo` and `IndexerVtxo` come from the ASP directly now. They were
  // `GetArkInfoResponse` and `VtxoInfo`, proto messages the cosigner relayed
  // from its own ASP connection — it has no socket, so the app asks and passes
  // what it learns back in on each `SendOpen`/`SettleOpen`.
  ArkInfo? _arkInfo;
  ArkInfo? get arkInfo => _arkInfo;
  String? _arkAddress;
  String? get arkAddress => _arkAddress;
  String? _boardingAddress;
  String? get boardingAddress => _boardingAddress;
  List<IndexerVtxo> _vtxos = [];
  List<IndexerVtxo> get vtxos => _vtxos;
  BigInt _arkBalance = BigInt.zero;
  BigInt get arkBalance => _arkBalance;

  /// Confirmed deposits — the only ones [boardFunds] can settle.
  int _boardingBalance = 0;
  int get boardingBalance => _boardingBalance;
  int _boardingUtxoCount = 0;
  int get boardingUtxoCount => _boardingUtxoCount;

  /// Deposits still in the mempool. Not boardable yet, but shown so a fresh
  /// deposit doesn't look like it never arrived.
  int _boardingPendingBalance = 0;
  int get boardingPendingBalance => _boardingPendingBalance;
  bool _arkAvailable = false;
  bool get arkAvailable => _arkAvailable;

  /// User-forced offline mode (persisted). When true the wallet stays on-chain
  /// only regardless of ASP reachability. [offlineMode] is the effective state:
  /// forced OR the ASP is unreachable.
  bool _offlineModeForced = false;
  bool get offlineModeForced => _offlineModeForced;

  /// On-chain-only mode: the Ark ASP is unavailable (auto-detected) or the user
  /// forced it. In this mode the UI hides Ark + Services and only Bitcoin
  /// (receive / balance / on-chain send) is usable.
  bool get offlineMode => _offlineModeForced || !_arkAvailable;

  /// Toggle user-forced offline mode. Persisted so it survives cold starts.
  /// Turning it OFF kicks an immediate ASP re-probe so Ark comes back promptly;
  /// turning it ON drops Ark polling/state right away.
  Future<void> setOfflineMode(bool forced) async {
    if (_offlineModeForced == forced) return;
    _offlineModeForced = forced;
    if (_identityBox != null && _identityBox!.isOpen) {
      await _identityBox!.put('offlineMode', forced);
    }
    if (forced) {
      _vtxoPollTimer?.cancel();
      _arkAvailable = false;
      notifyListeners();
    } else {
      notifyListeners();
      // Re-probe the ASP; initArk restores Ark state + polling on success.
      await initArk();
    }
  }

  void policyUpdated() {
    notifyListeners();
  }

  String? get receiveAddress {
    if (_wallet == null) return null;
    return _wallet!.toAddress();
  }

  Future<void> refreshHistory() async {
    if (_wallet != null) {
      try {
        await _wallet!.sync();
        _balance = await _wallet!.getBalance();
        _isConnected = true;
      } catch (e) {
        debugPrint("Refresh failed: $e");
        _isConnected = false;
      }
      notifyListeners();
    }
  }

  // Hardcoded for now, could be configurable
  String _host = '10.0.2.2'; // Default, will be overwritten by persistence

  /// Where a remote enclave's measurements are published.
  static const String _manifestRepo = 'BitspendPayment/MPCWallet';
  static const String _manifestTag = 'eif-latest';

  /// What a remote host's enclave must attest to, from the deployment manifest. Local hosts are a
  /// dev enclave, whose pins come from the build — see `DevEnclaveConfig`.
  EnclavePins? _remotePins;

  /// Fetch a remote enclave's pins from the deployment manifest.
  Future<void> fetchManifest() async {
    final m = await manifest.fetchManifest(_manifestRepo, tag: _manifestTag);
    final measurement = RegExp(r'^[a-f0-9]{96}$');
    if (!measurement.hasMatch(m.pcr0) || !measurement.hasMatch(m.pcr16)) {
      throw StateError('the deployment manifest does not carry a valid PCR0 and PCR16');
    }
    _remotePins = EnclavePins.aws(pcr0: m.pcr0, pcr16: m.pcr16);
    debugPrint('Fetched manifest: pcr0=${m.pcr0.substring(0, 16)}… pcr16=${m.pcr16.substring(0, 16)}…');
  }

  /// What this host's enclave must attest to. Throws when there is nothing to pin — talking to an
  /// enclave that has not proved what it is would be the one thing all of this exists to prevent.
  Future<EnclavePins> _pins() async {
    if (server_host.isLocalHost(_host)) return server_host.DevEnclaveConfig.fromDefines.pins();
    if (_remotePins == null) await fetchManifest();
    return _remotePins!;
  }

  Future<void> _ensurePersistenceInitialized() async {
    _persistenceInitFuture ??= () async {
      final appDir = await getApplicationDocumentsDirectory();
      final persistencePath = '${appDir.path}/mpc_client';
      await MpcClient.initPersistence(path: persistencePath);
    }();
    await _persistenceInitFuture;
  }

  Future<void> init() async {
    try {
      // 1. Initialize Hive for MpcClient (and us)
      await _ensurePersistenceInitialized();

      // 2. Open our own box for identity persistence
      _identityBox = await Hive.openBox('mpc_service_identity');

      _host = _identityBox!.get('serverHost', defaultValue: '10.0.2.2');
      debugPrint("MPC Service: Using host: $_host");

      _dkgComplete = _identityBox!.get('dkgComplete', defaultValue: false);
      _storageId = _identityBox!.get('storageId') as String?;
      if (_storageId == null || _storageId!.isEmpty) {
        _storageId = 'mpc_wallet_state_${_generateSessionId()}';
        await _identityBox!.put('storageId', _storageId);
      }

      // Migrate from the old client-side network selection: the wallet
      // network now comes from the server via `getServerInfo()`, so any
      // persisted 'network' key from prior versions is dead weight.
      // No-op if the key isn't present.
      await _identityBox!.delete('network');

      // The hardware-signer option was removed; the wallet is now always the
      // in-process software signer (2-of-2 with the cosigner). Drop any
      // persisted 'signerKind' key from prior versions. No-op if absent.
      await _identityBox!.delete('signerKind');

      // User-forced offline mode (on-chain only). Defaults to false; when true
      // the wallet stays on-chain only even if the ASP is reachable.
      _offlineModeForced =
          _identityBox!.get('offlineMode', defaultValue: false) as bool;

      // What the cosigner's sealed delegate already covers. Restoring this is
      // the whole point of persisting it: without it a cold start reads as "no
      // delegate" and settles again — a real ASP batch round, minutes long and
      // a biometric prompt, for a delegate that is already signed and sealed.
      final delegated = _identityBox!.get('delegatedOutpoints');
      if (delegated is List) {
        _delegatedOutpoints = delegated.cast<String>().toSet();
      }

      _isInitialized = true;
    } catch (e) {
      debugPrint("MPC Service Error: $e");
      rethrow;
    }
  }

  /// Closes all resources. Call this when the app is shutting down.
  @override
  Future<void> dispose() async {
    _vtxoPollTimer?.cancel();
    try {
      await _identityBox?.close();
      _identityBox = null;
    } catch (e) {
      debugPrint("MPC Service: Error closing identity box: $e");
    }
    super.dispose();
  }

  /// Fetch deployment metadata from the cosigner with bounded
  /// retry. Address rendering depends on `bitcoinNetwork`, so we refuse
  /// to proceed without a non-empty value — silently defaulting was the
  /// regression that the empty-string check guards against.
  Future<GetServerInfoResponse> _fetchServerInfoWithRetry() async {
    Object? lastError;
    for (int attempt = 1; attempt <= 3; attempt++) {
      try {
        final info = await _client!.getServerInfo();
        if (info.bitcoinNetwork.isEmpty) {
          throw StateError(
              "Server returned empty bitcoin_network; refusing to construct "
              "wallet without a known HRP source");
        }
        return info;
      } catch (e) {
        lastError = e;
        debugPrint(
            "getServerInfo attempt $attempt/3 failed: $e; "
            "${attempt < 3 ? 'retrying in ${attempt}s' : 'giving up'}");
        if (attempt < 3) {
          await Future.delayed(Duration(seconds: attempt));
        }
      }
    }
    throw StateError(
        "Cosigner unreachable: getServerInfo failed after 3 attempts. "
        "Last error: $lastError. Check that the server is running and "
        "reachable at $_host.");
  }

  /// Set the server endpoint. The Bitcoin network is no longer carried in
  /// app state — it's fetched from the server via `getServerInfo()` at the
  /// moment the wallet is constructed (see `restoreSession`/`doDkg`).
  Future<void> setHost(String host) async {
    if (_host == host && _isInitialized) return;

    debugPrint("MPC Service: Switching host to $host");
    _host = host;

    // Pins belong to a host. Whatever was fetched for the last one says nothing about this one.
    _remotePins = null;
    _closeGate();

    await _ensurePersistenceInitialized();
    if (_identityBox == null || !_identityBox!.isOpen) {
      _identityBox = await Hive.openBox('mpc_service_identity');
    }
    await _identityBox!.put('serverHost', host);
  }

  /// The gate for this host, built once and kept: its attested certificate is what the cosigner
  /// channel pins, and its passkey is what approves each call.
  Future<EnclaveGate> _ensureGate() async {
    final existing = _gate;
    if (existing != null) return existing;
    final gate = EnclaveGate(
      endpoint: server_host.enclaveEndpoint(_host),
      pins: await _pins(),
      origin: server_host.origin(_host),
    );
    final credentialId = _identityBox!.get('passkeyCredentialId') as String?;
    _passkey = PlatformPasskey(rpId: server_host.relyingPartyId(_host), credentialId: credentialId);
    if (credentialId != null) gate.authenticator = _passkey;
    return _gate = gate;
  }

  void _closeGate() {
    _gate?.close();
    _gate = null;
    _passkey = null;
  }

  /// Connect to this host's cosigner, through its enclave, and its ASP.
  Future<MpcClient> _createMpcClient({String? storageId}) async {
    final gate = await _ensureGate();
    if (gate.authenticator == null) {
      throw StateError('no passkey yet — every cosigner call needs one; register it first');
    }
    final asp = server_host.aspEndpoint(_host);
    final client = MpcClient.enclave(
      gate: gate,
      aspHost: asp.host,
      aspPort: asp.port,
      aspSecure: asp.secure,
      storageId: storageId,
    );
    // Before anything that might sign: the share is blinded under the passkey's PRF at DKG, and
    // reconstructed from it at every spend.
    client.setSeedSource(_passkey!.seedSource);
    return client;
  }

  /// Register this wallet's passkey, which is also its tenant in the enclave.
  ///
  /// The first onboarding step after choosing a host, and before DKG: enclave-runtime gates every
  /// request on a passkey, so without one there is no cosigner to run a ceremony with. The DKG that
  /// follows blinds the share under this passkey's PRF from the start — the raw share is never
  /// stored.
  ///
  /// Idempotent: a passkey already registered for this host is kept.
  Future<void> enablePasskey() async {
    if (!_isInitialized) throw StateError("MPC Service not initialized");
    final gate = await _ensureGate();
    if (_passkey!.isRegistered) {
      // Registered on an earlier attempt that did not get as far as DKG. Use it if the device can
      // still sign with it; if not — deleted, or created as a credential this device cannot find
      // (see PlatformPasskey.createCredential) — start over with a new one. Nothing is lost: no key
      // exists yet, and its tenant in the enclave is simply never used again.
      try {
        if (!_passkey!.hasFreshSeed) await _passkey!.waitUntilUsable(timeout: const Duration(seconds: 10));
        return;
      } on PlatformException catch (e) {
        if (e.code != PasskeyChannel.noCredential) rethrow;
        debugPrint('Stored passkey is not usable on this device (${e.message}); registering a new one');
        await _identityBox!.delete('passkeyCredentialId');
        await _identityBox!.delete('tenantId');
        _passkey = PlatformPasskey(rpId: server_host.relyingPartyId(_host));
        gate.authenticator = null;
      }
    }

    final enrolment = await gate.enrol(_passkey!, displayName: 'Merlin');
    await _identityBox!.put('passkeyCredentialId', enrolment.credentialId);
    await _identityBox!.put('tenantId', enrolment.tenantId);
    _passkey!.adopt(enrolment.credentialId);
    // Before anything asks for it: a passkey created a moment ago is not findable yet, and the DKG
    // that comes next would get "Sign in another way" instead of a fingerprint prompt.
    await _passkey!.waitUntilUsable();
    gate.authenticator = _passkey;
    notifyListeners();
    debugPrint('Passkey registered: tenant ${enrolment.tenantId}');
  }

  /// Run initial DKG: a pure 2-of-2 {wallet, cosigner}. The wallet generates its own dealer secret
  /// in-process (see [MpcClient.doDkg]), and its share is blinded under the passkey's PRF as it is
  /// finalized. There is no cloud backup — the share lives only on this device.
  Future<void> doDkg() async {
    if (!_isInitialized) throw StateError("MPC Service not initialized");

    if (_dkgComplete) {
      throw StateError("DKG already completed for this user.");
    }

    final storageId = _storageId ?? 'mpc_wallet_state_default';

    _client = await _createMpcClient(storageId: storageId);
    final serverInfo = await _fetchServerInfoWithRetry();
    _wallet = MpcBitcoinWallet(_client!,
        networkName: serverInfo.bitcoinNetwork, storageId: storageId);
    _wallet!.onSyncComplete = _onWalletSyncComplete;

    // wallet.init() restores persisted state or, on a fresh wallet, runs the
    // 2-of-2 DKG (MpcBitcoinWallet.initializeNewWallet -> client.doDkg()).
    await _wallet!.init();
    _balance = await _wallet!.getBalance();

    _dkgComplete = true;
    _isConnected = true;
    await _identityBox!.put('dkgComplete', true);

    await initArk();
    notifyListeners();
  }

  /// Restores a previously completed session without re-running DKG.
  /// Creates gRPC channel + MpcClient + MpcBitcoinWallet, then calls
  /// wallet.init() which restores keys from Hive persistence.
  Future<void> restoreSession() async {
    if (!_isInitialized) throw StateError("MPC Service not initialized");
    if (!_dkgComplete) throw StateError("DKG not completed. Cannot restore.");

    final storageId = _storageId ?? 'mpc_wallet_state_default';

    _client = await _createMpcClient(storageId: storageId);
    final serverInfo = await _fetchServerInfoWithRetry();
    _wallet = MpcBitcoinWallet(_client!,
        networkName: serverInfo.bitcoinNetwork, storageId: storageId);
    _wallet!.onSyncComplete = _onWalletSyncComplete;

    await _wallet!.init();
    _balance = await _wallet!.getBalance();
    _isConnected = true;

    await initArk();
    notifyListeners();
  }

  /// Reconnects to the server by tearing down the existing channel
  /// and restoring the session fresh.
  Future<void> reconnect() async {
    if (!_dkgComplete) return;

    _isConnected = false;
    notifyListeners();

    try {
      await _client?.close();
    } catch (_) {}
    _client = null;
    _wallet = null;

    try {
      await restoreSession();
    } catch (e) {
      debugPrint("Reconnect failed: $e");
      _isConnected = false;
      notifyListeners();
    }
  }

  /// Called by MpcBitcoinWallet when a background sync completes
  /// (e.g. after a transaction notification from the server).
  Future<void> _onWalletSyncComplete() async {
    try {
      _balance = await _wallet!.getBalance();
      _isConnected = true;
    } catch (e) {
      debugPrint("Post-sync balance update failed: $e");
    }
    notifyListeners();
  }

  // --- Ark methods ---

  Future<void> initArk() async {
    if (_client == null) return;
    // User forced on-chain-only: don't touch the ASP at all. The un-toggle path
    // (setOfflineMode(false) -> initArk) restarts polling.
    if (_offlineModeForced) {
      _arkAvailable = false;
      _vtxoPollTimer?.cancel();
      notifyListeners();
      return;
    }
    try {
      _arkInfo = await _client!.getArkInfo();
      _arkAddress = await _client!.getArkAddress();
      _boardingAddress = await _client!.getBoardingAddress();
      _arkAvailable = true;
      await refreshVtxos();
      _startVtxoPolling();
    } catch (e) {
      debugPrint("Ark init failed (ASP unreachable — offline mode): $e");
      _arkAvailable = false;
      // Keep polling so the ASP is re-probed and Ark auto-recovers when it returns.
      _startVtxoPolling();
    }
    notifyListeners();
  }

  /// Outpoints (`txid:vout`) seen on the previous refresh. Used to detect
  /// "new VTXO arrived" so the auto-settle re-delegation can fire even when
  /// the push notification path didn't deliver (denied perms, force-quit, etc).
  final Set<String> _previousVtxoOutpoints = <String>{};

  /// The outpoints the last settle covered, persisted.
  ///
  /// This replaces `ListVtxosResponse.has_active_delegate`, which the cosigner
  /// answered from its own view of the ASP. It has no such view — it is called
  /// rather than running — so the fact has to live where the knowledge is. It is
  /// persisted rather than held in memory because a cold start would otherwise
  /// read as "no delegate" and settle again: a real ASP batch round, minutes
  /// long and a biometric prompt, for a delegate that is already sealed.
  Set<String> _delegatedOutpoints = <String>{};
  bool _delegateInFlight = false;

  /// Don't retry a failed auto-delegate before this. With a passkey-gated
  /// share, `settleDelegate` is a signing op that can pop a biometric prompt;
  /// without a cooldown a persistent failure would re-prompt on EVERY poll
  /// tick (~10s).
  DateTime? _delegateRetryAfter;
  static const Duration _delegateFailureCooldown = Duration(minutes: 5);

  /// A re-delegate is needed but signing it would pop a biometric prompt, so
  /// we wait for the user instead: the Ark tab shows a delegate button while
  /// this is true (see [delegateNow]).
  bool _delegateActionNeeded = false;
  bool get needsDelegateAction => _delegateActionNeeded;

  /// Periodic VTXO poll. Off-chain receives don't trigger the on-chain electrs
  /// sync, so without this, received VTXOs only show up on a manual refresh.
  /// Runs while Ark is active; the OS pauses it when the app is backgrounded.
  Timer? _vtxoPollTimer;
  bool _vtxoPollInFlight = false;
  static const Duration _vtxoPollInterval = Duration(seconds: 10);

  /// Whether the cosigner's sealed delegate still covers everything we hold.
  ///
  /// A delegate is signed over a specific set of VTXOs, so a new one appearing
  /// makes it stale — that is the whole trigger for re-delegating. Used by
  /// integration tests to verify the auto-delegate flow fired.
  bool get hasActiveDelegate =>
      _vtxos.isNotEmpty && _delegateCoversCurrentVtxos;

  bool get _delegateCoversCurrentVtxos {
    final current = _vtxos.map((v) => v.outpoint).toSet();
    return current.isNotEmpty && current.difference(_delegatedOutpoints).isEmpty;
  }

  /// Record that a settle just covered what we hold, and remember it across restarts.
  void _markDelegated() {
    _delegatedOutpoints = _vtxos.map((v) => v.outpoint).toSet();
    _identityBox?.put('delegatedOutpoints', _delegatedOutpoints.toList());
  }

  /// Whether the last [refreshVtxos] failure was our credentials being refused
  /// rather than the ASP being unreachable. The poll loop must not treat the
  /// former as an outage.
  bool _lastVtxoFailureWasAuth = false;

  /// Refresh VTXO balance/state. Returns true if the ASP call succeeded — the
  /// poll loop uses this to detect an ASP outage and flip into offline mode.
  Future<bool> refreshVtxos() async {
    if (_client == null) return false;
    bool ok = false;
    _lastVtxoFailureWasAuth = false;
    try {
      // A bare list from the indexer. It was `ListVtxosResponse`, which also
      // carried the balance and whether the cosigner held a delegate; both came
      // from a cosigner that was watching the ASP for us. It no longer can, so
      // the balance is a sum and the delegate is tracked here — see
      // [_delegateCoversCurrentVtxos].
      _vtxos = await _client!.listVtxos();
      _arkBalance = _vtxos.fold(BigInt.zero, (sum, v) => sum + BigInt.from(v.amountSats));
      ok = true;
    } on CosignerException catch (e) {
      // Our credentials, not the ASP. Recorded so the poll loop does not read a
      // routine re-auth as an outage and evict the user from Ark.
      _lastVtxoFailureWasAuth = true;
      debugPrint("Refresh VTXOs unauthorized (not an outage): $e");
    } catch (e) {
      debugPrint("Refresh VTXOs failed: $e");
    }
    notifyListeners();
    unawaited(_delegateIfNeeded());
    return ok;
  }

  /// A re-delegate is needed when either:
  /// - A new VTXO appeared since the last refresh that wasn't created by us
  ///   (i.e. an external receive), OR
  /// - VTXOs exist but the server reports no active delegate (cosigner
  ///   restart, or first refresh after login).
  ///
  /// Self-originated change (txid matches a recent send/board/settle) is
  /// skipped since the corresponding handler already invalidated the delegate
  /// on the server side and a fresh re-delegate covers the new change VTXO.
  ///
  /// Signing the delegate needs the passkey. Only sign SILENTLY when no
  /// biometric prompt would appear (wallet un-gated, or the PRF seed is still
  /// cached from a just-finished user op). Otherwise raise [needsDelegateAction]
  /// so the Ark tab shows a delegate button — the cosigner's "Funds received"
  /// notification brings the user there.
  ///
  /// **This got much more expensive.** It used to be `settleDelegate(storeOnly:
  /// true)` — one call that had the cosigner seal an intent for its own later
  /// use. The cosigner cannot settle for itself any more (a guest has no
  /// egress), so the only way to renew is to drive a real ASP batch round from
  /// here: register an intent, wait for the ASP's next round, sign the tree,
  /// submit forfeits. That waits on the ASP's schedule, which is minutes, and
  /// it dies if the app is backgrounded part-way through.
  ///
  /// Firing that automatically on every receive is kept for now because it is
  /// what keeps a delegate armed and the watch running, and because the
  /// `promptless` guard below already stops it interrupting the user. Whether
  /// an unattended multi-minute round should start without being asked for is a
  /// product call, and [needsDelegateAction] is the mechanism if the answer is
  /// no — flip the condition to always raise it.
  Future<void> _delegateIfNeeded() async {
    if (_client == null || _delegateInFlight || _vtxos.isEmpty) return;

    final current = _vtxos.map((v) => '${v.txid}:${v.vout}').toSet();
    final newOutpoints = current.difference(_previousVtxoOutpoints);
    _previousVtxoOutpoints
      ..clear()
      ..addAll(current);

    // Every new outpoint counts as external now. This used to subtract our own sends, using the
    // cosigner's Ark history — a log it can no longer keep, since it is called rather than running
    // and never saw the receives. The cost is a delegate refreshed after our own change lands as
    // well as after a real receive, which is conservative rather than wrong.
    final needsDelegate = newOutpoints.isNotEmpty || !_delegateCoversCurrentVtxos;
    if (!needsDelegate) {
      if (_delegateActionNeeded) {
        _delegateActionNeeded = false;
        notifyListeners();
      }
      return;
    }

    final promptless =
        !(_client!.isShareGated) || (_passkey?.hasFreshSeed ?? false);
    if (!promptless) {
      if (!_delegateActionNeeded) {
        _delegateActionNeeded = true;
        notifyListeners();
      }
      return;
    }

    final retryAfter = _delegateRetryAfter;
    if (retryAfter != null && DateTime.now().isBefore(retryAfter)) return;

    _delegateInFlight = true;
    try {
      await _client!.settleDelegate();
      _markDelegated();
      _delegateActionNeeded = false;
      _delegateRetryAfter = null;
      await refreshVtxos();
      notifyListeners();
    } catch (e) {
      _delegateRetryAfter = DateTime.now().add(_delegateFailureCooldown);
      debugPrint("[auto-settle] re-delegate failed (cooldown "
          "${_delegateFailureCooldown.inMinutes}m): $e");
    } finally {
      _delegateInFlight = false;
    }
  }

  /// User-triggered delegate (the Ark-tab button). Runs `settleDelegate`
  /// directly — with a gated share this pops the passkey prompt, which is
  /// expected here because the user just asked for it. Throws on failure so
  /// the UI can surface it.
  Future<void> delegateNow() async {
    final client = _client;
    if (client == null) throw StateError('wallet not initialized');
    // Throw rather than silently return: the button's success feedback must
    // never fire for an attempt that didn't run.
    if (_delegateInFlight) throw StateError('a delegate is already in progress');
    _delegateInFlight = true;
    try {
      await client.settleDelegate();
      _markDelegated();
      _delegateActionNeeded = false;
      _delegateRetryAfter = null;
      await refreshVtxos();
      notifyListeners();
    } finally {
      _delegateInFlight = false;
    }
  }

  /// Periodic Ark health + VTXO poll. Runs continuously (idempotent; skips a
  /// tick if one is in flight) and drives the offline-mode state machine:
  ///  - forced offline    → do nothing (stay on-chain only);
  ///  - Ark up            → refresh VTXOs; if the ASP call fails, probe
  ///                        getArkInfo() and, if that also fails, flip to
  ///                        offline mode (auto-fallback);
  ///  - Ark down (auto)   → probe getArkInfo() and, on success, re-run initArk()
  ///                        to restore Ark + polling (auto-recover).
  void _startVtxoPolling() {
    _vtxoPollTimer?.cancel();
    _vtxoPollTimer = Timer.periodic(_vtxoPollInterval, (_) async {
      if (_client == null || _vtxoPollInFlight || _offlineModeForced) return;
      _vtxoPollInFlight = true;
      try {
        if (_arkAvailable) {
          final ok = await refreshVtxos();
          // An auth failure is not an outage. _probeArk() is itself an
          // authenticated call, so it fails for the same reason and used to
          // "confirm" a phantom outage — dropping the user out of Ark on a
          // routine token expiry or a dismissed biometric prompt.
          if (!ok && !_lastVtxoFailureWasAuth && !await _probeArk()) {
            // ASP went down — enter offline mode.
            _arkAvailable = false;
            debugPrint('Ark ASP unreachable — entering offline mode');
            notifyListeners();
          }
        } else if (await _probeArk()) {
          // ASP came back — restore Ark (re-fetches addresses, refreshes, notifies).
          debugPrint('Ark ASP reachable again — leaving offline mode');
          await initArk();
        }
      } finally {
        _vtxoPollInFlight = false;
      }
    });
  }

  /// Cheap, definitive ASP reachability probe. Used so a single transient
  /// listVtxos hiccup doesn't flap the offline flag.
  Future<bool> _probeArk() async {
    final c = _client;
    if (c == null) return false;
    try {
      await c.getArkInfo();
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<void> refreshBoardingBalance() async {
    if (_client == null || _wallet == null) return;
    try {
      // The wallet (the only chain-viewer) scans its boarding address directly.
      final boardingAddress = await _client!.getBoardingAddress();
      final utxos = await _wallet!.scanBoarding(boardingAddress);
      _boardingBalance = utxos.fold<int>(0, (s, u) => s + u.amountSats.toInt());
      _boardingUtxoCount = utxos.length;
      // Tracked separately because only confirmed deposits are boardable — the
      // ASP rejects the intent outright if any input is still in the mempool.
      // Without this a fresh deposit reads as "nothing arrived".
      final pending = await _wallet!.scanBoardingPending(boardingAddress);
      _boardingPendingBalance =
          pending.fold<int>(0, (s, u) => s + u.amountSats.toInt());
    } catch (e) {
      debugPrint("Refresh boarding balance failed: $e");
    }
    notifyListeners();
  }

  Future<String> boardFunds() async {
    if (_client == null || _wallet == null) {
      throw StateError("Client not initialized");
    }
    // Scan the boarding deposits on-chain and hand them to the cosigner's settle.
    //
    // ONE PER SETTLE. The cosigner's boarding session builds an intent proof for a
    // single outpoint, so passing several used to board only the first and silently
    // strand the rest — while the UI reported the full scanned total as boarded.
    // Looping keeps "Boarding Complete" honest; the cosigner now rejects a batch
    // of more than one outright rather than truncating.
    final boardingAddress = await _client!.getBoardingAddress();
    final utxos = await _wallet!.scanBoarding(boardingAddress);
    if (utxos.isEmpty) {
      throw StateError('No confirmed boarding deposits to settle.');
    }
    String? txid;
    for (final utxo in utxos) {
      txid = await _client!.settle(boardingUtxos: [utxo]);
    }
    await refreshVtxos();
    await refreshBoardingBalance();
    return txid!;
  }

  Future<String> sendArk(String recipientArkAddress, int amountSats) async {
    final client = _client;
    if (client == null || !arkAvailable) {
      throw StateError('Ark is unavailable — cannot send.');
    }
    // One call, where there were three. `MpcArkWallet` built the transaction here, had it
    // co-signed, then submitted it — a second implementation of the Ark send that derived the
    // VTXO owner key from the share id, which the ASP rejected. The cosigner builds it now and
    // hands back sighashes, so there is one path and it is the cosigner's.
    final arkTxid = await client.sendVtxo(recipientArkAddress, amountSats);
    await refreshVtxos();
    return arkTxid;
  }

  // --- Request-to-pay -------------------------------------------------------
  //
  // A party is identified by its GROUP key — what another wallet allowlists, and what a payer's
  // cosigner derives our payee address from.

  List<Contact> _contacts = [];
  List<Contact> get contacts => List.unmodifiable(_contacts);

  List<PaymentIntent> _paymentRequests = [];
  List<PaymentIntent> get paymentRequests => List.unmodifiable(_paymentRequests);

  /// Requests still awaiting a decision — what the inbox badge counts.
  List<PaymentIntent> get pendingPaymentRequests =>
      _paymentRequests.where((i) => i.status == 'pending').toList();

  /// This wallet's shareable identity: give it to someone so they can allowlist you.
  String? get myGroupKey => _client?.groupKeyHex;

  Future<void> refreshContacts() async {
    if (_client == null) return;
    _contacts = await _client!.contactList();
    notifyListeners();
  }

  Future<void> refreshPaymentRequests() async {
    if (_client == null) return;
    _paymentRequests = await _client!.paymentRequests();
    notifyListeners();
  }

  /// Authorize someone to bill this wallet.
  Future<void> addContact(String contactGroupKeyHex, String label) async {
    if (_client == null) throw StateError('Client not initialized');
    await _client!.contactAdd(contactGroupKeyHex.trim(), label.trim());
    await refreshContacts();
  }

  /// Revoke a contact; the cosigner drops their pending requests too.
  Future<void> removeContact(String contactGroupKeyHex) async {
    if (_client == null) throw StateError('Client not initialized');
    await _client!.contactRemove(contactGroupKeyHex);
    await refreshContacts();
    await refreshPaymentRequests();
  }

  /// Ask [payerGroupKeyHex] to pay us. **Not reachable from the app today.**
  ///
  /// The request is signed by us and addressed to the PAYER's cosigner — their
  /// contact allowlist is what authorizes it, which is why the payee address is
  /// derived there from our allowlisted key rather than supplied by us. That
  /// needs a connection to their cosigner, and there is no way to open one:
  /// enclave-runtime resolves the tenant from the caller's own interaction
  /// token and strips any tenant header a client sends, so every connection we
  /// can open lands in our own instance. Calling it against our own cosigner
  /// would create a request for *us* to pay, which is backwards.
  ///
  /// The inbox half is unaffected — [paymentRequests], [approvePaymentRequest]
  /// and [declinePaymentRequest] all read our own cosigner and work.
  ///
  /// What would close this: carry the signed request out of band (a QR code or
  /// a link) and have the payer's app submit it to the payer's own cosigner.
  /// The RPC already takes the requester's `user_id`, `signature` and
  /// `timestamp_ms`, so nothing on the cosigner needs to change — only how the
  /// request travels, which is a product decision rather than a port.
  Future<PaymentIntent> requestPayment(
    String payerGroupKeyHex,
    int amountSats, {
    String memo = '',
  }) async {
    throw UnsupportedError(
      'Requesting a payment needs a connection to the payer\'s cosigner, and '
      'the runtime routes every connection to our own. Share the request out '
      'of band instead — see MpcService.requestPayment.',
    );
  }

  /// Pay a request. Amount and payee come from the STORED intent, never the UI — that is what
  /// lets the cosigner match the settled send back to the request.
  Future<String> approvePaymentRequest(PaymentIntent intent) async {
    if (intent.status != 'pending') {
      throw StateError('Request is ${intent.status}, not pending');
    }
    final txid = await sendArk(intent.toArkAddress, intent.amountSats.toInt());
    await refreshPaymentRequests();
    return txid;
  }

  Future<void> declinePaymentRequest(String id) async {
    if (_client == null) throw StateError('Client not initialized');
    await _client!.declinePaymentRequest(id);
    await refreshPaymentRequests();
  }

  Future<String> settleDelegate() async {
    if (_client == null) throw StateError("Client not initialized");
    final txid = await _client!.settleDelegate();
    await refreshVtxos();
    return txid;
  }

  String _generateSessionId() {
    final r = Random.secure();
    return List.generate(
        16, (index) => r.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
  }
}
