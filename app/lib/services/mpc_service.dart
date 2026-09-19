import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:convert/convert.dart' show hex;
import 'package:fixnum/fixnum.dart';
import 'package:hive/hive.dart';
import 'package:protobuf/protobuf.dart' show GeneratedMessageGenericExtensions;
import 'package:path_provider/path_provider.dart';
// `ArkInfo` also exists as a proto message; the ASP's value type is the one meant here.
import 'package:protocol/protocol.dart' hide ArkInfo;

import 'package:app_core/asp/asp_client.dart';
import 'package:app_core/asp/exit_chain.dart';
import 'package:app_core/asp/history.dart';
import 'package:app_core/boarding.dart';
import 'package:app_core/client.dart';
import 'package:app_core/sessions/exit_plan.dart' show ExitTx;
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

  /// Deposits only: this wallet holds no on-chain coins and spends none. See `app_core/boarding`.
  BoardingScanner? _boarding;


  ArkInfo? _arkInfo;
  ArkInfo? get arkInfo => _arkInfo;
  String? _arkAddress;
  String? get arkAddress => _arkAddress;
  String? _boardingAddress;
  String? get boardingAddress => _boardingAddress;
  List<IndexerVtxo> _vtxos = [];
  List<IndexerVtxo> get vtxos => _vtxos;

  /// The Ark tab's transaction list, newest first — rebuilt from the indexer on each
  /// [refreshVtxos], so it includes what others sent us and costs no passkey prompt.
  List<ArkTransaction> _arkHistory = [];
  List<ArkTransaction> get arkHistory => _arkHistory;
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

  void policyUpdated() {
    notifyListeners();
  }

  // Hardcoded for now, could be configurable
  String _host = '10.0.2.2'; // Default, will be overwritten by persistence

  /// Where a remote enclave's measurements are published, for a host with no pins URL of its own
  /// (`server_host.pinsUrl`).
  static const String _manifestRepo = 'BitspendPayment/MerlinWallet';
  static const String _manifestTag = 'eif-latest';

  /// What a remote host's enclave must attest to, from the deployment manifest. Local hosts are a
  /// dev enclave, whose pins come from the build — see `DevEnclaveConfig`.
  EnclavePins? _remotePins;

  /// Fetch a remote enclave's pins from the deployment manifest.
  Future<EnclavePins> fetchManifest() async {
    final host = _host;
    final url = server_host.pinsUrl(host);
    final m = url != null
        ? await manifest.fetchManifestFrom(url)
        : await manifest.fetchManifest(_manifestRepo, tag: _manifestTag);
    final measurement = RegExp(r'^[a-f0-9]{96}$');
    if (!measurement.hasMatch(m.pcr0) || !measurement.hasMatch(m.pcr16)) {
      throw StateError('the deployment manifest does not carry a valid PCR0 and PCR16');
    }
    // A manifest that names its host must name this one, and the relying party it was built with
    // must be the one passkeys are made for — otherwise every approval would be refused, later and
    // less clearly.
    if (m.host.isNotEmpty && m.host != host) {
      throw StateError('the deployment manifest is for ${m.host}, not $host');
    }
    final rpId = server_host.relyingPartyId(host);
    if (m.rpId.isNotEmpty && m.rpId != rpId) {
      throw StateError('the enclave at $host accepts passkeys for ${m.rpId}, not $rpId');
    }
    final trustRoot = m.trustRoot;
    final pins = trustRoot == null
        ? EnclavePins.aws(pcr0: m.pcr0, pcr16: m.pcr16)
        : EnclavePins(trustRoot: trustRoot, pcr0: m.pcr0, pcr16: m.pcr16);
    if (host == _host) _remotePins = pins;
    debugPrint('Fetched manifest: pcr0=${m.pcr0.substring(0, 16)}… pcr16=${m.pcr16.substring(0, 16)}…'
        '${trustRoot == null ? '' : ' (emulated enclave root)'}');
    return pins;
  }

  /// What this host's enclave must attest to. Throws when there is nothing to pin — talking to an
  /// enclave that has not proved what it is would be the one thing all of this exists to prevent.
  Future<EnclavePins> _pins() async {
    if (server_host.isLocalHost(_host)) return server_host.DevEnclaveConfig.fromDefines.pins();
    return _remotePins ?? await fetchManifest();
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
      // network now comes from the ASP (see `_bitcoinNetwork`), so any
      // persisted 'network' key from prior versions is dead weight.
      // No-op if the key isn't present.
      await _identityBox!.delete('network');

      // The hardware-signer option was removed; the wallet is now always the
      // in-process software signer (2-of-2 with the cosigner). Drop any
      // persisted 'signerKind' key from prior versions. No-op if absent.
      await _identityBox!.delete('signerKind');

      // Offline mode was the on-chain half of a wallet that no longer has one.
      await _identityBox!.delete('offlineMode');

      _exitAddress = _identityBox!.get('exitAddress') as String?;

      // Replaced by the watch the client persists with its own state.
      await _identityBox!.delete('delegatedOutpoints');

      _loadLocalLists();

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

  /// The Bitcoin network, from the ASP — never the cosigner.
  ///
  /// It used to be `GetServerInfo`, which is a cosigner call, and every cosigner call is a passkey
  /// approval: asking on every cold start meant a fingerprint before the wallet could even show a
  /// balance. The ASP answers the same question without one, and its answer is the one that matters
  /// anyway — addresses have to match what the ASP validates, and the cosigner refuses to sign for a
  /// network that is not its own. Cached, so a cold start does not ask at all.
  ///
  /// Refuses to proceed without a value: address rendering depends on it, and silently defaulting
  /// was the regression the empty check guards against.
  Future<String> _bitcoinNetwork() async {
    final cached = _identityBox!.get('bitcoinNetwork') as String?;
    if (cached != null && cached.isNotEmpty) return cached;
    Object? lastError;
    for (int attempt = 1; attempt <= 3; attempt++) {
      try {
        final network = (await _client!.getArkInfo()).network;
        if (network.isEmpty) {
          throw StateError('the ASP reported no network; refusing to build a wallet without one');
        }
        await _identityBox!.put('bitcoinNetwork', network);
        return network;
      } catch (e) {
        lastError = e;
        debugPrint("ASP getInfo attempt $attempt/3 failed: $e");
        if (attempt < 3) await Future.delayed(Duration(seconds: attempt));
      }
    }
    throw StateError("ASP unreachable: getInfo failed after 3 attempts. Last error: $lastError. "
        "Check that it is running and reachable from $_host.");
  }

  /// Set the server endpoint. The Bitcoin network comes from that host's ASP when the wallet is
  /// constructed — see [_bitcoinNetwork].
  Future<void> setHost(String host) async {
    if (_host == host && _isInitialized) return;

    debugPrint("MPC Service: Switching host to $host");
    _host = host;

    // Pins and the network belong to a host. Whatever was learned for the last one says nothing
    // about this one.
    _remotePins = null;
    await _identityBox?.delete('bitcoinNetwork');
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
      // A remote enclave's pins change under a running app — a redeploy's PCR16, an emulated
      // enclave's per-boot root — and the gate asks for the current ones when a document fails.
      refreshPins: server_host.isLocalHost(_host) ? null : fetchManifest,
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
    // Before the DKG, so the ceremony carries the push token and no enrolment call follows it.
    client.onDeviceEnrolled = (token) {
      _identityBox?.put('pushToken', token);
      debugPrint('[push] enrolled for wakes');
    };
    client.offerDeviceToken(_unenrolledToken);
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
    // The DKG that follows is its first use, and waits for it to become findable — see
    // `PlatformPasskey.assertion`. No sign-in of its own here, so setup is one fingerprint.
    _passkey!.adopt(enrolment.credentialId);
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

    _client = await _createMpcClient(storageId: _storageId ?? 'mpc_wallet_state_default');
    // Nothing to restore on a wallet that has never run a ceremony, so this is the ceremony.
    if (!await _client!.restoreState()) await _client!.doDkg();

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

    _client = await _createMpcClient(storageId: _storageId ?? 'mpc_wallet_state_default');
    if (!await _client!.restoreState()) {
      throw StateError('this wallet has no key on this device to restore');
    }
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
    _boarding?.close();
    _boarding = null;

    try {
      await restoreSession();
    } catch (e) {
      debugPrint("Reconnect failed: $e");
      _isConnected = false;
      notifyListeners();
    }
  }

  // --- Ark methods ---

  Future<void> initArk() async {
    if (_client == null) return;
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

  /// A refresh round in progress — [delegateNow] refuses a second.
  bool _delegateInFlight = false;

  /// Periodic VTXO poll. Off-chain receives don't trigger the on-chain electrs
  /// sync, so without this, received VTXOs only show up on a manual refresh.
  /// Runs while Ark is active; the OS pauses it when the app is backgrounded.
  Timer? _vtxoPollTimer;
  bool _vtxoPollInFlight = false;
  static const Duration _vtxoPollInterval = Duration(seconds: 10);

  /// What the wallet holds now.
  Iterable<IndexerVtxo> get _held => _vtxos.where((v) => !v.isSpent);

  /// Whether a sealed delegate covers everything held — so the cosigner will refresh it on its own,
  /// from the enclave, before it expires.
  ///
  /// Answered locally, from the indexer and the delegate the last send, settle or [protectFunds]
  /// sealed — no call to the cosigner, so no passkey prompt. It stops being true when funds arrive
  /// that no delegate covers: a receive, or the VTXO the cosigner produced when it ran one.
  bool get fundsProtected {
    final delegate = _client?.delegateStatus;
    final held = _held.toList();
    return held.isNotEmpty && delegate != null && held.every(delegate.covers);
  }

  /// How long after a delegate's moment the cosigner is given before the owner is asked to step in.
  ///
  /// A batch round waits on the ASP's own schedule and can be retried, so the renewal is not late
  /// the instant it is due. Asking sooner would mean asking every time the machinery is simply
  /// working — the button would be on screen exactly when the cosigner was about to act.
  static const Duration _renewalGrace = Duration(minutes: 10);

  /// The last moment a renewal can wait: past this, ask rather than hope.
  static const Duration _expiryFloor = Duration(minutes: 30);

  /// Whether the cosigner's own renewal has failed to happen, so the owner has to do it.
  ///
  /// Not "the renewal is due" — that moment is when the *cosigner* acts, and it needs no help.
  /// This is later: either the delegate's moment passed and the funds it covered are still sitting
  /// here, or something is close enough to expiry that waiting is no longer safe whatever the
  /// reason.
  bool get refreshDue {
    final now = DateTime.now();
    final expiring = _held.any((v) =>
        v.expiresAt > 0 &&
        DateTime.fromMillisecondsSinceEpoch(v.expiresAt * 1000)
            .isBefore(now.add(_expiryFloor)));
    if (expiring) return true;

    final delegate = _client?.delegateStatus;
    if (delegate == null) return false; // Nothing was scheduled; that is what `fundsProtected` says.
    final late = now.isAfter(delegate.validAt.add(_renewalGrace));
    return late && _held.any(delegate.covers);
  }

  // --- The way out ------------------------------------------------------------------------------
  //
  // Every seal signs one unilateral exit per VTXO, paying an address this wallet does not control.
  // They are what the money is if the cosigner is never heard from again, so what matters here is
  // which funds have one and which do not.

  String? _exitAddress;

  /// Where unilateral exits pay. Null until the user has given one.
  String? get exitAddress => _exitAddress;

  bool get hasExitAddress => (_exitAddress ?? '').isNotEmpty;

  /// The exits this wallet holds, from the last seal.
  List<ExitTx> get exits => _client?.exits ?? const [];

  /// Held VTXOs with no exit signed for them.
  ///
  /// Anything received since the last seal, and — the one that matters — everything the cosigner
  /// made by running a delegate while nobody was here: a renewal spends the VTXOs the old exits
  /// named and makes a new one, which cannot be pre-signed until it exists. Sealing again covers
  /// it, which is what [protectFunds] does.
  List<IndexerVtxo> get vtxosWithoutExit {
    final covered = {for (final e in exits) e.outpoint};
    return _held.where((v) => !covered.contains('${v.txid}:${v.vout}')).toList();
  }

  /// Every transaction that has to reach the chain before [exit] can: the commitment, the batch
  /// tree below it, and — for money that moved since — the checkpoint and Ark transactions, ending
  /// with the exit itself.
  ///
  /// Read from the ASP's indexer, which has them all and signs nothing new, so this costs no
  /// approval. Cached per exit while the screen is open; a path does not change unless the exit
  /// does.
  Future<ExitChain> exitChain(ExitTx exit) async {
    final client = _client;
    if (client == null) throw StateError('wallet not initialized');
    return _chains[exit.outpoint] ??= await client.exitChain(exit);
  }

  final Map<String, ExitChain> _chains = {};

  /// Set the address unilateral exits pay to. Checked against the ASP's network, so a mistake is
  /// caught now rather than on the day it is the only thing that matters.
  Future<void> setExitAddress(String address) async {
    final client = _client;
    if (client == null) throw StateError('wallet not initialized');
    await client.setExitAddress(address);
    _exitAddress = address.trim();
    await _identityBox?.put('exitAddress', _exitAddress);
    notifyListeners();
  }

  /// Whether the Ark tab should ask the user for something: to protect funds no delegate covers
  /// ([protectFunds]), or to refresh funds that are due and were not ([delegateNow]). Never acted on
  /// without them — each is a passkey approval, and an approval is a person.
  bool get needsDelegateAction => _held.isNotEmpty && (refreshDue || !fundsProtected);

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
      // [fundsProtected].
      //
      // Spent ones too, in the same call: they are what the history is rebuilt from.
      _chains.removeWhere((outpoint, _) => !exits.any((e) => e.outpoint == outpoint));
      final all = await _client!.listVtxos(includeSpent: true);
      _arkHistory = arkHistoryOf(all);
      _vtxos = all.where((v) => !v.isSpent).toList();
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
    return ok;
  }

  /// This device's push token, as FCM last reported it.
  String? _pushToken;

  /// [_pushToken], unless the cosigner already has it.
  String? get _unenrolledToken {
    final token = _pushToken;
    if (token == null || _identityBox?.get('pushToken') == token) return null;
    return token;
  }

  /// Have the cosigner enrol [token] for wakes — on the DKG, or on the next delegate seal (a send, a
  /// settle, or "Renew automatically"), never as a call of its own. Every call is a passkey approval,
  /// and a separate enrolment was a fingerprint the user never asked for. Nothing is missed by
  /// waiting: a wake is only ever about a sealed delegate, and the seal is what carries the token.
  void offerDeviceToken(String token) {
    _pushToken = token;
    _client?.offerDeviceToken(_unenrolledToken);
  }

  /// Seal a delegate over what is held, so the cosigner refreshes it on its own before it expires.
  /// One passkey approval.
  ///
  /// For funds no delegate covers — a receive, or what the cosigner produced by running one. A send
  /// or a settle seals on its way out with no approval of its own, so this is only needed when
  /// [fundsProtected] is false and nothing is being sent.
  Future<void> protectFunds() async {
    final client = _client;
    if (client == null) throw StateError('wallet not initialized');
    await client.protectFunds();
    notifyListeners();
  }

  /// Refresh everything held in a batch round now — for funds past due that the cosigner could not
  /// refresh itself. One passkey approval, and it seals a new delegate on its way out. Throws on
  /// failure so the UI can surface it.
  /// Returns whether the renewal was re-armed on the way out. A refresh seals a new delegate on
  /// the same stream and the same approval, so this is normally true; it is false when the indexer
  /// had not caught up in time, and then the owner has to seal again — which is worth saying
  /// rather than reporting success.
  Future<bool> delegateNow() async {
    final client = _client;
    if (client == null) throw StateError('wallet not initialized');
    // Throw rather than silently return: the button's success feedback must
    // never fire for an attempt that didn't run.
    if (_delegateInFlight) throw StateError('a delegate is already in progress');
    _delegateInFlight = true;
    try {
      await client.settleDelegate();
      await refreshVtxos();
      notifyListeners();
      return fundsProtected;
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
      if (_client == null || _vtxoPollInFlight) return;
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

  /// The chain-viewer, built on the network the ASP reports. Deposits are the only thing this
  /// wallet reads the chain for.
  Future<BoardingScanner> _boardingScanner() async =>
      _boarding ??= BoardingScanner(networkName: await _bitcoinNetwork());

  Future<void> refreshBoardingBalance() async {
    if (_client == null) return;
    try {
      final scanner = await _boardingScanner();
      final boardingAddress = await _client!.getBoardingAddress();
      final utxos = await scanner.scan(boardingAddress);
      _boardingBalance = utxos.fold<int>(0, (s, u) => s + u.amountSats.toInt());
      _boardingUtxoCount = utxos.length;
      // Tracked separately because only confirmed deposits are boardable — the
      // ASP rejects the intent outright if any input is still in the mempool.
      // Without this a fresh deposit reads as "nothing arrived".
      final pending = await scanner.scanPending(boardingAddress);
      _boardingPendingBalance =
          pending.fold<int>(0, (s, u) => s + u.amountSats.toInt());
    } catch (e) {
      debugPrint("Refresh boarding balance failed: $e");
    }
    notifyListeners();
  }

  Future<String> boardFunds() async {
    if (_client == null) throw StateError("Client not initialized");
    // Scan the boarding deposits on-chain and hand them to the cosigner's settle.
    //
    // ONE PER SETTLE. The cosigner's boarding session builds an intent proof for a
    // single outpoint, so passing several used to board only the first and silently
    // strand the rest — while the UI reported the full scanned total as boarded.
    // Looping keeps "Boarding Complete" honest; the cosigner now rejects a batch
    // of more than one outright rather than truncating.
    final boardingAddress = await _client!.getBoardingAddress();
    final utxos = await (await _boardingScanner()).scan(boardingAddress);
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

  //
  // Both lists are kept here, and persisted, as what the app shows — not fetched to show them.
  // Reading either from the cosigner is a call, and every call is a passkey approval, so opening a
  // screen used to cost a fingerprint or two. Nothing else writes them: contacts are added and
  // removed from this app, and a request reaches the cosigner only when this app delivers it. So
  // each change this app makes is applied to the local copy as the cosigner confirms it, and a
  // pull-to-refresh is the only read.

  List<Contact> _contacts = [];
  List<Contact> get contacts => List.unmodifiable(_contacts);

  List<PaymentIntent> _paymentRequests = [];
  List<PaymentIntent> get paymentRequests => List.unmodifiable(_paymentRequests);

  void _loadLocalLists() {
    List<T> read<T>(String key, T Function(List<int>) decode) {
      final stored = _identityBox?.get(key);
      if (stored is! List) return [];
      return [for (final b64 in stored.cast<String>()) decode(base64.decode(b64))];
    }

    _contacts = read('contacts', Contact.fromBuffer);
    _paymentRequests = read('paymentRequests', PaymentIntent.fromBuffer);
  }

  Future<void> _saveLocalLists() async {
    await _identityBox?.put('contacts', [for (final c in _contacts) base64.encode(c.writeToBuffer())]);
    await _identityBox
        ?.put('paymentRequests', [for (final i in _paymentRequests) base64.encode(i.writeToBuffer())]);
  }

  /// Requests still awaiting a decision — what the inbox badge counts.
  List<PaymentIntent> get pendingPaymentRequests =>
      _paymentRequests.where((i) => i.status == 'pending').toList();

  /// This wallet's shareable identity: give it to someone so they can allowlist you.
  String? get myGroupKey => _client?.groupKeyHex;

  /// Re-read contacts from the cosigner. A passkey approval — pull-to-refresh only.
  Future<void> refreshContacts() async {
    if (_client == null) return;
    _contacts = await _client!.contactList();
    await _saveLocalLists();
    notifyListeners();
  }

  /// Re-read the inbox from the cosigner. A passkey approval — pull-to-refresh only.
  Future<void> refreshPaymentRequests() async {
    if (_client == null) return;
    _paymentRequests = await _client!.paymentRequests();
    await _saveLocalLists();
    notifyListeners();
  }

  /// Authorize someone to bill this wallet.
  Future<void> addContact(String contactGroupKeyHex, String label) async {
    if (_client == null) throw StateError('Client not initialized');
    final key = contactGroupKeyHex.trim();
    await _client!.contactAdd(key, label.trim());
    _contacts = [
      for (final c in _contacts)
        if (hex.encode(c.verifyingKey) != key) c,
      Contact(
        verifyingKey: hex.decode(key),
        label: label.trim(),
        addedAt: Int64(DateTime.now().millisecondsSinceEpoch ~/ 1000),
      ),
    ];
    await _saveLocalLists();
    notifyListeners();
  }

  /// Revoke a contact; the cosigner drops their pending requests too.
  Future<void> removeContact(String contactGroupKeyHex) async {
    if (_client == null) throw StateError('Client not initialized');
    await _client!.contactRemove(contactGroupKeyHex);
    _contacts = [
      for (final c in _contacts)
        if (hex.encode(c.verifyingKey) != contactGroupKeyHex) c,
    ];
    // What the cosigner did with them, mirrored: a revoked contact's pending requests go with it.
    _paymentRequests = [
      for (final i in _paymentRequests)
        if (!(i.status == 'pending' && hex.encode(i.fromVerifyingKey) == contactGroupKeyHex)) i,
    ];
    await _saveLocalLists();
    notifyListeners();
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
    // The cosigner marks it fulfilled as it records the send; mirrored rather than re-read.
    _setRequest(intent.id, (i) => i
      ..status = 'fulfilled'
      ..arkTxid = txid);
    await _saveLocalLists();
    notifyListeners();
    return txid;
  }

  Future<void> declinePaymentRequest(String id) async {
    if (_client == null) throw StateError('Client not initialized');
    await _client!.declinePaymentRequest(id);
    _setRequest(id, (i) => i..status = 'declined');
    await _saveLocalLists();
    notifyListeners();
  }

  void _setRequest(String id, PaymentIntent Function(PaymentIntent) change) {
    _paymentRequests = [
      for (final i in _paymentRequests) i.id == id ? change(i.deepCopy()) : i,
    ];
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
