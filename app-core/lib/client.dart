import 'dart:async';
import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:app_core/policy.dart';
import 'package:app_core/ark/ark.dart' as ark_addr;
import 'package:app_core/ark/exit.dart' as ark_exit;
import 'package:app_core/asp/asp_client.dart';
import 'package:app_core/asp/exit_chain.dart';
import 'package:app_core/asp/history.dart';
import 'enclave/gate.dart';
import 'package:app_core/cosigner/connection.dart';
import 'package:app_core/sessions/dkg_session.dart';
import 'package:app_core/sessions/send_session.dart';
import 'package:app_core/sessions/settle_session.dart';
import 'package:app_core/sessions/sign_session.dart';
import 'package:app_core/sessions/delegate.dart';
import 'package:app_core/sessions/exit_plan.dart' show ExitTx;
import 'package:app_core/requests/authorship.dart';
import 'package:app_core/threshold/frost/ceremony.dart' show schnorr64;
import 'package:app_core/passkey/seed_source.dart';
import 'package:app_core/pin_blinding.dart';
import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:app_core/threshold/core/dkg.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;
// `ArkInfo` is hidden: the proto one is the wire shape, and `asp/ark_info.dart` has the value type
// the wallet actually passes around. `SendSession.arkInfoToProto` converts at the boundary.
import 'package:protocol/protocol.dart' hide ArkInfo;
import 'package:fixnum/fixnum.dart';
import 'package:protobuf/protobuf.dart' show GeneratedMessageGenericExtensions;
import 'package:hive/hive.dart';
import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:convert/convert.dart';

import 'package:app_core/persistence/wallet_store.dart';

class MpcClient {
  /// The cosigner: four ceremony streams and seven single-round calls.
  final CosignerConnection _conn;

  /// Nonces for payment requests. A repeated nonce is refused by the payer as a replay.
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
    final pkp = _normalPolicy?.publicKeyPackage;
    if (pkp == null) return null;
    final compressed = threshold.elemSerializeCompressed(pkp.verifyingKey.E);
    final compressedHex = hex.encode(compressed);
    // Strip 02/03 prefix to get x-only
    return compressedHex.length == 66 ? compressedHex.substring(2) : compressedHex;
  }

  /// The FROST group verifying key, COMPRESSED (66 hex) — the wallet's public IDENTITY. Neither
  /// [userId] (a share key) nor [groupXOnlyPubKey] (same key, parity stripped, for taproot).
  String? get groupKeyHex {
    final pkp = _normalPolicy?.publicKeyPackage;
    if (pkp == null) return null;
    return hex.encode(threshold.elemSerializeCompressed(pkp.verifyingKey.E));
  }

  List<int>? get groupKeyBytes {
    final h = groupKeyHex;
    return h == null ? null : hex.decode(h);
  }

  final int _maxSigners;
  final int _minSigners;

  /// PIN/passkey-PRF share gating. When a [SeedSource] is configured the wallet's FROST share is
  /// stored BLINDED (δ = share − b(seed)) inside `_normalPolicy.keyPackage.secretShare`; the raw
  /// share is never persisted and is reconstructed transiently only for an ARK sign / contract
  /// op (see [_walletKeyPackage]). Nothing else needs the share: requests are approved by the enclave's
  /// passkey gate, not by anything the share signs.
  SeedSource? _seedSource;

  /// Whether the stored share is blinded (a persistent property set at DKG time; loaded from state).
  /// Kept separate from [_seedSource] so persist/load/sign agree even before a seed source is wired.
  bool _shareBlinded = false;

  /// Whether the persisted share is blinded — i.e. a passkey/PIN was provisioned
  /// and a seed source must be wired before any ARK sign. Used on cold-start
  /// restore to decide whether to re-attach the passkey seed/token sources.
  bool get isShareGated => _shareBlinded;

  /// Wire the blinding seed source (passkey PRF in production; a fixed seed in tests). Set before
  /// DKG to create a gated wallet, and before signing to unlock ARK ops. Never wired ⇒ legacy
  /// un-gated behavior.
  void setSeedSource(SeedSource source) => _seedSource = source;

  /// The wallet's DKG dealer secret — the polynomial constant term that
  /// generated this wallet's share. It is a SINGLE secp256k1 key the wallet
  /// controls alone (its public point is the DKG `walletVk`), distinct from the
  /// threshold share. It is the wallet's on-chain ("utxo") signing key: on-chain
  /// receive/spend/broadcast happen wallet-alone with NO cosigner. The FROST
  /// group key stays the Ark owner key (boarding + VTXO).
  threshold.SecretKey? _onchainSecret;

  /// 32-byte on-chain secret, or null before DKG/restore.
  Uint8List? get onchainSecretBytes => _onchainSecret == null
      ? null
      : Uint8List.fromList(threshold.bigIntToBytes(_onchainSecret!.scalar));

  SpendingPolicy? _normalPolicy;

  /// A wallet whose cosigner runs inside an enclave, reached through [gate].
  ///
  /// The gate attests the enclave on every approval and the channel only talks to a socket serving
  /// the certificate it attested — see `CosignerConnection.enclave`.
  ///
  /// The ASP is a separate party and takes none of that: it is arkd, reached directly.
  ///
  /// [storageId] names the Hive box the wallet's half of the key lives in; [encryptionCipher]
  /// encrypts it (`HiveAesCipher`), and without one it is stored in the clear.
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
  MpcClient.withConnection(
    CosignerConnection connection, {
    required String aspHost,
    required int aspPort,
    bool aspSecure = false,
    int maxSigners = 2,
    int minSigners = 2,
    String? storageId,
    HiveCipher? encryptionCipher,
  })  : _conn = connection,
        _asp = AspClient.connect(aspHost, aspPort, secure: aspSecure),
        _maxSigners = maxSigners,
        _minSigners = minSigners {
    _store = WalletStore(
      boxName: storageId ?? 'mpc_wallet_state_default',
      cipher: encryptionCipher,
    );
  }

  /// The ASP, for a caller that needs to ask it something directly — chiefly polling for receives.
  AspClient get asp => _asp;

  /// The cosigner connection.
  ///
  /// Exposed because a payment request is addressed to *somebody else's* cosigner, so a caller has
  /// to be able to name one — see [writePaymentRequest]. Also what a test harness drives a raw
  /// stream with.
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
  bool get isInitialized => _normalPolicy != null;

  /// Restores client state from persistence.
  /// [debugState] can be provided to inject state for testing (bypassing store).
  /// Returns true if state was found and restored.
  Future<bool> restoreState({Map<String, dynamic>? debugState}) async {
    // Ensure persistence is initialized (via initPersistence or just ensure path)
    // WalletStore relies on Hive.init being called previously.
    // If not called, assume default? We rely on user calling initPersistence.
    await _store.init();

    Map<String, dynamic>? state;
    if (debugState != null) {
      state = debugState;
    } else {
      state = await _store.getClientState();
    }

    if (state == null) return false;

    final storedUserId = state['userId'];
    if (storedUserId is! String || storedUserId.isEmpty) {
      return false;
    }
    _userId = hex.decode(storedUserId);

    // `signingSecret` may still be in an older state, and is ignored. It was a second plaintext copy
    // of the wallet's share, kept only to sign request authentication the cosigner no longer reads.
    // Gated wallet: `_normalPolicy.keyPackage.secretShare` holds δ; reconstruct at sign time.
    _shareBlinded = state['shareBlinded'] == true;

    // Restore the single-key on-chain secret (the DKG dealer secret).
    if (state['onchainSecret'] != null) {
      final secretBytes =
          Uint8List.fromList(hex.decode(state['onchainSecret'] as String));
      _onchainSecret =
          threshold.SecretKey(threshold.bytesToBigInt(secretBytes));
    }

    if (state['spendingPolicies'] != null) {
      _normalPolicy = SpendingPolicy.fromJson(
          Map<String, dynamic>.from(state['spendingPolicies']));
    }

    final delegate = state['delegate'];
    _delegate =
        delegate is Map ? DelegateStatus.fromJson(Map<String, dynamic>.from(delegate)) : null;
    final exitScript = state['exitScriptPubkey'];
    _exitScriptPubkeyHex = exitScript is String && exitScript.isNotEmpty ? exitScript : null;

    return true;
  }

  Future<void> _saveState() async {
    final state = <String, dynamic>{
      'userId': hex.encode(_userId!),
    };
    if (_onchainSecret != null) {
      state['onchainSecret'] =
          hex.encode(threshold.bigIntToBytes(_onchainSecret!.scalar));
    }
    if (_normalPolicy != null) {
      // When gating is on, `_normalPolicy.keyPackage.secretShare` already holds δ (the raw share is
      // never persisted); `shareBlinded` tells restore to reconstruct at sign time, not load time.
      state['spendingPolicies'] = _normalPolicy!.toJson();
    }
    state['shareBlinded'] = _shareBlinded;
    if (_delegate != null) state['delegate'] = _delegate!.toJson();
    if (_exitScriptPubkeyHex != null) state['exitScriptPubkey'] = _exitScriptPubkeyHex;
    await _store.saveClientState(state);
  }

  // Getters for testing
  threshold.KeyPackage? get keyPackage1 => _normalPolicy?.keyPackage;
  threshold.PublicKeyPackage? get publicKey => _normalPolicy?.publicKeyPackage;

  // --- SERVER METADATA ---

  /// Fetch the server's deployment metadata (Bitcoin network).
  /// Unauthenticated; safe to call before DKG completes.
  Future<GetServerInfoResponse> getServerInfo() => _conn.getServerInfo();

  // --- DKG ---

  /// Run the DKG ceremony and keep the resulting share.
  ///
  /// 2-of-2 {wallet, cosigner}: both deal, both hold a share, both are needed to sign.
  Future<void> doDkg() async {
    await _store.init();
    final result = await DkgSession(_conn).run(
      maxSigners: _maxSigners,
      minSigners: _minSigners,
      deviceToken: _deviceToken ?? '',
    );
    // The wallet's dealer secret doubles as its single-key on-chain key.
    _onchainSecret = result.onchainSecret;
    await _finalizeWalletShare(result.dkg.keyPackage, result.dkg.publicKeyPackage);
    await _saveState();
    _deviceTokenCarried(result.deviceEnrolled);
  }

  // --- The way out ---
  //
  // Where this wallet's money goes if the cosigner is never heard from again. Every seal signs one
  // exit per VTXO to it, and the wallet keeps them — see `sessions/exit_plan.dart`. Without an
  // address there is nothing to pre-sign to, which is why the app asks for one before it opens.

  String? _exitScriptPubkeyHex;

  /// The scriptPubKey exits pay, hex. Empty until an address is set.
  String get exitScriptPubkeyHex => _exitScriptPubkeyHex ?? '';

  bool get hasExitAddress => (_exitScriptPubkeyHex ?? '').isNotEmpty;

  /// Set the address unilateral exits pay to, checked against the ASP's network.
  ///
  /// Throws if it is not an address, or belongs to another chain — a mistake here is only
  /// discovered on the day nothing else works, so it is caught on the day it is typed. Exits
  /// already signed still pay the old address; the next seal reissues them to this one.
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

  /// The exits this wallet holds, newest issue first: one per VTXO the last seal covered.
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
  // but carried on a call the user already made: the DKG, or the next seal.

  String? _deviceToken;

  /// Called with a token once the cosigner has enrolled it, so the caller can stop offering it.
  void Function(String token)? onDeviceEnrolled;

  /// Carry [token] on the next DKG or delegate seal, until one enrolls it. Null offers nothing — the
  /// token is already enrolled, or there is none.
  void offerDeviceToken(String? token) => _deviceToken = token;

  void _deviceTokenCarried(bool enrolled) {
    final token = _deviceToken;
    if (!enrolled || token == null) return;
    _deviceToken = null;
    onDeviceEnrolled?.call(token);
  }

  PublicKeyPackage? getTweakedPublicKeyPackage(List<int>? merkle_root) {
    final publicKeyPackage = _normalPolicy?.publicKeyPackage;
    return publicKeyPackage?.tweak(merkle_root);
  }

  PublicKeyPackage? getPublicKeyPackage() {
    return _normalPolicy?.publicKeyPackage;
  }


  /// The wallet's key package carrying the REAL share for a single op. Gated: reconstruct
  /// `P_full = δ + b(seed)` from `_seedSource` (throws if no seed is wired — an ARK sign needs the
  /// PIN/passkey). Un-gated: the stored key package already holds the real share. The reconstructed
  /// share lives only for the caller's scope (best-effort wipe = it goes out of scope after use).
  Future<threshold.KeyPackage> _walletKeyPackage() async {
    final kp = _normalPolicy!.keyPackage;
    if (!_shareBlinded) return kp;
    final src = _seedSource;
    if (src == null) {
      throw StateError(
          'signing requires the wallet seed (PIN/passkey) — none configured');
    }
    final seed = await src.deriveSeed();
    final pFull = reconstructShare(
            threshold.bigIntToBytes(kp.secretShare), kp.identifier, seed)
        .scalar;
    return threshold.KeyPackage(kp.identifier, pFull, kp.verifyingShare,
        kp.verifyingKey, kp.minSigners);
  }

  /// The share for an operation that opens [method] — with the call approved first.
  ///
  /// A gated share is unblinded by the passkey's PRF, and so is every call approved: one gesture
  /// yields both, as long as the approval comes first. Unlocking the share first cost a fingerprint
  /// of its own, then the call asked for another. See `CosignerConnection.approveAhead`.
  Future<threshold.KeyPackage> _keyPackageFor(String method) async {
    await _conn.approveAhead(method);
    try {
      return await _walletKeyPackage();
    } catch (_) {
      _conn.discardApproval(method);
      rethrow;
    }
  }

  /// Finalize the wallet's freshly-DKG'd share into `_normalPolicy` + auth state. When a
  /// [SeedSource] is configured, store the share BLINDED (δ) — the raw share is never persisted and
  /// never lingers in memory; it's reconstructed transiently at sign time. Without one the raw share
  /// is kept.
  Future<void> _finalizeWalletShare(threshold.KeyPackage walletKeyPkg,
      threshold.PublicKeyPackage pubKeyPkg) async {
    _userId =
        threshold.elemSerializeCompressed(walletKeyPkg.verifyingShare).toList();
    final src = _seedSource;
    if (src != null) {
      final seed = await src.deriveSeed();
      final delta = threshold.bytesToBigInt(blindShare(
          threshold.SecretKey(walletKeyPkg.secretShare),
          walletKeyPkg.identifier,
          seed));
      final blindedKp = threshold.KeyPackage(walletKeyPkg.identifier, delta,
          walletKeyPkg.verifyingShare, walletKeyPkg.verifyingKey,
          walletKeyPkg.minSigners);
      _normalPolicy = SpendingPolicy(
          id: "normal_policy_id",
          keyPackage: blindedKp,
          publicKeyPackage: pubKeyPkg);
      _shareBlinded = true;
    } else {
      _normalPolicy = SpendingPolicy(
          id: "normal_policy_id",
          keyPackage: walletKeyPkg,
          publicKeyPackage: pubKeyPkg);
    }
  }

  /// Gate an already-DKG'd (raw) share retroactively: blind it to δ under [seed], persist δ, and drop
  /// the raw share. Used when the seed only exists after DKG — a passkey's PRF
  /// needs the post-DKG user id to register/assert. No-op if already gated.
  Future<void> gateShare(Uint8List seed) async {
    if (_shareBlinded) return;
    final kp = _normalPolicy?.keyPackage;
    if (kp == null) throw StateError('no wallet share to gate');
    final delta = threshold.bytesToBigInt(
        blindShare(threshold.SecretKey(kp.secretShare), kp.identifier, seed));
    _normalPolicy = SpendingPolicy(
        id: "normal_policy_id",
        keyPackage: threshold.KeyPackage(kp.identifier, delta, kp.verifyingShare,
            kp.verifyingKey, kp.minSigners),
        publicKeyPackage: _normalPolicy!.publicKeyPackage);
    _shareBlinded = true;
    await _saveState();
    // Hive appends; without compaction the pre-gating state (the raw share, and any `signingSecret`
    // an older version wrote) would remain readable in the box file.
    await _store.compact();
  }

  // --- SIGNING ---

  Future<threshold.Signature> sign(Uint8List message,
      {List<int>? fullTransaction, bool applyTweak = true}) async {
    final keyPackage = await _keyPackageFor('Sign');
    final groupPubKey = _normalPolicy!.publicKeyPackage;

    if (_userId == null) {
      throw StateError("User ID is null, cannot proceed with signing.");
    }

    return signWithContext(
      message,
      keyPackage,
      groupPubKey,
      fullTransaction,
      applyTweak: applyTweak,
    );
  }

  /// Sign [message], with the ceremony carried on one stream.
  ///
  /// The two unary steps this replaces made the cosigner hold a single-use FROST nonce between
  /// them; here it lives on the handler's stack and dies with the stream, so an interrupted
  /// ceremony leaves nothing to reuse.
  Future<threshold.Signature> signWithContext(
    Uint8List message,
    threshold.KeyPackage keyPkg,
    threshold.PublicKeyPackage groupPubKey,
    List<int>? fullTransaction, {
    bool applyTweak = true,
  }) async {
    return SignSession(_conn).sign(
      message: message,
      keyPkg: keyPkg,
      groupPubKey: groupPubKey,
      fullTransaction: fullTransaction,
      applyTweak: applyTweak,
    );
  }
  // --- ARK ---
  //
  // The cosigner answered all of this once, by relaying its own ASP connection and deriving from a
  // key the caller already held. It has no socket now, so the wallet asks the ASP itself and
  // derives its own addresses through the FFI — which is parity-tested against the same ark-core
  // code the cosigner signs with.

  /// This wallet's group key, x-only, as address derivation wants it.
  String get _ownerXOnly {
    final pkp = _normalPolicy?.publicKeyPackage;
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
  Future<String> sendVtxo(String recipientArkAddress, int amountSats) async {
    final info = await _asp.getInfo();
    final vtxos = await listVtxos();
    final result = await SendSession(_conn, _asp).send(
      recipientArkAddress: recipientArkAddress,
      amountSats: amountSats,
      vtxos: vtxos,
      info: info,
      keyPkg: await _keyPackageFor('Send'),
      groupPubKey: _normalPolicy!.publicKeyPackage,
      readHeld: listVtxos,
      deviceToken: _deviceToken ?? '',
      exitScriptPubkeyHex: exitScriptPubkeyHex,
      ownerXOnlyHex: _ownerXOnly,
    );
    _deviceTokenCarried(result.delegate?.deviceEnrolled ?? false);
    // A send spends what the old delegate covered, so the cosigner dropped it: what is sealed now is
    // whatever this send sealed, or nothing.
    await _recordDelegate(result.delegate);
    return result.arkTxid;
  }

  // --- The delegate ----------------------------------------------------------------------------

  DelegateStatus? _delegate;

  /// The delegate last sealed for this wallet — what the cosigner will refresh on its own, and when.
  /// Null until a send, a settle or [protectFunds] sealed one. See `sessions/delegate.dart`.
  DelegateStatus? get delegateStatus => _delegate;

  /// Held VTXOs no sealed delegate covers: arrived since it was sealed (a receive), or produced by
  /// the cosigner running it. Answered from the indexer alone; asks the cosigner nothing.
  Future<List<IndexerVtxo>> unprotectedVtxos() async {
    final held = (await listVtxos()).where((v) => !v.isSpent).toList();
    final delegate = _delegate;
    return delegate == null ? held : held.where((v) => !delegate.covers(v)).toList();
  }

  /// Seal a delegate over everything held now, so the cosigner refreshes it on its own before it
  /// expires.
  ///
  /// [over] replaces the indexer's answer with a set the caller names. Only a test has any business
  /// doing that — it is how an exit can be proven against bitcoind, by sealing over an output that
  /// carries this wallet's VTXO script but that no ASP ever made. One approval — for funds that arrived without an operation of ours; a send or a settle
  /// seals on its way out at no extra cost.
  Future<DelegateStatus> protectFunds({List<IndexerVtxo>? over}) async {
    final info = await _asp.getInfo();
    final held = over ??
        await heldOnceIndexed(listVtxos, timeout: const Duration(seconds: 10));
    if (held == null) {
      throw StateError('the indexer has not reported every VTXO\'s expiry yet — try again shortly');
    }
    if (held.isEmpty) throw StateError('nothing is held, so there is nothing to protect');
    final sealed = await SettleSession(_conn, _asp).seal(
      info: info,
      keyPkg: await _keyPackageFor('Settle'),
      groupPubKey: _normalPolicy!.publicKeyPackage,
      vtxos: held,
      deviceToken: _deviceToken ?? '',
      exitScriptPubkeyHex: exitScriptPubkeyHex,
      ownerXOnlyHex: _ownerXOnly,
    );
    _deviceTokenCarried(sealed.deviceEnrolled);
    await _recordDelegate(sealed);
    return sealed;
  }

  Future<void> _recordDelegate(DelegateStatus? delegate) async {
    _delegate = delegate;
    await _saveState();
  }

  /// Board an on-chain output into Ark, or refresh what is already held.
  ///
  /// One boarding output at a time: a longer list used to be silently truncated to its first
  /// element, boarding one deposit and stranding the rest while the caller was told the whole batch
  /// settled.
  Future<String> settle({
    List<cs.BoardingUtxo> boardingUtxos = const [],
    void Function(SettlePhase)? onProgress,
  }) async {
    if (boardingUtxos.length > 1) {
      throw ArgumentError(
        'settle takes one boarding UTXO at a time, got ${boardingUtxos.length} — '
        'settle them individually',
      );
    }
    final info = await _asp.getInfo();
    final vtxos = boardingUtxos.isEmpty ? await listVtxos() : const <IndexerVtxo>[];
    final result = await SettleSession(_conn, _asp).settle(
      info: info,
      keyPkg: await _keyPackageFor('Settle'),
      groupPubKey: _normalPolicy!.publicKeyPackage,
      boardingUtxo: boardingUtxos.isEmpty ? null : boardingUtxos.first,
      vtxos: vtxos,
      onProgress: onProgress,
      readHeld: listVtxos,
      deviceToken: _deviceToken ?? '',
      exitScriptPubkeyHex: exitScriptPubkeyHex,
      ownerXOnlyHex: _ownerXOnly,
    );
    _deviceTokenCarried(result.delegate?.deviceEnrolled ?? false);
    // A refresh spends the old delegate's inputs; boarding leaves it standing. Either way what this
    // settle sealed, when it sealed, supersedes it.
    if (result.delegate != null || boardingUtxos.isEmpty) await _recordDelegate(result.delegate);
    return result.commitmentTxid;
  }

  /// Refresh the held VTXOs before they expire.
  ///
  /// The same `Settle` stream with no boarding output. There is no `storeOnly` any more: the
  /// cosigner cannot drive a round unattended — a guest has no egress — so what it does instead is
  /// arm a durable watch and wake the device when the deadline arrives, and this is what runs then.
  Future<String> settleDelegate({void Function(SettlePhase)? onProgress}) =>
      settle(onProgress: onProgress);

  Future<void> contactAdd(String contactGroupKeyHex, String label) async {
    await _conn.contactAdd(ContactAddRequest()
      ..contactVerifyingKey = hex.decode(contactGroupKeyHex)
      ..label = label);
  }

  /// Revoke a contact. Their pending requests are dropped too.
  Future<void> contactRemove(String contactGroupKeyHex) async {
    await _conn.contactRemove(ContactRemoveRequest()
      ..contactVerifyingKey = hex.decode(contactGroupKeyHex));
  }

  Future<List<Contact>> contactList() async {
    final resp = await _conn.contactList(ContactListRequest());
    return resp.contacts;
  }

  /// Write a request for [payerGroupKeyHex] to pay this wallet, signed as this wallet.
  ///
  /// The result is the whole of the request — serialize it with `writeToBuffer()` and carry it however
  /// requests travel: a QR code, a link. It cannot be sent to the payer's cosigner from here: the
  /// runtime resolves a tenant from the caller's own token, so every connection this wallet opens
  /// lands in its own instance. The payer's app receives it into theirs — see
  /// [receivePaymentRequest].
  ///
  /// The signature is by this wallet's **group** key, made with this wallet's own cosigner, over a
  /// digest that names the payer, the amount, the memo, an expiry and a fresh nonce. So it cannot be
  /// forged by anyone holding only a share, redirected to another payer, altered, or replayed.
  ///
  /// `ark_info` is left unset. The payer supplies it from their own view of the ASP, and it is not
  /// signed: the payee address is derived from the key that signed, so ASP parameters cannot send
  /// the payment anywhere this wallet does not control.
  Future<PaymentRequestCreateRequest> writePaymentRequest(
    String payerGroupKeyHex,
    int amountSats, {
    String memo = '',
    int expiresInSecs = 0,
    Duration validFor = const Duration(hours: 1),
  }) async {
    if (validFor > maxRequestValidity) {
      throw ArgumentError('a request may be valid for at most ${maxRequestValidity.inHours}h');
    }
    final requesterHex = groupKeyHex;
    if (requesterHex == null) throw StateError('no wallet key yet — run DKG first');

    final payer = hex.decode(payerGroupKeyHex);
    final requester = hex.decode(requesterHex);
    final nonce = List<int>.generate(16, (_) => _secureRandom.nextInt(256));
    final notAfter = DateTime.now().add(validFor).millisecondsSinceEpoch ~/ 1000;

    final digest = requestDigest(
      payerGroupKey: payer,
      requesterGroupKey: requester,
      amountSats: amountSats,
      expiresInSecs: expiresInSecs,
      notAfter: notAfter,
      nonce: nonce,
      memo: memo,
    );
    // Untweaked: this is a statement by the group key, not a taproot key-path spend.
    final signature = await SignSession(_conn).sign(
      message: digest,
      keyPkg: await _keyPackageFor('Sign'),
      groupPubKey: _normalPolicy!.publicKeyPackage,
      applyTweak: false,
    );

    return PaymentRequestCreateRequest()
      ..amountSats = Int64(amountSats)
      ..memo = memo
      ..expiresInSecs = Int64(expiresInSecs)
      ..authorship = (RequestAuthorship()
        ..requesterGroupKey = requester
        ..payerGroupKey = payer
        ..notAfter = Int64(notAfter)
        ..nonce = nonce
        ..signature = schnorr64(signature));
  }

  /// Take a request somebody wrote and put it in this wallet's inbox.
  ///
  /// The other half of [writePaymentRequest]. This wallet's cosigner checks the signature, that the
  /// request names this wallet, that it is fresh and not seen before, and that its author is an
  /// allowlisted contact — and derives the payee address from the key that signed.
  Future<PaymentIntent> receivePaymentRequest(PaymentRequestCreateRequest request) async {
    // Our own view of the ASP, since the payee address is derived under it and we are the one who
    // will pay. Copied rather than mutated: the caller's request is left as it was received.
    final withInfo = request.deepCopy()..arkInfo = arkInfoToProto(await _asp.getInfo());
    final resp = await _conn.paymentRequestCreate(withInfo);
    return resp.intent;
  }

  /// Payment requests addressed to this wallet, newest first.
  Future<List<PaymentIntent>> paymentRequests() async {
    final resp = await _conn.paymentRequestList(PaymentRequestListRequest());
    return resp.intents;
  }

  Future<void> declinePaymentRequest(String id) async {
    await _conn.paymentRequestDecline(PaymentRequestDeclineRequest()
      ..id = id);
  }

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
