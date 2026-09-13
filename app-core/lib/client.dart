import 'dart:async';
import 'dart:typed_data';

import 'package:app_core/policy.dart';
import 'package:app_core/auth_helper.dart';
import 'package:app_core/ark/ark.dart' as ark_addr;
import 'package:app_core/asp/asp_client.dart';
import 'package:app_core/cosigner/connection.dart';
import 'package:app_core/sessions/dkg_session.dart';
import 'package:app_core/sessions/send_session.dart';
import 'package:app_core/sessions/settle_session.dart';
import 'package:app_core/sessions/sign_session.dart';
import 'package:app_core/passkey/session_token_source.dart';
import 'package:app_core/passkey/seed_source.dart';
import 'package:app_core/pin_blinding.dart';
import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:app_core/threshold/core/dkg.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;
// `ArkInfo` is hidden: the proto one is the wire shape, and `asp/ark_info.dart` has the value type
// the wallet actually passes around. `SendSession.arkInfoToProto` converts at the boundary.
import 'package:protocol/protocol.dart' hide ArkInfo;
import 'package:fixnum/fixnum.dart';
import 'package:hive/hive.dart';
import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:convert/convert.dart';

import 'package:app_core/persistence/wallet_store.dart';

class MpcClient {
  /// The cosigner: four ceremony streams and seven single-round calls.
  final CosignerConnection _conn;

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

  threshold.SecretKey? _signingSecret;

  /// PIN/passkey-PRF share gating. When a [SeedSource] is configured the wallet's FROST share is
  /// stored BLINDED (δ = share − b(seed)) inside `_normalPolicy.keyPackage.secretShare`; the raw
  /// share is never persisted and is reconstructed transiently only for an ARK sign / contract
  /// op (see [_walletKeyPackage]). Reads + auth then need no share (auth rides the session token).
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

  // Auth helper for signing requests (initialized after DKG or restore)
  ClientAuthHelper? _authHelper;

  SpendingPolicy? _normalPolicy;

  /// Creates a client that manages two shares (identities).
  ///
  /// [channel] - gRPC channel to the MPC server
  /// [maxSigners] - Maximum number of signers in the threshold scheme
  /// [minSigners] - Minimum signers required (threshold)
  /// [storageId] - Unique identifier for the Hive box
  /// [encryptionCipher] - Optional cipher for encrypted storage.
  ///                      Use HiveAesCipher for AES-256 encryption.
  ///                      When null, data is stored unencrypted.
  /// Connect to a cosigner and an ASP.
  ///
  /// One transport now. REST is gone — the cosigner serves a single gRPC service — and with it the
  /// attested-REST variant, whose per-response signature header had nothing to attach to on a
  /// bidirectional stream. Attestation belongs per request, in gRPC metadata, once the runtime
  /// serves a document to verify against; the FFI verifier in `enclave/` is untouched and is the
  /// half worth keeping.
  MpcClient.grpc({
    required String cosignerHost,
    required int cosignerPort,
    required String aspHost,
    required int aspPort,
    bool secure = false,
    int maxSigners = 2,
    int minSigners = 2,
    String? storageId,
    HiveCipher? encryptionCipher,
  })  : _conn = CosignerConnection.connect(cosignerHost, cosignerPort, secure: secure),
        _asp = AspClient.connect(aspHost, aspPort, secure: secure),
        _maxSigners = maxSigners,
        _minSigners = minSigners {
    _store = WalletStore(
      boxName: storageId ?? 'mpc_wallet_state_default',
      cipher: encryptionCipher,
    );
  }

  /// The ASP, for a caller that needs to ask it something directly — chiefly polling for receives.
  AspClient get asp => _asp;

  /// No-op. The Bearer session token rode HTTP headers on the REST transport; there are none. When
  /// tokens return they ride gRPC metadata, which is an interceptor on [CosignerConnection].
  void setSessionTokenSource(SessionTokenSource source) {}

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

    // Restore signing secret for authentication. Absent for a gated wallet (share stored blinded);
    // then `_authHelper` stays null and auth rides the session token.
    if (state['signingSecret'] != null) {
      final secretHex = state['signingSecret'] as String;
      final secretBytes = Uint8List.fromList(hex.decode(secretHex));
      _signingSecret =
          threshold.SecretKey(threshold.bytesToBigInt(secretBytes));
      _authHelper =
          ClientAuthHelper.fromSigningSecret(_signingSecret!, _userId!);
    }
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

    return true;
  }

  Future<void> _saveState() async {
    final state = <String, dynamic>{
      'userId': hex.encode(_userId!),
    };
    if (_signingSecret != null) {
      state['signingSecret'] =
          hex.encode(threshold.bigIntToBytes(_signingSecret!.scalar));
    }
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
    );
    // The wallet's dealer secret doubles as its single-key on-chain key.
    _onchainSecret = result.onchainSecret;
    await _finalizeWalletShare(result.dkg.keyPackage, result.dkg.publicKeyPackage);
    await _saveState();
  }

  PublicKeyPackage? getTweakedPublicKeyPackage(List<int>? merkle_root) {
    final publicKeyPackage = _normalPolicy?.publicKeyPackage;
    return publicKeyPackage?.tweak(merkle_root);
  }

  PublicKeyPackage? getPublicKeyPackage() {
    return _normalPolicy?.publicKeyPackage;
  }


  /// Auth signature for a request. With share gating on, `_authHelper` is null and the cosigner
  /// authenticates the Bearer session token at the REST boundary, so we send an empty Schnorr
  /// signature. Un-gated, this is the usual share-derived signature.
  AuthSignature _authSig(AuthSignature Function(ClientAuthHelper) sign) {
    final h = _authHelper;
    if (h != null) return sign(h);
    return AuthSignature(
        Uint8List(0), Int64(DateTime.now().millisecondsSinceEpoch));
  }

  /// Auth signature authorizing a passkey to be attached to this wallet.
  ///
  /// Deliberately NOT routed through [_authSig]: that falls back to an empty
  /// signature once the share is gated, and the cosigner rejects an empty one
  /// here — a session token is what a passkey mints, so accepting one would be
  /// circular. Call this while the share is still un-gated (during
  /// `enablePasskey`, before `gateShare`).
  AuthSignature signForPasskeyRegister() {
    final h = _authHelper;
    if (h == null) {
      throw StateError(
          'passkey registration must be signed with the wallet key, but the '
          'share is already gated — re-run before gateShare()');
    }
    return h.signForPasskeyRegister();
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

  /// Finalize the wallet's freshly-DKG'd share into `_normalPolicy` + auth state. When a
  /// [SeedSource] is configured, store the share BLINDED (δ) — the raw share is never persisted and
  /// never lingers in memory; it's reconstructed transiently at sign time. Auth then rides the
  /// session token (no share-derived helper). Un-gated: keep the raw share + the Schnorr helper.
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
      _signingSecret = null;
      _authHelper = null;
    } else {
      _signingSecret = threshold.SecretKey(walletKeyPkg.secretShare);
      _normalPolicy = SpendingPolicy(
          id: "normal_policy_id",
          keyPackage: walletKeyPkg,
          publicKeyPackage: pubKeyPkg);
      _authHelper =
          ClientAuthHelper.fromSigningSecret(_signingSecret!, _userId!);
    }
  }

  /// Gate an already-DKG'd (raw) share retroactively: blind it to δ under [seed], persist δ, and drop
  /// the raw share + Schnorr auth helper. Used when the seed only exists after DKG — a passkey's PRF
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
    _signingSecret = null;
    _authHelper = null;
    await _saveState();
    // Hive appends; without compaction the pre-gating state (raw share +
    // signingSecret) would remain readable in the box file.
    await _store.compact();
  }

  // --- SIGNING ---

  Future<threshold.Signature> sign(Uint8List message,
      {List<int>? fullTransaction, bool applyTweak = true}) async {
    final keyPackage = await _walletKeyPackage();
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
    final userId = _userId;
    if (userId == null) {
      throw StateError('User ID is null, cannot proceed with signing.');
    }
    final auth = _authSig((h) => h.signForSignStep1());
    return SignSession(_conn).sign(
      message: message,
      keyPkg: keyPkg,
      groupPubKey: groupPubKey,
      userId: userId,
      signature: auth.signature,
      timestampMs: auth.timestampMs.toInt(),
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

  /// What this wallet holds, from the ASP's indexer.
  ///
  /// Both scripts — a boarded VTXO keeps the boarding delay while received and refreshed ones use
  /// the unilateral delay, so they sit under different ones, and asking for a single script makes
  /// the other bucket invisible.
  Future<List<IndexerVtxo>> listVtxos() async {
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
    );
  }

  /// Our own verifying share, or a clear failure. Every authenticated call needs it, and "null
  /// user id" surfaces far from the call that forgot to run DKG.
  List<int> _idOrThrow() {
    final id = _userId;
    if (id == null) throw StateError('No user id yet — run DKG first.');
    return id;
  }

  static String _hexOf(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// Send [amountSats] off-chain to [recipientArkAddress]. Returns the ark txid.
  ///
  /// The wallet no longer builds the transaction — the cosigner does, and hands back sighashes to
  /// FROST-sign. What the wallet does instead is talk to the ASP: `SubmitTx`, then `FinalizeTx`,
  /// then tell the cosigner it was accepted so the send is recorded only once it is real.
  Future<String> sendVtxo(String recipientArkAddress, int amountSats) async {
    final userId = _userId;
    if (userId == null) throw StateError('User ID is null, cannot send.');
    final auth = _authSig((h) => h.signForSendVtxo());
    final info = await _asp.getInfo();
    return SendSession(_conn, _asp).send(
      recipientArkAddress: recipientArkAddress,
      amountSats: amountSats,
      vtxos: await listVtxos(),
      info: info,
      keyPkg: await _walletKeyPackage(),
      groupPubKey: _normalPolicy!.publicKeyPackage,
      userId: userId,
      signature: auth.signature,
      timestampMs: auth.timestampMs.toInt(),
    );
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
    final userId = _userId;
    if (userId == null) throw StateError('User ID is null, cannot settle.');
    final auth = _authSig((h) => h.signForSettle());
    final info = await _asp.getInfo();
    final result = await SettleSession(_conn, _asp).settle(
      info: info,
      keyPkg: await _walletKeyPackage(),
      groupPubKey: _normalPolicy!.publicKeyPackage,
      userId: userId,
      signature: auth.signature,
      timestampMs: auth.timestampMs.toInt(),
      boardingUtxo: boardingUtxos.isEmpty ? null : boardingUtxos.first,
      vtxos: boardingUtxos.isEmpty ? await listVtxos() : const [],
      onProgress: onProgress,
    );
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
    final auth = _authSig((h) => h.signForContactAdd());
    await _conn.contactAdd(ContactAddRequest()
      ..userId = _idOrThrow()
      ..contactVerifyingKey = hex.decode(contactGroupKeyHex)
      ..label = label
      ..signature = auth.signature
      ..timestampMs = auth.timestampMs);
  }

  /// Revoke a contact. Their pending requests are dropped too.
  Future<void> contactRemove(String contactGroupKeyHex) async {
    final auth = _authSig((h) => h.signForContactRemove());
    await _conn.contactRemove(ContactRemoveRequest()
      ..userId = _idOrThrow()
      ..contactVerifyingKey = hex.decode(contactGroupKeyHex)
      ..signature = auth.signature
      ..timestampMs = auth.timestampMs);
  }

  Future<List<Contact>> contactList() async {
    final auth = _authSig((h) => h.signForContactList());
    final resp = await _conn.contactList(ContactListRequest()
      ..userId = _idOrThrow()
      ..signature = auth.signature
      ..timestampMs = auth.timestampMs);
    return resp.contacts;
  }

  /// Ask to be paid.
  ///
  /// Signed by US and addressed to the PAYER's cosigner — their allowlist is the authorization,
  /// which is why there is no ownership check on the other side. The payee address is derived there
  /// from our allowlisted key; we never supply one, or a contact could redirect the payment.
  ///
  /// [conn] must point at the payer's cosigner. There is no routing argument any more: one process
  /// serves one wallet, so which cosigner you are talking to *is* which payer you are billing.
  Future<PaymentIntent> requestPayment(
    CosignerConnection conn,
    int amountSats, {
    String memo = '',
    int expiresInSecs = 0,
  }) async {
    final auth = _authSig((h) => h.signForPayreqCreate());
    // The payer's cosigner derives our address from these; it has no ASP of its own to ask.
    final info = await _asp.getInfo();
    final resp = await conn.paymentRequestCreate(
      PaymentRequestCreateRequest()
        ..userId = _idOrThrow()
        ..amountSats = Int64(amountSats)
        ..memo = memo
        ..expiresInSecs = Int64(expiresInSecs)
        ..signature = auth.signature
        ..timestampMs = auth.timestampMs
        ..arkInfo = arkInfoToProto(info),
    );
    return resp.intent;
  }

  /// Payment requests addressed to this wallet, newest first.
  Future<List<PaymentIntent>> paymentRequests() async {
    final auth = _authSig((h) => h.signForPayreqList());
    final resp = await _conn.paymentRequestList(PaymentRequestListRequest()
      ..userId = _idOrThrow()
      ..signature = auth.signature
      ..timestampMs = auth.timestampMs);
    return resp.intents;
  }

  Future<void> declinePaymentRequest(String id) async {
    final auth = _authSig((h) => h.signForPayreqDecline());
    await _conn.paymentRequestDecline(PaymentRequestDeclineRequest()
      ..userId = _idOrThrow()
      ..id = id
      ..signature = auth.signature
      ..timestampMs = auth.timestampMs);
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
    final auth = _authSig((h) => h.signForRegisterDeviceToken());
    await _conn.registerDevice(cs.RegisterDeviceRequest()
      ..userId = _idOrThrow()
      ..token = token
      ..signature = auth.signature
      ..timestampMs = auth.timestampMs);
  }

  /// Stop waking the device behind [token] — a sign-out, or a token FCM rotated away.
  Future<void> forgetDevice(String token) async {
    final auth = _authSig((h) => h.signForRegisterDeviceToken());
    await _conn.forgetDevice(cs.ForgetDeviceRequest()
      ..userId = _idOrThrow()
      ..token = token
      ..signature = auth.signature
      ..timestampMs = auth.timestampMs);
  }

  /// How many devices are enrolled. A count, never the tokens: the cosigner is not meant to be
  /// able to enumerate them.
  Future<int> deviceCount() async {
    final auth = _authSig((h) => h.signForRegisterDeviceToken());
    return _conn.deviceCount(cs.DeviceCountRequest()
      ..userId = _idOrThrow()
      ..signature = auth.signature
      ..timestampMs = auth.timestampMs);
  }
}
