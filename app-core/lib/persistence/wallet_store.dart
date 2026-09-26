import 'dart:async';
import 'package:hive/hive.dart';
import 'package:synchronized/synchronized.dart';

/// The version of the client state this build reads and writes.
///
/// 2 is the first that holds nothing secret. There is no 1 on disk by that name — everything
/// before simply had no version — and there is no migration from it: see
/// [IncompatibleWalletStateException].
const int walletStateVersion = 2;

/// Keys that held wallet private-key material in some earlier state, and may never be written
/// again. Matched at any depth, because the share sat two maps down.
///
///  * `secretShare` — the FROST share inside a serialized key package; blinded (δ) once gating
///    existed, in the clear before.
///  * `onchainSecret` — the DKG constant `a0`, in the clear.
///  * `shareBlinded` — not a secret, but only ever true of a state that holds one.
///  * `signingSecret` — a second plaintext copy of the share, older still.
const Set<String> forbiddenStateKeys = {
  'secretShare',
  'onchainSecret',
  'shareBlinded',
  'signingSecret',
};

/// This device holds wallet state from before shares were rebuilt per operation, and this build
/// will neither read it nor quietly replace it.
///
/// **There is no migration, deliberately.** Everything in this repository is development data.
/// State like this holds a blinded share and a plaintext `a0` in an append-only file, and the
/// honest way to be rid of them is to delete the file — [WalletStore.destroy], reached through
/// `MpcClient.resetLocalState` — and then restore the wallet from its passkey, which needs nothing
/// that was in it. If the cosigner answers that the wallet "was created before recovery existed",
/// the wallet is older than recovery too, and the enclave's tenant needs resetting with it.
class IncompatibleWalletStateException implements Exception {
  IncompatibleWalletStateException(this.reason);
  final String reason;

  @override
  String toString() =>
      'this device holds development wallet state this build cannot use ($reason). It is from '
      'before shares were rebuilt from the passkey for each operation, and there is no migration: '
      'reset the local wallet state, then restore the wallet from its passkey.';
}

/// The first forbidden key found anywhere in [value], or null.
String? findForbiddenStateKey(Object? value) {
  if (value is Map) {
    for (final entry in value.entries) {
      if (forbiddenStateKeys.contains(entry.key)) return entry.key as String;
      final nested = findForbiddenStateKey(entry.value);
      if (nested != null) return nested;
    }
  } else if (value is Iterable) {
    for (final element in value) {
      final nested = findForbiddenStateKey(element);
      if (nested != null) return nested;
    }
  }
  return null;
}

/// [raw] as this build's client state, or an [IncompatibleWalletStateException] saying why not.
Map<String, dynamic> validateClientState(dynamic raw) {
  if (raw is! Map) throw IncompatibleWalletStateException('it is not a map');
  final state = raw.cast<String, dynamic>();

  final forbidden = findForbiddenStateKey(state);
  if (forbidden != null) {
    throw IncompatibleWalletStateException('it holds "$forbidden"');
  }
  final version = state['stateVersion'];
  if (version != walletStateVersion) {
    throw IncompatibleWalletStateException(
        version == null ? 'it has no version' : 'it is version $version');
  }
  if (state['userId'] is! String || (state['userId'] as String).isEmpty) {
    throw IncompatibleWalletStateException('it names no wallet');
  }
  return state;
}

/// Thread-safe wallet store with optional encryption support.
///
/// What it holds is public: who the wallet is, the delegate last sealed and the exits signed with
/// it. It used to hold the client's half of the key as well. It does not, and [saveClientState]
/// refuses anything that looks as though it might — a store that cannot be handed a secret is a
/// stronger statement than callers that remember not to hand it one.
///
/// When encryption is enabled, all data is encrypted at rest using AES-256. That is privacy for
/// what is here — balances' outpoints, an exit address — not what keeps the key safe.
class WalletStore {
  final String boxName;
  final HiveCipher? _cipher;
  late Box _box;
  bool _isInitialized = false;
  final Lock _lock = Lock();

  /// Creates a WalletStore with optional encryption.
  ///
  /// [boxName] - Name of the Hive box
  /// [cipher] - Optional cipher for encrypted storage. Pass a HiveAesCipher
  ///            created from a SecureKeyProvider for encrypted storage.
  WalletStore({
    this.boxName = 'bitcoin_wallet_state',
    HiveCipher? cipher,
  }) : _cipher = cipher;

  bool get isInitialized => _isInitialized;

  Future<void> init() async {
    await _lock.synchronized(() async {
      if (_isInitialized) return;
      // Open box with encryption if cipher is provided
      _box = await Hive.openBox(
        boxName,
        encryptionCipher: _cipher,
      );
      _isInitialized = true;
    });
  }

  void _ensureInitialized() {
    if (!_isInitialized) {
      throw StateError('WalletStore not initialized. Call init() first.');
    }
  }

  /// Write the client state. Throws [ArgumentError] if it is not version [walletStateVersion], or
  /// holds a key from [forbiddenStateKeys] at any depth — nothing is written in either case.
  Future<void> saveClientState(Map<String, dynamic> state) async {
    final forbidden = findForbiddenStateKey(state);
    if (forbidden != null) {
      throw ArgumentError(
          'refusing to persist "$forbidden": wallet private-key material is never stored');
    }
    if (state['stateVersion'] != walletStateVersion) {
      throw ArgumentError('client state must carry stateVersion $walletStateVersion');
    }
    await _lock.synchronized(() async {
      _ensureInitialized();
      await _box.put('client_state', state);
    });
  }

  /// The client state, or null when there is none.
  ///
  /// Throws [IncompatibleWalletStateException] when there is one and it is not this build's. It
  /// used to return null for anything it did not like, which sent the app back to onboarding — and
  /// an onboarding over a wallet that exists is a DKG the cosigner refuses, with a message about
  /// keys rather than about the stale file that caused it.
  Future<Map<String, dynamic>?> getClientState() async {
    return _lock.synchronized(() async {
      _ensureInitialized();
      final raw = _box.get('client_state');
      if (raw == null) return null;
      return validateClientState(raw);
    });
  }

  /// Delete the box and its file. What a reset does: Hive is an append-only log, so overwriting an
  /// old state would leave it readable in the file, and only removing the file removes it.
  ///
  /// The store is closed afterwards; [init] opens a new, empty one.
  Future<void> destroy() async {
    await _lock.synchronized(() async {
      if (!_isInitialized) {
        _box = await Hive.openBox(boxName, encryptionCipher: _cipher);
      }
      await _box.deleteFromDisk();
      _isInitialized = false;
    });
  }

  /// Closes the store and releases resources.
  Future<void> close() async {
    await _lock.synchronized(() async {
      if (_isInitialized && _box.isOpen) {
        await _box.close();
        _isInitialized = false;
      }
    });
  }
}
