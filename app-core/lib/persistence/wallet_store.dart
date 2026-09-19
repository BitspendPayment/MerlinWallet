import 'dart:async';
import 'package:hive/hive.dart';
import 'package:synchronized/synchronized.dart';

/// Thread-safe wallet store with optional encryption support.
///
/// What it holds is the client's half of the key — the FROST share, the spending policy, the
/// delegate and the exits signed with it. It used to hold an on-chain UTXO set as well, for the
/// single-key wallet that lived beside the Ark one; that wallet is gone, and with it the only
/// reason this file knew what a Bitcoin address was.
///
/// When encryption is enabled, all data is encrypted at rest using AES-256.
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

  Future<void> saveClientState(Map<String, dynamic> state) async {
    await _lock.synchronized(() async {
      _ensureInitialized();
      await _box.put('client_state', state);
    });
  }

  Future<Map<String, dynamic>?> getClientState() async {
    return _lock.synchronized(() async {
      _ensureInitialized();
      final raw = _box.get('client_state');
      if (raw == null) return null;
      return _validateClientState(raw);
    });
  }

  /// Rewrite the box file, dropping overwritten entries. Hive is an
  /// append-only log, so a `put` alone leaves the PREVIOUS value readable in
  /// the file — call this after a write whose old value held secret material
  /// (e.g. replacing the raw FROST share with its blinded form).
  Future<void> compact() async {
    await _lock.synchronized(() async {
      _ensureInitialized();
      await _box.compact();
    });
  }

  Map<String, dynamic>? _validateClientState(dynamic raw) {
    if (raw == null) return null;

    try {
      final state = (raw as Map).cast<String, dynamic>();

      // Validate required userId field
      if (state['userId'] is! String ||
          (state['userId'] as String).isEmpty) {
        return null;
      }

      // Validate signingSecret format if present
      if (state['signingSecret'] != null) {
        final secret = state['signingSecret'];
        if (secret is! String || secret.isEmpty) {
          return null;
        }
        // Validate hex format (should be 64 hex chars for 32 bytes)
        if (!RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(secret)) {
          return null;
        }
      }

      return state;
    } catch (e) {
      return null;
    }
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
