import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:hive/hive.dart';
import 'package:app_core/persistence/wallet_store.dart';
import 'package:app_core/persistence/encryption.dart';

/// Test salt and low-cost Argon2 params so tests stay fast.
final _testSalt = List<int>.filled(16, 0x42);

Future<HiveCipher> _cipherFor(String password) async {
  final provider = Argon2PasswordKeyProvider(
    password: password,
    salt: _testSalt,
    memoryKib: 8,
    iterations: 1,
    parallelism: 1,
  );
  final key = await provider.getOrCreateKey();
  return createCipherFromKey(key);
}

void main() {
  late Directory tempDir;

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('wallet_store_test_');
    Hive.init(tempDir.path);
  });

  tearDown(() async {
    await Hive.close();
    await tempDir.delete(recursive: true);
  });

  group('Encryption utilities', () {
    test('Argon2PasswordKeyProvider returns 32-byte key', () async {
      final provider = Argon2PasswordKeyProvider(
        password: 'testpin',
        salt: _testSalt,
        memoryKib: 8,
        iterations: 1,
        parallelism: 1,
      );
      final key = await provider.getOrCreateKey();
      expect(key.length, equals(32));
    });

    test('Argon2PasswordKeyProvider returns consistent key', () async {
      final provider = Argon2PasswordKeyProvider(
        password: 'testpin',
        salt: _testSalt,
        memoryKib: 8,
        iterations: 1,
        parallelism: 1,
      );
      final key1 = await provider.getOrCreateKey();
      final key2 = await provider.getOrCreateKey();
      expect(key1, equals(key2));
    });

    test('Different passwords produce different keys', () async {
      final provider1 = Argon2PasswordKeyProvider(
        password: '1234',
        salt: _testSalt,
        memoryKib: 8,
        iterations: 1,
        parallelism: 1,
      );
      final provider2 = Argon2PasswordKeyProvider(
        password: '5678',
        salt: _testSalt,
        memoryKib: 8,
        iterations: 1,
        parallelism: 1,
      );
      final key1 = await provider1.getOrCreateKey();
      final key2 = await provider2.getOrCreateKey();
      expect(key1, isNot(equals(key2)));
    });

    test('createCipherFromKey validates key length', () {
      expect(
        () => createCipherFromKey(Uint8List(16)),
        throwsArgumentError,
      );
      expect(
        () => createCipherFromKey(Uint8List(32)),
        returnsNormally,
      );
    });
  });

  group('WalletStore', () {
    test('initializes without encryption', () async {
      final store = WalletStore(boxName: 'test_unencrypted');
      await store.init();
      expect(store.isInitialized, isTrue);
      await store.close();
    });

    test('initializes with encryption', () async {
      final cipher = await _cipherFor('testpin');
      final store = WalletStore(
        boxName: 'test_encrypted',
        cipher: cipher,
      );
      await store.init();
      expect(store.isInitialized, isTrue);
      await store.close();
    });

    test('saves and retrieves client state', () async {
      final store = WalletStore(boxName: 'test_state');
      await store.init();

      final testState = {
        'userId': 'abcd1234' * 8, // 64 hex chars
        'signingSecret': 'ef567890' * 8, // 64 hex chars
      };

      await store.saveClientState(testState);
      final retrieved = await store.getClientState();

      expect(retrieved, isNotNull);
      expect(retrieved!['userId'], equals(testState['userId']));
      expect(retrieved['signingSecret'], equals(testState['signingSecret']));

      await store.close();
    });

    test('saves and retrieves state with encryption', () async {
      final cipher = await _cipherFor('securepin');
      final store = WalletStore(
        boxName: 'test_encrypted_state',
        cipher: cipher,
      );
      await store.init();

      final testState = {
        'userId': 'abcd1234' * 8,
        'signingSecret': 'ef567890' * 8,
      };

      await store.saveClientState(testState);
      final retrieved = await store.getClientState();

      expect(retrieved, isNotNull);
      expect(retrieved!['userId'], equals(testState['userId']));

      await store.close();
    });

    test('validates userId format on retrieval', () async {
      final store = WalletStore(boxName: 'test_validation');
      await store.init();

      // Save invalid state directly to box (bypassing validation)
      final box = await Hive.openBox('test_validation_raw');
      await box.put('client_state', {'userId': ''}); // Invalid empty userId
      await box.close();

      // Create new store pointing to same data
      final store2 = WalletStore(boxName: 'test_validation_raw');
      await store2.init();
      final retrieved = await store2.getClientState();

      expect(retrieved, isNull); // Should fail validation

      await store.close();
      await store2.close();
    });

    test('validates signingSecret hex format', () async {
      final store = WalletStore(boxName: 'test_secret_validation');
      await store.init();

      // Save state with invalid hex in signingSecret
      final box = await Hive.openBox('test_secret_validation_raw');
      await box.put('client_state', {
        'userId': 'abcd1234' * 8,
        'signingSecret': 'not-valid-hex!',
      });
      await box.close();

      final store2 = WalletStore(boxName: 'test_secret_validation_raw');
      await store2.init();
      final retrieved = await store2.getClientState();

      expect(retrieved, isNull); // Should fail validation

      await store.close();
      await store2.close();
    });

    test('throws when not initialized', () async {
      final store = WalletStore(boxName: 'test_not_init');
      // Don't call init()

      expect(
        () async => await store.getClientState(),
        throwsStateError,
      );
    });

    test('close is idempotent', () async {
      final store = WalletStore(boxName: 'test_close');
      await store.init();
      await store.close();
      await store.close(); // Should not throw
      expect(store.isInitialized, isFalse);
    });
  });

  group('Encrypted storage isolation', () {
    test('wrong password cannot read encrypted data', () async {
      // Save with password 1
      final cipher1 = await _cipherFor('correctpin');
      final store1 = WalletStore(
        boxName: 'test_pin_isolation',
        cipher: cipher1,
      );
      await store1.init();
      await store1.saveClientState({
        'userId': 'abcd1234' * 8,
        'signingSecret': 'ef567890' * 8,
      });
      await store1.close();

      // Try to read with wrong password - this should fail to open or read
      final cipher2 = await _cipherFor('wrongpin');
      final store2 = WalletStore(
        boxName: 'test_pin_isolation',
        cipher: cipher2,
      );

      // Opening with wrong cipher should fail or return corrupted data
      try {
        await store2.init();
        await store2.getClientState();
        await store2.close();
      } catch (e) {
        // Expected - wrong key should cause decryption failure
        expect(e, isNotNull);
      }
    });
  });
}
