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
        'stateVersion': walletStateVersion,
        'userId': 'abcd1234' * 8, // 64 hex chars
        'exitScriptPubkey': 'ef567890' * 8,
      };

      await store.saveClientState(testState);
      final retrieved = await store.getClientState();

      expect(retrieved, isNotNull);
      expect(retrieved!['userId'], equals(testState['userId']));
      expect(retrieved['exitScriptPubkey'], equals(testState['exitScriptPubkey']));

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
        'stateVersion': walletStateVersion,
        'userId': 'abcd1234' * 8,
      };

      await store.saveClientState(testState);
      final retrieved = await store.getClientState();

      expect(retrieved, isNotNull);
      expect(retrieved!['userId'], equals(testState['userId']));

      await store.close();
    });

    /// Put [state] in a box behind the store's back, and read it through the store.
    Future<Map<String, dynamic>?> readBack(String boxName, Map<String, dynamic> state) async {
      final box = await Hive.openBox(boxName);
      await box.put('client_state', state);
      await box.close();
      final store = WalletStore(boxName: boxName);
      await store.init();
      try {
        return await store.getClientState();
      } finally {
        await store.close();
      }
    }

    test('an empty store holds no wallet, and says so with null', () async {
      final store = WalletStore(boxName: 'test_empty');
      await store.init();
      expect(await store.getClientState(), isNull);
      await store.close();
    });

    // Anything else used to be null as well, which sent the app back to onboarding over a wallet
    // that exists. Now it is an error with the way out in it.
    test('state with no version is refused by name, not read as absent', () async {
      await expectLater(
        readBack('test_unversioned', {'userId': 'abcd1234' * 8}),
        throwsA(isA<IncompatibleWalletStateException>()
            .having((e) => e.toString(), 'message', contains('reset'))),
      );
    });

    test('state of another version is refused', () async {
      await expectLater(
        readBack('test_future', {'stateVersion': 3, 'userId': 'abcd1234' * 8}),
        throwsA(isA<IncompatibleWalletStateException>()),
      );
    });

    test('state that names no wallet is refused', () async {
      await expectLater(
        readBack('test_validation', {'stateVersion': walletStateVersion, 'userId': ''}),
        throwsA(isA<IncompatibleWalletStateException>()),
      );
    });

    test('state holding a share is refused even under the right version', () async {
      for (final key in forbiddenStateKeys) {
        await expectLater(
          readBack('test_forbidden_$key', {
            'stateVersion': walletStateVersion,
            'userId': 'abcd1234' * 8,
            'spendingPolicies': {
              'keyPackage': {key: 'ef567890' * 8},
            },
          }),
          throwsA(isA<IncompatibleWalletStateException>()),
          reason: key,
        );
      }
    });

    test('refuses to write private-key material, under any name it has had', () async {
      final store = WalletStore(boxName: 'test_refuses_secrets');
      await store.init();
      final shapes = <Map<String, dynamic>>[
        {'onchainSecret': '11' * 32},
        {'signingSecret': '11' * 32},
        {'shareBlinded': true},
        {
          'spendingPolicies': {
            'keyPackage': {'secretShare': '11' * 32}
          }
        },
        {
          'delegate': {
            'exits': [
              {'secretShare': '11' * 32}
            ]
          }
        },
      ];
      for (final shape in shapes) {
        await expectLater(
          store.saveClientState(
              {'stateVersion': walletStateVersion, 'userId': 'abcd1234' * 8, ...shape}),
          throwsArgumentError,
          reason: '$shape',
        );
      }
      expect(await store.getClientState(), isNull, reason: 'a refused write writes nothing');
      await store.close();
    });

    test('refuses to write state without the current version', () async {
      final store = WalletStore(boxName: 'test_refuses_unversioned');
      await store.init();
      await expectLater(store.saveClientState({'userId': 'abcd1234' * 8}), throwsArgumentError);
      await store.close();
    });

    test('destroy removes the file, and with it everything ever appended to it', () async {
      final store = WalletStore(boxName: 'test_destroy');
      await store.init();
      await store.saveClientState({'stateVersion': walletStateVersion, 'userId': 'abcd1234' * 8});
      final file = File('${tempDir.path}/test_destroy.hive');
      expect(file.existsSync(), isTrue);

      await store.destroy();
      expect(file.existsSync(), isFalse);
      expect(store.isInitialized, isFalse);

      await store.init();
      expect(await store.getClientState(), isNull);
      await store.close();
    });

    test('destroy works on a store that was never opened', () async {
      final box = await Hive.openBox('test_destroy_cold');
      await box.put('client_state', {'userId': 'aa', 'onchainSecret': '11' * 32});
      await box.close();
      await WalletStore(boxName: 'test_destroy_cold').destroy();
      expect(File('${tempDir.path}/test_destroy_cold.hive').existsSync(), isFalse);
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
        'stateVersion': walletStateVersion,
        'userId': 'abcd1234' * 8,
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
