/// Rebuilding the wallet's share for one operation, and everything that must stop it.
///
/// The wallet keeps no share. Each operation that signs rebuilds one from the passkey's polynomial
/// and the scalar the cosigner dealt (`passkey/share_reconstruction.dart`), and holds it in a
/// `WalletOperation` until the operation ends (`passkey/operation_secrets.dart`). Both dealers are
/// played here, so the right answer is known and every wrong one can be constructed.
@Tags(['ffi'])
library;

import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/passkey/operation_secrets.dart';
import 'package:app_core/passkey/share_reconstruction.dart';
import 'package:app_core/passkey/wallet_public_state.dart';
import 'package:app_core/threshold/frost/commitment.dart' as frost_comm;
import 'package:app_core/threshold/frost/signing.dart' as frost;
import 'package:app_core/threshold_types.dart' as threshold;

import 'support/ceremony.dart';

Uint8List bytesOf(BigInt scalar) => threshold.bigIntToBytes(scalar);

void main() {
  group('rebuilding the share', () {
    test('gives the share the ceremony produced, whichever way the group key fell', () async {
      // `dkg_part3` negates every share when the group key comes out odd, so about half of all
      // wallets are rebuilt as `n - sum`. Several ceremonies, so that both branches are walked.
      for (var fill = 1; fill <= 8; fill++) {
        final polynomial = await walletPolynomial(seed(fill));
        final c = await ceremony(polynomial);
        final rebuilt = reconstructWalletShare(
          polynomial: polynomial,
          dealtShare: bytesOf(c.dealtToWallet),
          wallet: c.wallet,
        );
        expect(rebuilt.secretShare, c.walletKp.secretShare, reason: 'seed $fill');
        expect(rebuilt.identifier, c.walletKp.identifier);
        expect(rebuilt.verifyingShare.toLowerCase(), c.walletKp.verifyingShare.toLowerCase());
        expect(rebuilt.verifyingKey.E, c.pkp.verifyingKey.E);
      }
    });

    test('signs: a rebuilt share and the cosigner make a signature the group key verifies',
        () async {
      final polynomial = await walletPolynomial(seed(21));
      final c = await ceremony(polynomial);
      final walletKp = reconstructWalletShare(
        polynomial: polynomial,
        dealtShare: bytesOf(c.dealtToWallet),
        wallet: c.wallet,
      );

      final message = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final walletNonce = frost_comm.newNonce(walletKp.secretShare);
      final cosignerNonce = frost_comm.newNonce(c.cosignerKp.secretShare);
      final package = frost_comm.SigningPackage({
        walletKp.identifier: walletNonce.commitments,
        c.cosignerKp.identifier: cosignerNonce.commitments,
      }, message);
      final signature = frost.aggregate(
        package,
        {
          walletKp.identifier: frost.sign(package, walletNonce, walletKp),
          c.cosignerKp.identifier: frost.sign(package, cosignerNonce, c.cosignerKp),
        },
        c.pkp,
      );
      // Throws if it does not verify.
      signature.verify(c.pkp.verifyingKey, message);
    });

    test('a different PRF output is a different wallet, and is refused as a wrong passkey',
        () async {
      final c = await ceremony(await walletPolynomial(seed(3)));
      expect(
        () async => reconstructWalletShare(
          polynomial: await walletPolynomial(seed(4)),
          dealtShare: bytesOf(c.dealtToWallet),
          wallet: c.wallet,
        ),
        throwsA(isA<WrongPasskey>()),
      );
    });

    test("another wallet's public state is refused: this passkey is not that wallet", () async {
      final mine = await walletPolynomial(seed(5));
      final c = await ceremony(mine);
      final theirs = await ceremony(await walletPolynomial(seed(6)));
      expect(
        () => reconstructWalletShare(
          polynomial: mine,
          dealtShare: bytesOf(c.dealtToWallet),
          wallet: theirs.wallet,
        ),
        throwsA(isA<WrongPasskey>()),
      );
    });

    test('the right identifier over the wrong verifying share is a share mismatch', () async {
      // The identifier is public, so a stored state can name it and still be for another key. What
      // stops a share being accepted against it is the verifying share, not the name.
      final polynomial = await walletPolynomial(seed(7));
      final c = await ceremony(polynomial);
      final other = await ceremony(await walletPolynomial(seed(8)));
      final forged = WalletPublicState(
        identifier: c.walletId,
        verifyingShare: other.wallet.verifyingShare,
        minSigners: 2,
        publicKeyPackage: other.pkp,
      );
      expect(
        () => reconstructWalletShare(
          polynomial: polynomial,
          dealtShare: bytesOf(c.dealtToWallet),
          wallet: forged,
        ),
        throwsA(isA<ShareMismatch>()),
      );
    });

    group('a contribution that is not what was dealt', () {
      late WalletPolynomial polynomial;
      late Ceremony c;
      setUp(() async {
        polynomial = await walletPolynomial(seed(9));
        c = await ceremony(polynomial);
      });

      Matcher refusedAs<T>() => throwsA(isA<T>());
      void rebuildWith(List<int> dealt) =>
          reconstructWalletShare(polynomial: polynomial, dealtShare: dealt, wallet: c.wallet);

      test('one bit out', () {
        final tampered = bytesOf(c.dealtToWallet)..[31] ^= 0x01;
        expect(() => rebuildWith(tampered), refusedAs<ShareMismatch>());
      });

      test("the cosigner's OWN share is not the wallet's half", () {
        expect(() => rebuildWith(bytesOf(c.cosignerKp.secretShare)), refusedAs<ShareMismatch>());
      });

      test("another wallet's dealt share", () async {
        final other = await ceremony(await walletPolynomial(seed(10)));
        expect(() => rebuildWith(bytesOf(other.dealtToWallet)), refusedAs<ShareMismatch>());
      });

      test('zero', () {
        expect(() => rebuildWith(Uint8List(32)), refusedAs<InvalidContribution>());
      });

      test('not below the group order', () {
        expect(() => rebuildWith(bytesOf(threshold.secp256k1Curve.n)),
            refusedAs<InvalidContribution>());
        expect(() => rebuildWith(List<int>.filled(32, 0xff)), refusedAs<InvalidContribution>());
      });

      test('the wrong length, or nothing', () {
        expect(() => rebuildWith(List<int>.filled(31, 1)), refusedAs<InvalidContribution>());
        expect(() => rebuildWith(List<int>.filled(33, 1)), refusedAs<InvalidContribution>());
        expect(() => rebuildWith(const []), refusedAs<InvalidContribution>());
      });
    });
  });

  group('what a new device accepts from Recover', () {
    test('a key package that is not for the group key named beside it', () async {
      final c = await ceremony(await walletPolynomial(seed(11)));
      final other = await ceremony(await walletPolynomial(seed(12)));
      expect(
        () => publicStateFromRecovery(
          publicKeyPackage: c.pkp,
          claimedGroupKeyHex: other.pkp.verifyingKey.E,
          identifier: c.walletId,
          minSigners: 2,
        ),
        throwsA(isA<GroupKeyMismatch>()),
      );
    });

    test('a ceremony this wallet took no part in', () async {
      final c = await ceremony(await walletPolynomial(seed(13)));
      final other = await ceremony(await walletPolynomial(seed(14)));
      expect(
        () => publicStateFromRecovery(
          publicKeyPackage: other.pkp,
          claimedGroupKeyHex: other.pkp.verifyingKey.E,
          identifier: c.walletId,
          minSigners: 2,
        ),
        throwsA(isA<NotAMember>()),
      );
    });

    test('hex case is not a difference', () async {
      final c = await ceremony(await walletPolynomial(seed(15)));
      final state = publicStateFromRecovery(
        publicKeyPackage: c.pkp,
        claimedGroupKeyHex: c.pkp.verifyingKey.E.toUpperCase(),
        identifier: c.walletId,
        minSigners: 2,
      );
      expect(state.groupKeyHex, c.pkp.verifyingKey.E.toLowerCase());
    });
  });

  group('an operation', () {
    test('overwrites the seed it was given, as soon as it has derived from it', () async {
      final c = await ceremony(await walletPolynomial(seed(16)));
      final handed = seed(16);
      final operation = await WalletOperation.begin(handed, wallet: c.wallet);
      expect(handed, everyElement(0), reason: 'the PRF output must not outlive the derivation');
      expect(operation.identifier, c.walletId);
      operation.dispose();
    });

    test('overwrites the seed when it refuses the passkey, too', () async {
      final c = await ceremony(await walletPolynomial(seed(17)));
      final handed = seed(18);
      await expectLater(
          WalletOperation.begin(handed, wallet: c.wallet), throwsA(isA<WrongPasskey>()));
      expect(handed, everyElement(0));
    });

    test('rebuilds once, and signs every later round of the stream with the same share', () async {
      final polynomial = await walletPolynomial(seed(19));
      final c = await ceremony(polynomial);
      final operation = await WalletOperation.begin(seed(19), wallet: c.wallet);

      final first = operation.keyPackage(bytesOf(c.dealtToWallet));
      expect(first.secretShare, c.walletKp.secretShare);
      // A renewal's second sighashes, or the delegate's after them: no share with it, same key.
      expect(identical(operation.keyPackage(const []), first), isTrue);
      operation.dispose();
    });

    test('refuses a cosigner that sends the share twice, or not at all', () async {
      final c = await ceremony(await walletPolynomial(seed(20)));
      final dealt = bytesOf(c.dealtToWallet);

      final none = await WalletOperation.begin(seed(20), wallet: c.wallet);
      expect(() => none.keyPackage(const []), throwsA(isA<ContributionProtocolException>()));
      none.dispose();

      final twice = await WalletOperation.begin(seed(20), wallet: c.wallet);
      twice.keyPackage(dealt);
      expect(() => twice.keyPackage(dealt), throwsA(isA<ContributionProtocolException>()));
      twice.dispose();
    });

    test('holds nothing once disposed, and can produce nothing', () async {
      final c = await ceremony(await walletPolynomial(seed(22)));
      final dealt = bytesOf(c.dealtToWallet);

      final operation = await WalletOperation.begin(seed(22), wallet: c.wallet);
      operation.keyPackage(dealt);
      expect(operation.holdsSecrets, isTrue);

      operation.dispose();
      expect(operation.isDisposed, isTrue);
      expect(operation.holdsSecrets, isFalse);
      expect(() => operation.keyPackage(const []), throwsStateError);
      expect(() => operation.keyPackage(dealt), throwsStateError);
      expect(operation.takePolynomial, throwsStateError);
      // Twice is fine: a `finally` does not know whether something else already did.
      operation.dispose();
    });

    test('disposing before any share existed is the cancelled case, and is clean', () async {
      final c = await ceremony(await walletPolynomial(seed(23)));
      final operation = await WalletOperation.begin(seed(23), wallet: c.wallet);
      expect(operation.holdsSecrets, isTrue, reason: 'the polynomial is a secret too');
      operation.dispose();
      expect(operation.holdsSecrets, isFalse);
    });

    test('gives its polynomial away once, for DKG and recovery', () async {
      final operation = await WalletOperation.begin(seed(24));
      final polynomial = operation.takePolynomial();
      expect(identifierOf(polynomial), operation.identifier);
      expect(operation.holdsSecrets, isFalse, reason: 'the operation keeps no copy');
      expect(operation.takePolynomial, throwsStateError);
      // And there is no wallet here to rebuild a share for.
      expect(() => operation.keyPackage(List<int>.filled(32, 1)), throwsStateError);
      operation.dispose();
    });
  });
}
