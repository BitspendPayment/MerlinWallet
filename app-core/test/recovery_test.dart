/// Recovering a wallet: the arithmetic the new device does, over a ceremony played out in full.
///
/// `MpcClient.recover` rebuilds a share from two halves — the one it derives from the passkey and
/// the one the cosigner sealed — and refuses anything that does not match the verifying share the
/// ceremony recorded. Both dealers are played here, so what the cosigner would hand back is known
/// exactly, and the rebuilt share can be checked against the one a real DKG produced.
///
/// The cosigner's own side of this is proved against its seal in `cosigner/tests/dkg_test.rs`.
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/threshold_types.dart' as threshold;

/// A stand-in for a passkey's PRF output: 32 bytes, the same on every device the passkey syncs to.
Uint8List seed(int fill) => Uint8List.fromList(List<int>.filled(32, fill));

/// One 2-of-2 ceremony. Returns what each side ends up with, plus the share the cosigner dealt —
/// the scalar it seals, and the only thing recovery needs from it.
Future<
    ({
      threshold.KeyPackage walletKp,
      threshold.PublicKeyPackage pkp,
      threshold.Identifier walletId,
      BigInt dealtToWallet,
    })> ceremony(WalletPolynomial wallet) async {
  final (wR1s, wR1p) = threshold.dkgPart1(2, 2, wallet.a0, wallet.higherCoefficients);
  final (cR1s, cR1p) =
      threshold.dkgPart1(2, 2, threshold.newSecretKey(), [threshold.modNRandom()]);
  final walletId = wR1s.identifier;
  final cosignerId = cR1s.identifier;

  final (wR2s, _) = threshold.dkgPart2(wR1s, {cosignerId: cR1p});
  final (_, cShares) = threshold.dkgPart2(cR1s, {walletId: wR1p});
  final dealt = cShares[walletId]!.secretShare;

  final (kp, pkp) = threshold.dkgPart3(
      wR1s, wR2s, {cosignerId: cR1p}, {cosignerId: threshold.Round2Package(dealt)});
  return (walletKp: kp, pkp: pkp, walletId: walletId, dealtToWallet: dealt);
}

/// What `MpcClient.recover` does once it has both halves: add, fix the sign, and check.
BigInt rebuild({
  required WalletPolynomial polynomial,
  required threshold.Identifier id,
  required BigInt dealt,
  required String expectedVerifyingShare,
}) {
  final own = threshold.evaluatePolynomial(
      id, [polynomial.a0.scalar, ...polynomial.higherCoefficients]);
  final n = threshold.secp256k1Curve.n;
  final sum = (own + dealt) % n;
  return [sum, (n - sum) % n].firstWhere(
      (c) => threshold.elemBaseMul(c) == expectedVerifyingShare,
      orElse: () => throw StateError('neither sign matched the verifying share'));
}

void main() {
  group('recovering a wallet from its passkey', () {
    test('the rebuilt share is the share the ceremony produced', () async {
      final polynomial = await walletPolynomial(seed(1));
      final c = await ceremony(polynomial);

      final share = rebuild(
        polynomial: polynomial,
        id: c.walletId,
        dealt: c.dealtToWallet,
        expectedVerifyingShare: c.pkp.verifyingShares[c.walletId]!,
      );
      expect(share, equals(c.walletKp.secretShare),
          reason: 'a recovered wallet must hold exactly the share it had before');
    });

    test('the same passkey lands on the same identifier, so the cosigner recognizes it', () async {
      final first = await walletPolynomial(seed(2));
      final second = await walletPolynomial(seed(2));
      threshold.Identifier idOf(WalletPolynomial p) => threshold.Identifier.derive(
          threshold.elemSerializeCompressed(threshold.elemBaseMul(p.a0.scalar)));

      expect(idOf(first), equals(idOf(second)));
      // And it is the identifier the ceremony itself derived — the one the cosigner sealed.
      expect(idOf(first), equals((await ceremony(first)).walletId));
    });

    test('a different passkey derives a different wallet entirely', () async {
      final mine = await walletPolynomial(seed(3));
      final theirs = await walletPolynomial(seed(4));
      expect(mine.a0.scalar, isNot(equals(theirs.a0.scalar)));

      final c = await ceremony(mine);
      // The cosigner would refuse this on the identifier alone. If it ever did not, the arithmetic
      // still would: the wrong half rebuilds a share that is not the wallet's.
      expect(
        () => rebuild(
          polynomial: theirs,
          id: c.walletId,
          dealt: c.dealtToWallet,
          expectedVerifyingShare: c.pkp.verifyingShares[c.walletId]!,
        ),
        throwsStateError,
      );
    });

    test('half a key is not a key: the passkey alone rebuilds nothing', () async {
      final polynomial = await walletPolynomial(seed(5));
      final c = await ceremony(polynomial);
      final own = threshold.evaluatePolynomial(
          c.walletId, [polynomial.a0.scalar, ...polynomial.higherCoefficients]);

      expect(own, isNot(equals(c.walletKp.secretShare)));
      expect(threshold.elemBaseMul(own),
          isNot(equals(c.pkp.verifyingShares[c.walletId]!)));
    });

    test('the dealt share alone rebuilds nothing either', () async {
      final polynomial = await walletPolynomial(seed(6));
      final c = await ceremony(polynomial);

      expect(c.dealtToWallet, isNot(equals(c.walletKp.secretShare)));
      expect(threshold.elemBaseMul(c.dealtToWallet),
          isNot(equals(c.pkp.verifyingShares[c.walletId]!)));
    });
  });
}
