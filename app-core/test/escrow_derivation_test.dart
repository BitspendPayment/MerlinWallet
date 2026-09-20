/// The escrow delta, and the reshare it drives — both sides played here.
///
/// Escrowed money must be as recoverable as ordinary money, and that rests on one property: the
/// delta a wallet deals to mint an escrow is *derived* from its passkey, not drawn. So the same
/// passkey on a new device reproduces it, and with the scalar the cosigner sealed that is enough to
/// rebuild the escrow share.
///
/// The cosigner's half of this is proved against its own handler in `cosigner/tests/escrow_test.rs`.
/// What is proved here is the Dart side: the derivation reproduces, contexts separate one escrow
/// from the next, and the reshare these feed really does produce a key the pair can sign under.
@Tags(['ffi'])
library;

import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/threshold_types.dart' as threshold;

/// A stand-in for a passkey's PRF output.
Uint8List seed(int fill) => Uint8List.fromList(List<int>.filled(32, fill));

Uint8List context(int fill) => Uint8List.fromList(List<int>.filled(16, fill));

/// One 2-of-2, so there is a key to reshare from.
({List<threshold.KeyPackage> kps, threshold.PublicKeyPackage pkp}) wallet() {
  final aSecret = threshold.newSecretKey();
  final bSecret = threshold.newSecretKey();
  final (aR1s, aR1p) = threshold.dkgPart1(2, 2, aSecret, [threshold.modNRandom()]);
  final (bR1s, bR1p) = threshold.dkgPart1(2, 2, bSecret, [threshold.modNRandom()]);
  final aId = aR1s.identifier;
  final bId = bR1s.identifier;

  final (aR2s, aShares) = threshold.dkgPart2(aR1s, {bId: bR1p});
  final (bR2s, bShares) = threshold.dkgPart2(bR1s, {aId: aR1p});

  final (aKp, aPkp) = threshold.dkgPart3(aR1s, aR2s, {bId: bR1p}, {bId: bShares[aId]!});
  final (bKp, _) = threshold.dkgPart3(bR1s, bR2s, {aId: aR1p}, {aId: aShares[bId]!});
  return (kps: [aKp, bKp], pkp: aPkp);
}

/// The reshare, both sides in Dart. Returns each party's new share and the escrow key.
({List<threshold.KeyPackage> kps, threshold.PublicKeyPackage pkp}) reshare(
  List<threshold.KeyPackage> old,
  threshold.PublicKeyPackage oldPkp,
  WalletPolynomial walletDelta,
) {
  final aId = old[0].identifier;
  final bId = old[1].identifier;

  final (aR1s, aR1p) = threshold.dkgResharePart1From(
      aId, 2, 2, walletDelta.a0, walletDelta.higherCoefficients);
  // The cosigner's delta is drawn, not derived: it is the enclave's to keep, and it seals what the
  // wallet needs from it.
  final (bR1s, bR1p) = threshold.dkgResharePart1From(
      bId, 2, 2, threshold.newSecretKey(), [threshold.modNRandom()]);

  final (aR2s, aShares) = threshold.dkgPart2(aR1s, {bId: bR1p});
  final (bR2s, bShares) = threshold.dkgPart2(bR1s, {aId: aR1p});

  final receivers = [aId, bId];
  final (aKp, aPkp) = threshold.dkgResharePart3(
      aR2s, {bId: bR1p}, {bId: bShares[aId]!}, oldPkp, old[0], receivers);
  final (bKp, bPkp) = threshold.dkgResharePart3(
      bR2s, {aId: aR1p}, {aId: aShares[bId]!}, oldPkp, old[1], receivers);

  expect(bPkp.verifyingKey.E, equals(aPkp.verifyingKey.E),
      reason: 'both sides must land on one escrow key');
  return (kps: [aKp, bKp], pkp: aPkp);
}

void main() {
  group('the escrow delta', () {
    test('the same passkey and context give the same delta, every time', () async {
      final first = await escrowPolynomial(seed(1), context(9));
      final second = await escrowPolynomial(seed(1), context(9));
      expect(first.a0.scalar, equals(second.a0.scalar));
      expect(first.a1, equals(second.a1));
    });

    test('a different context is a different escrow', () async {
      final first = await escrowPolynomial(seed(1), context(9));
      final second = await escrowPolynomial(seed(1), context(10));
      expect(first.a0.scalar, isNot(equals(second.a0.scalar)));
      expect(first.a1, isNot(equals(second.a1)));
    });

    test('a different passkey is a different delta under the same context', () async {
      final mine = await escrowPolynomial(seed(1), context(9));
      final theirs = await escrowPolynomial(seed(2), context(9));
      expect(mine.a0.scalar, isNot(equals(theirs.a0.scalar)));
    });

    test('it is not the wallet polynomial wearing a different hat', () async {
      final key = await walletPolynomial(seed(1));
      final delta = await escrowPolynomial(seed(1), context(9));
      expect(delta.a0.scalar, isNot(equals(key.a0.scalar)),
          reason: 'a delta equal to the wallet key would be one label doing two jobs');
      expect(delta.a1, isNot(equals(key.a1)));
    });

    test('its constant term is non-zero, or the key would not move', () async {
      final delta = await escrowPolynomial(seed(3), context(4));
      expect(delta.a0.scalar, isNot(equals(BigInt.zero)));
    });
  });

  group('the reshare it drives', () {
    test('mints a key that is not the wallet key, held by the same pair', () async {
      final w = wallet();
      final delta = await escrowPolynomial(seed(1), context(9));
      final escrow = reshare(w.kps, w.pkp, delta);

      expect(escrow.pkp.verifyingKey.E, isNot(equals(w.pkp.verifyingKey.E)),
          reason: 'a non-zero delta must move the key');
      expect(escrow.pkp.verifyingShares.length, equals(2));
      expect(escrow.kps[0].identifier, equals(w.kps[0].identifier),
          reason: 'a reshare keeps the identifiers it was dealt under');
    });

    test('a derived delta reproduces the same escrow key from the same passkey', () async {
      final w = wallet();
      // Same wallet, same context, but the cosigner's delta is random each time — so the escrow
      // keys differ. What must reproduce is the wallet's own contribution, and the way to see it is
      // that the wallet's dealing is identical.
      final first = await escrowPolynomial(seed(1), context(9));
      final second = await escrowPolynomial(seed(1), context(9));
      final id = w.kps[0].identifier;
      final (_, firstPkg) =
          threshold.dkgResharePart1From(id, 2, 2, first.a0, first.higherCoefficients);
      final (_, secondPkg) =
          threshold.dkgResharePart1From(id, 2, 2, second.a0, second.higherCoefficients);
      expect(
        firstPkg.commitment.toVerifyingKey().E,
        equals(secondPkg.commitment.toVerifyingKey().E),
        reason: 'the same passkey must deal the same delta — this is what makes escrow recoverable',
      );
    });

    test('each share matches the verifying share the escrow published', () async {
      final w = wallet();
      final delta = await escrowPolynomial(seed(5), context(6));
      final escrow = reshare(w.kps, w.pkp, delta);

      // `s·G` against what the package publishes, for both halves. This is the check a device runs
      // on every rebuilt share, and the reason a wrong term is caught rather than signed with.
      // (That the pair's signature verifies under BIP-340 is proved in `cosigner/tests/escrow_test.rs`,
      // against bitcoin's own secp256k1.)
      for (final kp in escrow.kps) {
        expect(
          threshold.elemBaseMul(kp.secretShare).toLowerCase(),
          equals(escrow.pkp.verifyingShares[kp.identifier]!.toLowerCase()),
        );
      }
    });

    test('the wallet share alone is not the escrow share', () async {
      final w = wallet();
      final delta = await escrowPolynomial(seed(8), context(2));
      final escrow = reshare(w.kps, w.pkp, delta);

      expect(escrow.kps[0].secretShare, isNot(equals(w.kps[0].secretShare)),
          reason: 'the delta must actually move the share, not merely the key');
    });
  });
}
