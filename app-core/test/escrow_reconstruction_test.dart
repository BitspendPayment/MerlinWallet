/// Rebuilding the wallet's ESCROW share for one operation, and everything that must stop it.
///
/// `reconstructEscrowShare` had no test of its own: the reshare was proved to produce a key the
/// pair can sign under, but nothing fed a reshare's two halves through the Dart sum and compared
/// the result with the share the reshare actually produced — for both parities of the wallet key,
/// which is where its own doc says the sign goes wrong. Both dealers are played here, so the right
/// answer is known and every wrong one can be made.
@Tags(['ffi'])
library;

import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/passkey/operation_secrets.dart';
import 'package:app_core/passkey/share_reconstruction.dart';
import 'package:app_core/passkey/wallet_public_state.dart';
import 'package:app_core/threshold_types.dart' as threshold;

import 'support/ceremony.dart';

Uint8List bytesOf(BigInt scalar) => threshold.bigIntToBytes(scalar);

Uint8List context(int fill) => Uint8List.fromList(List<int>.filled(16, fill));

/// A reshare over [c]'s wallet key, the wallet dealing [delta]. Returns what the wallet ends up
/// holding, the escrow's public half, and the one scalar the cosigner seals — its delta dealt to
/// the wallet — which is what a reclaim or a pairing hands back as `escrow_delta_share`.
({
  threshold.KeyPackage walletKp,
  WalletPublicState escrow,
  BigInt cosignerDeltaToWallet,
}) reshare(Ceremony c, WalletPolynomial delta) {
  final aId = c.walletKp.identifier;
  final bId = c.cosignerKp.identifier;
  final (aR1s, aR1p) = threshold.dkgResharePart1From(aId, 2, 2, delta.a0, delta.higherCoefficients);
  final (bR1s, bR1p) = threshold.dkgResharePart1From(
      bId, 2, 2, threshold.newSecretKey(), [threshold.modNRandom()]);
  final (aR2s, _) = threshold.dkgPart2(aR1s, {bId: bR1p});
  final (_, bShares) = threshold.dkgPart2(bR1s, {aId: aR1p});
  final dealt = bShares[aId]!.secretShare;
  final (aKp, aPkp) = threshold.dkgResharePart3(
      aR2s, {bId: bR1p}, {bId: threshold.Round2Package(dealt)}, c.pkp, c.walletKp, [aId, bId]);
  return (
    walletKp: aKp,
    escrow: WalletPublicState.fromPublicKeyPackage(aPkp, aId, minSigners: 2),
    cosignerDeltaToWallet: dealt,
  );
}

void main() {
  group('rebuilding the escrow share', () {
    test('gives the share the reshare produced, whichever way either key fell', () async {
      // Two normalisations, one for each key, so four cases — many seeds walk all of them.
      for (var fill = 1; fill <= 12; fill++) {
        final polynomial = await walletPolynomial(seed(fill));
        final c = await ceremony(polynomial);
        final delta = await escrowPolynomial(seed(fill), context(fill));
        final e = reshare(c, delta);
        final rebuilt = reconstructEscrowShare(
          polynomial: polynomial,
          escrowDelta: delta,
          dealtShare: bytesOf(c.dealtToWallet),
          deltaShare: bytesOf(e.cosignerDeltaToWallet),
          wallet: c.wallet,
          escrow: e.escrow,
        );
        expect(rebuilt.secretShare, e.walletKp.secretShare, reason: 'seed $fill');
        expect(rebuilt.verifyingKey.E, e.escrow.publicKeyPackage.verifyingKey.E);
      }
    });

    test('a wrong passkey is refused before the escrow half is even looked at', () async {
      final c = await ceremony(await walletPolynomial(seed(20)));
      final delta = await escrowPolynomial(seed(20), context(1));
      final e = reshare(c, delta);
      expect(
        () async => reconstructEscrowShare(
          polynomial: await walletPolynomial(seed(21)),
          escrowDelta: delta,
          dealtShare: bytesOf(c.dealtToWallet),
          deltaShare: bytesOf(e.cosignerDeltaToWallet),
          wallet: c.wallet,
          escrow: e.escrow,
        ),
        throwsA(isA<WrongPasskey>()),
      );
    });

    test('the wrong escrow delta — another context — is a share mismatch', () async {
      final polynomial = await walletPolynomial(seed(22));
      final c = await ceremony(polynomial);
      final e = reshare(c, await escrowPolynomial(seed(22), context(1)));
      expect(
        () async => reconstructEscrowShare(
          polynomial: polynomial,
          escrowDelta: await escrowPolynomial(seed(22), context(2)),
          dealtShare: bytesOf(c.dealtToWallet),
          deltaShare: bytesOf(e.cosignerDeltaToWallet),
          wallet: c.wallet,
          escrow: e.escrow,
        ),
        throwsA(isA<ShareMismatch>()),
      );
    });

    test("a cosigner's delta that is not what it dealt", () async {
      final polynomial = await walletPolynomial(seed(23));
      final c = await ceremony(polynomial);
      final delta = await escrowPolynomial(seed(23), context(1));
      final e = reshare(c, delta);
      void rebuildWith(List<int> deltaShare) => reconstructEscrowShare(
            polynomial: polynomial,
            escrowDelta: delta,
            dealtShare: bytesOf(c.dealtToWallet),
            deltaShare: deltaShare,
            wallet: c.wallet,
            escrow: e.escrow,
          );
      expect(() => rebuildWith(bytesOf(e.cosignerDeltaToWallet)..[31] ^= 1),
          throwsA(isA<ShareMismatch>()));
      expect(() => rebuildWith(Uint8List(32)), throwsA(isA<InvalidContribution>()));
      expect(() => rebuildWith(List<int>.filled(31, 1)), throwsA(isA<InvalidContribution>()));
      expect(() => rebuildWith(const []), throwsA(isA<InvalidContribution>()));
    });
  });

  group('inside an operation', () {
    test('the escrow share is rebuilt once, from the halves, and released with the rest', () async {
      final polynomial = await walletPolynomial(seed(24));
      final c = await ceremony(polynomial);
      final ctx = context(3);
      final delta = await escrowPolynomial(seed(24), ctx);
      final e = reshare(c, delta);

      final operation = await WalletOperation.begin(seed(24),
          wallet: c.wallet, escrow: e.escrow, escrowContext: ctx);
      final dealt = bytesOf(c.dealtToWallet);
      final theirs = bytesOf(e.cosignerDeltaToWallet);
      final first = operation.escrowKeyPackage(dealt, theirs);
      expect(first.secretShare, e.walletKp.secretShare);
      // Later rounds bring nothing and sign with the same share.
      expect(identical(operation.escrowKeyPackage(const [], const []), first), isTrue);
      expect(() => operation.escrowKeyPackage(dealt, theirs),
          throwsA(isA<ContributionProtocolException>()));

      operation.dispose();
      expect(operation.holdsSecrets, isFalse);
      expect(() => operation.escrowKeyPackage(const [], const []), throwsStateError);
    });

    test('without both halves nothing is rebuilt', () async {
      final c = await ceremony(await walletPolynomial(seed(25)));
      final ctx = context(4);
      final e = reshare(c, await escrowPolynomial(seed(25), ctx));
      final operation = await WalletOperation.begin(seed(25),
          wallet: c.wallet, escrow: e.escrow, escrowContext: ctx);
      expect(() => operation.escrowKeyPackage(bytesOf(c.dealtToWallet), const []),
          throwsA(isA<ContributionProtocolException>()));
      expect(() => operation.escrowKeyPackage(const [], bytesOf(e.cosignerDeltaToWallet)),
          throwsA(isA<ContributionProtocolException>()));
      operation.dispose();
    });
  });
}
