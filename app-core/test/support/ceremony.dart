/// A 2-of-2 ceremony played out in full, both dealers in one process — so what the cosigner would
/// seal and hand back is known exactly, and a rebuilt share can be held against the one a real DKG
/// produced.
library;

import 'dart:typed_data';

import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/passkey/wallet_public_state.dart';
import 'package:app_core/threshold_types.dart' as threshold;

/// A stand-in for a passkey's PRF output: 32 bytes, the same on every device the passkey syncs to.
Uint8List seed(int fill) => Uint8List.fromList(List<int>.filled(32, fill));

typedef Ceremony = ({
  threshold.KeyPackage walletKp,
  threshold.KeyPackage cosignerKp,
  threshold.PublicKeyPackage pkp,
  threshold.Identifier walletId,

  /// `f_cosigner(wallet identifier)` — the scalar the cosigner seals, and the only thing the wallet
  /// ever needs back from it.
  BigInt dealtToWallet,

  /// What the wallet's device keeps: the ceremony's public half, and nothing else.
  WalletPublicState wallet,
});

/// One 2-of-2 ceremony, the wallet dealing [polynomial].
Future<Ceremony> ceremony(WalletPolynomial polynomial) async {
  final (wR1s, wR1p) = threshold.dkgPart1(2, 2, polynomial.a0, polynomial.higherCoefficients);
  final (cR1s, cR1p) =
      threshold.dkgPart1(2, 2, threshold.newSecretKey(), [threshold.modNRandom()]);
  final walletId = wR1s.identifier;
  final cosignerId = cR1s.identifier;

  final (wR2s, wShares) = threshold.dkgPart2(wR1s, {cosignerId: cR1p});
  final (cR2s, cShares) = threshold.dkgPart2(cR1s, {walletId: wR1p});
  final dealt = cShares[walletId]!.secretShare;

  final (walletKp, pkp) = threshold.dkgPart3(
      wR1s, wR2s, {cosignerId: cR1p}, {cosignerId: threshold.Round2Package(dealt)});
  final (cosignerKp, _) =
      threshold.dkgPart3(cR1s, cR2s, {walletId: wR1p}, {walletId: wShares[cosignerId]!});

  return (
    walletKp: walletKp,
    cosignerKp: cosignerKp,
    pkp: pkp,
    walletId: walletId,
    dealtToWallet: dealt,
    wallet: WalletPublicState.fromPublicKeyPackage(pkp, walletId, minSigners: 2),
  );
}
