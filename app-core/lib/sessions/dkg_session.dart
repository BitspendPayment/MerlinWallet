/// The DKG ceremony, as one bidirectional session.
///
/// Two exchanges, not three. `DKGStep1/2/3` were three unary calls because each had to be a
/// request, and the middle one did nothing a caller needed — it recomputed the cosigner's round 2
/// and returned the round-1 packages step 1 had already returned. On a stream the cosigner does
/// that itself, leaving what the ceremony actually is: our round 1 in and everybody's out, then our
/// round 2 in and the cosigner's out with the key.
///
/// Three unary calls also meant the cosigner held round-1 and round-2 secrets between them, and
/// those secrets are how the key is born. Here they live on one handler's stack and die with it.
library;

import 'dart:convert';

import 'package:fixnum/fixnum.dart';
import 'package:protocol/cosigner_v1.dart' as cs;

import '../cosigner/connection.dart';
import '../passkey/key_derivation.dart';
import '../threshold_types.dart' as threshold;

/// What a completed ceremony hands back.
class DkgResult {
  DkgResult(this.keyPackage, this.publicKeyPackage, this.groupKeyHex);
  final threshold.KeyPackage keyPackage;
  final threshold.PublicKeyPackage publicKeyPackage;

  /// The group key the cosigner says the ceremony produced. Checked against the one the wallet
  /// derives independently — see [DkgSession.run].
  final String groupKeyHex;
}

class DkgSession {
  DkgSession(this._conn);
  final CosignerConnection _conn;

  /// Run the ceremony. 2-of-2 {wallet, cosigner}: both deal, both hold a share, both are needed to
  /// sign. No hardware signer, and no recovery share — the passkey is the recovery, because the
  /// wallet's own dealer is derived from it and the cosigner seals the half it deals back.
  ///
  /// The wallet's own dealer secret is returned alongside, because it doubles as the single-key
  /// on-chain key.
  ///
  /// [deviceToken], when not empty, is enrolled for wakes once the key exists; `deviceEnrolled` says
  /// whether it was.
  /// [polynomial] is what this wallet deals, derived from its passkey rather than drawn at random
  /// — see `passkey/key_derivation.dart`. That is what makes the wallet recoverable: the same
  /// passkey re-derives the same polynomial, and so the same identifier and the same half of the
  /// share. Nothing else in the ceremony needs to be deterministic; `dkgPart1`'s own randomness is
  /// the proof-of-knowledge nonce, which no key material depends on.
  Future<({DkgResult dkg, threshold.SecretKey onchainSecret, bool deviceEnrolled})> run({
    required int maxSigners,
    required int minSigners,
    required WalletPolynomial polynomial,
    String deviceToken = '',
  }) async {
    final secret = polynomial.a0;
    // A dealer's polynomial has degree `minSigners - 1`, and `walletPolynomial` derives exactly the
    // two coefficients a 2-of-2 needs. A higher threshold would need labels this KDF does not
    // define, and passing too few here would quietly deal a lower-degree polynomial — a weaker
    // secret sharing that only fails later, at the peer's commitment-length check.
    if (polynomial.higherCoefficients.length != minSigners - 1) {
      throw ArgumentError(
        'a $minSigners-of-$maxSigners ceremony needs ${minSigners - 1} coefficients above a0, and '
        'this polynomial has ${polynomial.higherCoefficients.length}',
      );
    }
    final (r1Secret, r1Pkg) = threshold.dkgPart1(
        maxSigners, minSigners, secret, polynomial.higherCoefficients);

    final walletVkBytes =
        threshold.elemSerializeCompressed(r1Pkg.commitment.toVerifyingKey().E);
    final walletIdentifier = threshold.Identifier.derive(walletVkBytes);

    // No identity is sent. There is no owner key to prove anything with yet — the ceremony mints it
    // — and none is needed: the runtime approved this stream with the tenant's passkey, which is
    // not the key being made and so can vouch for making it.

    final duplex = _conn.openDkg();
    try {
      duplex.send(cs.DkgClientMsg(
        sessionId: '',
        seq: Int64(0),
        open: cs.DkgOpen(
          identifier: walletIdentifier.serialize(),
          round1Package: jsonEncode(r1Pkg.toJson()),
          deviceToken: deviceToken,
        ),
      ));

      final round1 = await duplex.next('the round-1 packages');
      if (!round1.hasRound1()) {
        throw CosignerException('expected the round-1 packages, got ${round1.whichBody()}');
      }

      // Everybody's round 1 except our own.
      final round1Pkgs = <threshold.Identifier, threshold.Round1Package>{};
      round1.round1.round1Packages.forEach((k, v) {
        if (v.isEmpty) return;
        final id = threshold.Identifier(BigInt.parse(k, radix: 16));
        if (id == walletIdentifier) return;
        round1Pkgs[id] = threshold.Round1Package.fromJson(jsonDecode(v));
      });
      if (round1Pkgs.isEmpty) {
        throw CosignerException('the cosigner dealt no round-1 package of its own');
      }

      final (r2Secret, sharesFromWallet) = threshold.dkgPart2(r1Secret, round1Pkgs);

      duplex.send(cs.DkgClientMsg(
        sessionId: '',
        seq: Int64(1),
        round2: cs.DkgRound2(
          identifier: threshold.bigIntToBytes(walletIdentifier.toScalar()),
          round2PackagesForOthers: {
            for (final e in sharesFromWallet.entries)
              _idHex(e.key): jsonEncode(e.value.toJson()),
          },
        ),
      ));

      final complete = await duplex.next('the key');
      if (!complete.hasComplete()) {
        throw CosignerException('expected the key, got ${complete.whichBody()}');
      }

      final sharesForWallet = <threshold.Identifier, threshold.Round2Package>{};
      complete.complete.round2PackagesForMe.forEach((k, v) {
        sharesForWallet[threshold.Identifier(BigInt.parse(k, radix: 16))] =
            threshold.Round2Package.fromJson(jsonDecode(v));
      });

      final (keyPkg, pubKeyPkg) =
          threshold.dkgPart3(r1Secret, r2Secret, round1Pkgs, sharesForWallet);

      // Both sides derived a key; they must be the same key. The cosigner is about to seal its
      // share against its answer, so a mismatch here is a wallet that can never sign — caught now,
      // while it is still a failed onboarding rather than an unspendable balance.
      final derived = _hex(threshold.elemSerializeCompressed(pubKeyPkg.verifyingKey.E));
      if (derived != complete.complete.groupKey) {
        throw CosignerException(
          'the ceremony produced two different group keys: the cosigner says '
          '${complete.complete.groupKey}, this wallet derives $derived',
        );
      }

      return (
        dkg: DkgResult(keyPkg, pubKeyPkg, derived),
        onchainSecret: secret,
        deviceEnrolled: complete.complete.deviceEnrolled,
      );
    } finally {
      await duplex.close();
    }
  }

  static String _idHex(threshold.Identifier id) => _hex(id.serialize());

  static String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
