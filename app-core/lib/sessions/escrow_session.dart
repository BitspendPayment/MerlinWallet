/// Minting an escrow key, as one bidirectional session.
///
/// The same two exchanges as the DKG ceremony, and for the same reason — the round-1 and round-2
/// secrets are what the key is born from, so they live on one frame on each side and die with it.
/// What differs is that both parties already have keys: this is a *reshare*, dealt under the
/// identifiers they already hold in the wallet key.
///
/// ```text
///   V' = V + Δ_wallet + Δ_cosigner
/// ```
///
/// `V` is untouched — the wallet keeps spending from it exactly as before — and `V'` is a second
/// 2-of-2 held by the same pair. Escrowed money goes to `V'`'s Ark address by an ordinary send, and
/// a service is paired into `V'` and never into the wallet. That separation is the whole point of
/// minting a key rather than reusing one.
///
/// The wallet's `Δ` is derived from its passkey rather than drawn, so a new device reproduces it:
/// see `passkey/key_derivation.dart`. Without that, escrowed money would be the one thing a lost
/// phone could not recover.
///
/// An escrow minted for a service can have that service paired into it on the same stream — one
/// approval for both — and the pairing is then the one `pairing_session.dart` describes, without
/// its first round: the wallet already holds the escrow share it just made.
library;

import 'dart:convert';

import 'package:fixnum/fixnum.dart';
import 'package:protocol/cosigner_v1.dart' as cs;

import '../cosigner/connection.dart';
import '../passkey/key_derivation.dart';
import '../passkey/operation_secrets.dart';
import '../threshold_types.dart' as threshold;
import 'pairing_session.dart';
import 'service_delivery.dart';

/// What a completed reshare hands back.
class EscrowResult {
  EscrowResult(this.keyPackage, this.publicKeyPackage, this.escrowKeyHex, {this.pairing});

  /// The wallet's share of `V'` — held for this operation only, never stored.
  final threshold.KeyPackage keyPackage;
  final threshold.PublicKeyPackage publicKeyPackage;

  /// `V'`, compressed hex, as both sides derived it.
  final String escrowKeyHex;

  /// The service paired into it on the same stream, when one was asked for.
  final PairingResult? pairing;
}

/// A service to pair into the escrow a stream mints, and what pairing it takes — see
/// `MpcClient.setUpEscrow`.
typedef EscrowPairing = ({
  threshold.Identifier service,
  List<int> attemptId,
  BigInt slope,
  DeliverToService delivery,
  CancelSignal? cancel,
});

class EscrowSession {
  EscrowSession(this._conn);
  final CosignerConnection _conn;

  /// Run the reshare.
  ///
  /// A reshare adds a delta to the wallet's EXISTING share, so that share has to be rebuilt first.
  /// [resolveWallet] is handed the cosigner's half when the stream brings it and returns the share
  /// — `WalletOperation.keyPackage`, the same resolver every other stream uses, so the share lives
  /// for this stream and no longer.
  ///
  /// [delta] is what this wallet deals, derived from its passkey under [context]. The same context
  /// must never be used twice for one wallet: two escrows on one delta are two points on one line.
  /// The cosigner records it and refuses a repeat.
  ///
  /// With [pair], the stream goes on to pair that service into the escrow once it is minted, and
  /// [onMinted] is told of the escrow first — before anything is dealt on it — so a pairing that
  /// fails leaves an escrow the caller knows it holds.
  ///
  /// The cosigner's identifier is taken from [walletPkp] — the one holder in the wallet key that
  /// is not this wallet — and **not** derived from the dealing it sends back.
  ///
  /// That distinction is the whole difference between a DKG and a reshare. `dkg_part1` derives a
  /// dealer's identifier from its own commitment, because the ceremony is where identifiers come
  /// from; `dkg_reshare_part1` takes one explicitly, because the deltas must land on the points the
  /// existing shares already sit at. Deriving it here instead produces an identifier the peer never
  /// dealt under, and the proof of knowledge — which is bound to the dealer's identifier — fails to
  /// verify. That is a cross-language bug no single-language test can see: both sides agree with
  /// themselves.
  Future<EscrowResult> run({
    required threshold.Identifier walletId,
    required threshold.PublicKeyPackage walletPkp,
    required threshold.KeyPackage Function(List<int> dealtShare) resolveWallet,
    required WalletPolynomial delta,
    required List<int> context,
    EscrowPairing? pair,
    Future<void> Function(EscrowResult minted)? onMinted,
    int maxSigners = 2,
    int minSigners = 2,
  }) async {
    final (r1Secret, r1Pkg) = threshold.dkgResharePart1From(
      walletId,
      maxSigners,
      minSigners,
      delta.a0,
      delta.higherCoefficients,
    );

    final duplex = _conn.openEscrow();
    try {
      duplex.send(cs.EscrowClientMsg(
        sessionId: '',
        seq: Int64(0),
        open: cs.EscrowOpen(
          identifier: walletId.serialize(),
          round1Package: jsonEncode(r1Pkg.toJson()),
          context: context,
          // Checked by the cosigner before anything is dealt, as a pairing on its own is.
          serviceIdentifier: pair?.service.serialize(),
          attemptId: pair?.attemptId,
        ),
      ));

      final round1 = await duplex.next("the cosigner's dealing");
      if (!round1.hasRound1()) {
        throw CosignerException("expected the cosigner's dealing, got ${round1.whichBody()}");
      }
      // The wallet's own share, rebuilt from its passkey and the half that just arrived. It has to
      // exist before the reshare can finalize, and it is gone when this operation ends.
      final walletKeyPackage = resolveWallet(round1.round1.walletDealtShare);
      final cosignerR1 =
          threshold.Round1Package.fromJson(jsonDecode(round1.round1.round1Package));
      // The wallet key's other holder. A 2-of-2 has exactly one, and a reshare is dealt under the
      // identifiers both parties already hold — see the note on [run].
      final others = walletPkp.verifyingShares.keys.where((id) => id != walletId).toList();
      if (others.length != 1) {
        throw StateError(
          'a wallet key is a 2-of-2, and this package names ${walletPkp.verifyingShares.length} '
          'holders',
        );
      }
      final cosignerId = others.single;

      final peers = {cosignerId: cosignerR1};
      final (r2Secret, ourShares) = threshold.dkgPart2(r1Secret, peers);
      final forCosigner = ourShares[cosignerId];
      if (forCosigner == null) {
        throw StateError('our reshare dealt the cosigner nothing');
      }

      duplex.send(cs.EscrowClientMsg(
        sessionId: '',
        seq: Int64(1),
        round2: cs.EscrowRound2(round2Package: jsonEncode(forCosigner.toJson())),
      ));

      final complete = await duplex.next('the escrow key');
      if (!complete.hasComplete()) {
        throw CosignerException('expected the escrow key, got ${complete.whichBody()}');
      }
      final theirShare =
          threshold.Round2Package.fromJson(jsonDecode(complete.complete.round2Package));

      final (keyPkg, pkp) = threshold.dkgResharePart3(
        r2Secret,
        peers,
        {cosignerId: theirShare},
        walletPkp,
        walletKeyPackage,
        [walletId, cosignerId],
      );

      // Both sides derived a key; they must be the same key. The cosigner has already sealed its
      // share against its answer, so a mismatch here is an escrow nothing could ever spend from —
      // caught before any money is sent to it.
      final derived = _hex(threshold.elemSerializeCompressed(pkp.verifyingKey.E));
      if (derived != complete.complete.escrowKey) {
        throw CosignerException(
          'the reshare produced two different escrow keys: the cosigner says '
          '${complete.complete.escrowKey}, this wallet derives $derived',
        );
      }

      final minted = EscrowResult(keyPkg, pkp, derived);
      await onMinted?.call(minted);
      if (pair == null) return minted;

      final pairing = await dealPairing(
        escrowKp: keyPkg,
        escrowKeyHex: derived,
        walletIdentifier: walletId,
        cosignerId: cosignerId,
        serviceIdentifier: pair.service,
        attemptId: pair.attemptId,
        slope: pair.slope,
        delivery: pair.delivery,
        cancel: pair.cancel,
        exchange: (deal) async {
          duplex.send(cs.EscrowClientMsg(sessionId: '', seq: Int64(2), deal: deal));
          final paired = await duplex.next('the pairing');
          if (!paired.hasPaired()) {
            throw CosignerException('expected the pairing, got ${paired.whichBody()}');
          }
          return paired.paired;
        },
        // On this stream: it still holds the tenant, so a call of its own would wait for it.
        confirm: (attemptId) async {
          duplex.send(cs.EscrowClientMsg(
            sessionId: '',
            seq: Int64(3),
            delivered: cs.PairServiceConfirmRequest(escrowKey: derived, attemptId: attemptId),
          ));
          final confirmed = await duplex.next('the confirmation');
          if (!confirmed.hasConfirmed()) {
            throw CosignerException('expected the confirmation, got ${confirmed.whichBody()}');
          }
        },
      );
      return EscrowResult(keyPkg, pkp, derived, pairing: pairing);
    } finally {
      await duplex.close();
    }
  }

  static String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
