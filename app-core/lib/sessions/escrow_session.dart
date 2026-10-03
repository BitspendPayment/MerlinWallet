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
/// An escrow minted for a service has that service paired into it on the same stream, and its deal
/// struck — one approval for all three — and the pairing is then the one `pairing_session.dart`
/// describes, without its first round: the wallet already holds the escrow share it just made. One
/// escrow, one deal: nothing commits an escrow but the stream that minted it.
library;

import 'dart:convert';

import 'package:fixnum/fixnum.dart';
import 'package:protocol/cosigner_v1.dart' as cs;

import '../asp/asp_client.dart';
import '../cosigner/connection.dart';
import '../passkey/key_derivation.dart';
import '../passkey/operation_secrets.dart';
import '../threshold_types.dart' as threshold;
import 'pairing_session.dart';
import 'send_session.dart';
import 'service_delivery.dart';

/// What a completed reshare hands back.
class EscrowResult {
  EscrowResult(this.keyPackage, this.publicKeyPackage, this.escrowKeyHex,
      {this.pairing, this.agreed, this.funded});

  /// The wallet's share of `V'` — held for this operation only, never stored.
  final threshold.KeyPackage keyPackage;
  final threshold.PublicKeyPackage publicKeyPackage;

  /// `V'`, compressed hex, as both sides derived it.
  final String escrowKeyHex;

  /// The service paired into it on the same stream, when one was asked for.
  final PairingResult? pairing;

  /// Its deal as the cosigner sealed it, rendered for consent — what the owner agreed to. Null
  /// when no service was paired, and so no deal struck.
  final String? agreed;

  /// The send that funded it on the same stream, when one was asked for.
  final SendResult? funded;
}

/// The send that funds the escrow a stream mints, on the same stream and its one approval — see
/// `MpcClient.setUpEscrow`. What it sends is the wallet's to say; where it goes is the cosigner's
/// to derive, so there is no recipient here.
typedef EscrowFunding = ({
  int amountSats,
  List<IndexerVtxo> vtxos,
  ArkInfo info,
  AspClient asp,
  Future<List<IndexerVtxo>> Function()? readHeld,
  String deviceToken,
  String exitScriptPubkeyHex,
  String ownerXOnlyHex,
  Future<void> Function(String escrowKeyHex)? beforeFunding,
});

/// A service to pair into the escrow a stream mints, what pairing it takes, and the deal it is
/// paired in for — see `MpcClient.setUpEscrow`.
typedef EscrowPairing = ({
  threshold.Identifier service,
  List<int> attemptId,
  BigInt slope,
  DeliverToService delivery,
  CancelSignal? cancel,
  Map<String, dynamic> policy,
  DateTime deadline,
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
  /// With [pair], the stream goes on to pair that service into the escrow once it is minted and
  /// strike its deal, and [onMinted] is told of the escrow first — before anything is dealt on it —
  /// so a pairing that fails leaves an escrow the caller knows it holds.
  ///
  /// With [fund] as well, the stream then funds the escrow: a send's rounds, carried on it, with
  /// the share the reshare already rebuilt — so a payment costs the owner one approval.
  /// `fund.beforeFunding` is told the escrow before any money moves to it.
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
    EscrowFunding? fund,
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
          // Checked by the cosigner before anything is dealt, as a pairing on its own is — and the
          // deal with them, so terms it could never strike mint nothing.
          serviceIdentifier: pair?.service.serialize(),
          attemptId: pair?.attemptId,
          policyJson: pair == null ? null : jsonEncode(pair.policy),
          deadlineSecs:
              pair == null ? null : Int64(pair.deadline.millisecondsSinceEpoch ~/ 1000),
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

      String? agreed;
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
        // On this stream: it still holds the tenant, so a call of its own would wait for it. The
        // answer is the deal, struck now that both halves are with the service.
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
          agreed = confirmed.confirmed.policyDescription;
        },
      );
      if (fund == null) {
        return EscrowResult(keyPkg, pkp, derived, pairing: pairing, agreed: agreed);
      }

      // --- Funding it, on this stream ---------------------------------------------------------
      //
      // Told first, so a caller can remember the escrow before money is sent to it: whatever the
      // send then does, what the escrow holds can be taken back.
      await fund.beforeFunding?.call(derived);
      final funded =
          await SendSession(_conn, fund.asp).drive<cs.EscrowClientMsg, cs.EscrowServerMsg>(
        duplex: duplex,
        // Its own seq numbers, after the escrow's.
        carry: (msg) => cs.EscrowClientMsg(sessionId: '', seq: Int64(4) + msg.seq, fund: msg),
        uncarry: (msg) => msg.hasFunding() ? msg.funding : cs.SendServerMsg(),
        // The cosigner pays the escrow it minted; naming somewhere else is refused.
        recipientArkAddress: '',
        amountSats: fund.amountSats,
        vtxos: fund.vtxos,
        info: fund.info,
        identifier: walletId.serialize(),
        // The share this stream already rebuilt: the funding's sighashes bring no dealt share.
        resolve: resolveWallet,
        groupPubKey: walletPkp,
        cancel: pair.cancel,
        readHeld: fund.readHeld,
        deviceToken: fund.deviceToken,
        exitScriptPubkeyHex: fund.exitScriptPubkeyHex,
        ownerXOnlyHex: fund.ownerXOnlyHex,
      );
      return EscrowResult(keyPkg, pkp, derived,
          pairing: pairing, agreed: agreed, funded: funded);
    } finally {
      await duplex.close();
    }
  }

  static String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
