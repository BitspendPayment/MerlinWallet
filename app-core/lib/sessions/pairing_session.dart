/// Pairing a service into an escrow, as one bidirectional session.
///
/// The escrow key `V'` is held by this wallet and its cosigner. Pairing gives a *service* a share
/// of the same key by a key-preserving refresh, so afterwards two pairs can sign `V'` — the wallet
/// with the cosigner, and the service with the cosigner — and the key itself never moves.
///
/// ```text
///   wallet   deals  a@service (as a POINT) , a@cosigner (as a scalar)
///   cosigner deals  b@service                              its own, freshly random
///   service        s = a@service + b@service
/// ```
///
/// **The wallet sends its contribution to the service as a point, never as the scalar.** A cosigner
/// holding both that scalar and its own counter-share would have two points on one line and could
/// reconstruct the service's share; it checks the point against public data instead.
///
/// **And it never sees the cosigner's half.** That travels from the enclave straight to the
/// service, over an origin the image names — a wallet names a service id, never a URL.
///
/// But the wallet's own half has to get there too, and it must not go through the cosigner: one
/// that saw both terms could sign as the service. So it goes **directly from this device to the
/// same origin the enclave resolved**, which the cosigner returns for exactly that purpose.
///
/// So a pairing is finished in four steps, and is not usable until all four are done:
///
/// ```text
///   1. cosigner deals, delivers b@service, seals the pairing PENDING
///   2. wallet delivers a@service to the same origin
///   3. service assembles s = a + b and checks it against the published verifying share
///   4. wallet confirms  ──▶  the cosigner marks the pairing READY
/// ```
///
/// Steps 2-4 are retryable for one attempt, because the wallet's slope is *derived* from its
/// passkey under the escrow's context and the attempt id — so redelivering reproduces the same
/// contribution rather than a second, incompatible one. A failure at step 1 is different: the
/// cosigner's half is never retained, so that attempt is dead and the wallet pairs again under a
/// fresh attempt id.
///
/// A stream rather than one call, because the wallet has to rebuild its escrow share before it can
/// deal, and it keeps no share: the halves it needs arrive on the first server message.
///
/// An escrow minted for a service is paired on the stream that mints it instead — the wallet holds
/// the share it just made, so there is nothing to rebuild — and confirmed there too. Both streams
/// deal through [dealPairing].
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:protocol/cosigner_v1.dart' as cs;

import '../cosigner/connection.dart';
import '../passkey/operation_secrets.dart';
import '../threshold_types.dart' as threshold;
import 'service_delivery.dart';

/// What a completed pairing hands back — all of it public.
class PairingResult {
  PairingResult(
    this.publicKeyPackage,
    this.serviceVerifyingShareHex,
    this.attemptIdHex,
    this.serviceOrigin,
  );

  /// The pairing's public package. Its verifying key is the escrow key, unchanged.
  final threshold.PublicKeyPackage publicKeyPackage;

  /// The verifying share the service's assembled share must match.
  final String serviceVerifyingShareHex;

  /// Which attempt succeeded. Kept so a caller retrying a half-finished pairing names the same one
  /// rather than starting a second.
  final String attemptIdHex;

  /// Where both halves went, as the enclave resolved it.
  final String serviceOrigin;
}

class PairingSession {
  PairingSession(this._conn, {DeliverToService? delivery})
      : _delivery = delivery ?? HttpServiceDelivery();
  final CosignerConnection _conn;
  final DeliverToService _delivery;

  /// Pair [serviceIdentifier] into the escrow described by [escrowPkp].
  ///
  /// [resolveEscrow] is handed the two halves the cosigner sends and returns this wallet's escrow
  /// share — see `MpcClient.pairService`, which rebuilds it from the passkey and lets it go when
  /// the operation ends.
  Future<PairingResult> run({
    required String escrowKeyHex,
    required threshold.PublicKeyPackage escrowPkp,
    required threshold.Identifier serviceIdentifier,
    required threshold.Identifier walletIdentifier,
    required List<int> attemptId,
    required BigInt slope,
    required threshold.KeyPackage Function(
            List<int> walletDealtShare, List<int> escrowDeltaShare)
        resolveEscrow,
    CancelSignal? cancel,
  }) async {
    // The escrow's other holder: the one identifier in its package that is not this wallet's. A
    // 2-of-2 has exactly one, and anything else is not the escrow this wallet thinks it is.
    final others = escrowPkp.verifyingShares.keys.where((id) => id != walletIdentifier).toList();
    if (others.length != 1) {
      throw StateError(
        'an escrow is a 2-of-2, and this package names ${escrowPkp.verifyingShares.length} '
        'holders',
      );
    }
    final cosignerId = others.single;

    final duplex = _conn.openPairService();
    try {
      duplex.send(cs.PairServiceClientMsg(
        sessionId: '',
        seq: Int64(0),
        open: cs.PairServiceOpen(
          escrowKey: escrowKeyHex,
          serviceIdentifier: serviceIdentifier.serialize(),
          attemptId: attemptId,
        ),
      ));

      final ready = await duplex.next('the halves to rebuild the escrow share with');
      if (!ready.hasReady()) {
        throw CosignerException('expected the escrow halves, got ${ready.whichBody()}');
      }
      final escrowKp = resolveEscrow(
        ready.ready.walletDealtShare,
        ready.ready.escrowDeltaShare,
      );

      return await dealPairing(
        escrowKp: escrowKp,
        escrowKeyHex: escrowKeyHex,
        walletIdentifier: walletIdentifier,
        cosignerId: cosignerId,
        serviceIdentifier: serviceIdentifier,
        slope: slope,
        delivery: _delivery,
        cancel: cancel,
        exchange: (deal) async {
          duplex.send(cs.PairServiceClientMsg(sessionId: '', seq: Int64(1), deal: deal));
          final done = await duplex.next('the pairing');
          if (!done.hasDone()) {
            throw CosignerException('expected the pairing, got ${done.whichBody()}');
          }
          return done.done;
        },
        // A call of its own: the cosigner ended this stream when it sent `Done`, so the tenant is
        // free for it.
        confirm: (attemptId) => _conn.pairServiceConfirm(cs.PairServiceConfirmRequest(
          escrowKey: escrowKeyHex,
          attemptId: attemptId,
        )),
      );
    } finally {
      await duplex.close();
    }
  }
}

/// Steps 1-4 above, from the wallet's side, once it holds its escrow share [escrowKp]: deal onto
/// `{service, cosigner}`, let the cosigner deliver its half, deliver this wallet's half to the
/// origin the cosigner resolved, and confirm.
///
/// [exchange] sends the dealing and returns the cosigner's `PairServiceDone`; [confirm] tells the
/// cosigner this wallet's half was taken. Each stream that pairs says how, on its own messages.
Future<PairingResult> dealPairing({
  required threshold.KeyPackage escrowKp,
  required String escrowKeyHex,
  required threshold.Identifier walletIdentifier,
  required threshold.Identifier cosignerId,
  required threshold.Identifier serviceIdentifier,
  required BigInt slope,
  required DeliverToService delivery,
  required Future<cs.PairServiceDone> Function(cs.PairServiceDeal deal) exchange,
  required Future<void> Function(List<int> attemptId) confirm,
  CancelSignal? cancel,
}) async {
  // The delivery is an HTTP call carrying a secret, and the confirmation is what makes the pairing
  // usable: neither may go on after the owner has cancelled. See `CancelSignal`.
  Future<T> guarded<T>(Future<T> work) => cancel?.guard(work) ?? work;

  // Deal onto {service, cosigner}. The slope is derived, not drawn — see `pairingSlope`. That is
  // what makes step 2 retryable: the same attempt reproduces the same contribution.
  final (atService, atCosigner) = threshold.refreshShareToId(
    escrowKp,
    [walletIdentifier, cosignerId],
    serviceIdentifier,
    cosignerId,
    slope,
  );

  final done = await exchange(cs.PairServiceDeal(
    contributionToCosigner: threshold.bigIntToBytes(atCosigner),
    // A point, never the scalar behind it.
    contributionToService: Uint8List.fromList(
      threshold.elemSerializeCompressed(threshold.elemBaseMul(atService)),
    ),
  ));
  final pkp = threshold.PublicKeyPackage.fromJson(
      jsonDecode(done.publicKeyPackageJson) as Map<String, dynamic>);

  // A refresh preserves the key. If this one did not, the pairing signs for something that is not
  // the escrow — and money already in the escrow would be unreachable through it.
  final derived = _hex(threshold.elemSerializeCompressed(pkp.verifyingKey.E));
  if (derived.toLowerCase() != escrowKeyHex.toLowerCase()) {
    throw CosignerException(
      'the pairing moved the escrow key: it was $escrowKeyHex and the pairing signs for $derived',
    );
  }

  // --- The wallet's own half, to the origin the enclave resolved -------------------------------
  //
  // Directly, and not through the cosigner: one that held both terms could sign as the service.
  final attemptHex = _hex(done.attemptId);
  final origin = done.serviceOrigin;
  if (origin.isEmpty) {
    throw CosignerException(
      'the cosigner delivered its half but did not say where, so this wallet cannot send its own '
      'to the same place',
    );
  }
  await guarded(delivery.deliver(
    origin,
    ServiceContribution(
      escrowKeyHex: escrowKeyHex,
      attemptIdHex: attemptHex,
      serviceIdentifierHex: _hex(serviceIdentifier.serialize()),
      contributionHex: _hex(threshold.bigIntToBytes(atService)),
    ),
  ));

  // The service has both and has checked the share they sum to — it answered "ready", which is
  // what that means. Only now is the pairing usable, and only now does the cosigner agree.
  await guarded(confirm(done.attemptId));

  return PairingResult(pkp, done.serviceVerifyingShare, attemptHex, origin);
}

String _hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
