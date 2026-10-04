/// Pairing a service into an escrow, on the `Escrow` stream that mints it.
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
/// service, over an origin the deployment names — a wallet names a service id, never a URL.
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
/// A pairing that fails part-way leaves that escrow unpaired; the wallet sets up a new one. Steps 1,
/// 2 and 4 run on the `Escrow` stream, after the escrow is minted — the wallet holds the share it
/// just made, so there is nothing to rebuild — and step 3 is the service's own.
library;

import 'dart:convert';
import 'dart:typed_data';

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

  /// Which attempt this was: the label both halves carried to the service.
  final String attemptIdHex;

  /// Where both halves went, as the enclave resolved it.
  final String serviceOrigin;
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
  required List<int> attemptId,
  required BigInt slope,
  required DeliverToService delivery,
  required Future<cs.PairServiceDone> Function(cs.PairServiceDeal deal) exchange,
  required Future<void> Function(List<int> attemptId) confirm,
  CancelSignal? cancel,
}) async {
  // The delivery is an HTTP call carrying a secret, and the confirmation is what makes the pairing
  // usable: neither may go on after the owner has cancelled. See `CancelSignal`.
  Future<T> guarded<T>(Future<T> work) => cancel?.guard(work) ?? work;

  // Deal onto {service, cosigner}, on the slope derived for this attempt — see `pairingSlope`.
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
  final attemptHex = _hex(attemptId);
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
  await guarded(confirm(attemptId));

  return PairingResult(pkp, done.serviceVerifyingShare, attemptHex, origin);
}

String _hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
