/// One FROST signature, as one bidirectional session.
///
/// Two rounds: our commitments up, everybody's back; our share up, the aggregate back. It was two
/// unary calls, which made the cosigner hold a single-use nonce in memory between them — and a
/// reused nonce leaks a secret share. On one stream the nonce lives on the handler's stack and dies
/// with it, so an interrupted ceremony leaves nothing to reuse.
library;

import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:protocol/cosigner_v1.dart' as cs;

import '../cosigner/connection.dart';
import '../threshold/frost/ceremony.dart';
import '../threshold_types.dart' as threshold;

class SignSession {
  SignSession(this._conn);
  final CosignerConnection _conn;

  /// Sign [message] under this wallet's 2-of-2 key.
  ///
  /// [applyTweak] selects key-path (true) or script-path (false). [fullTransaction] is the bytes
  /// the signature will authorize — the cosigner has nothing that reads it today, but it is what a
  /// policy must see, so it travels.
  Future<threshold.Signature> sign({
    required Uint8List message,
    required threshold.KeyPackage keyPkg,
    required threshold.PublicKeyPackage groupPubKey,
    required List<int> userId,
    required List<int> signature,
    required int timestampMs,
    List<int>? fullTransaction,
    bool applyTweak = true,
  }) async {
    final round1 = frostRound1(keyPkg);
    final duplex = _conn.openSign();
    try {
      duplex.send(cs.SignClientMsg(
        sessionId: '',
        seq: Int64(0),
        open: cs.SignOpen(
          userId: userId,
          signature: signature,
          timestampMs: Int64(timestampMs),
          hidingCommitment: round1.hiding,
          bindingCommitment: round1.binding,
          messageToSign: message,
          fullTransaction: fullTransaction ?? const [],
          scriptPathSpend: !applyTweak,
        ),
      ));

      final commitments = await duplex.next('the commitments');
      if (!commitments.hasCommitments()) {
        throw CosignerException('expected the commitments round, got ${commitments.whichBody()}');
      }

      // The cosigner echoes what it will sign. Check it: it is authoritative about the message on
      // some paths, and a silent substitution is exactly what this round is the chance to catch.
      final echoed = Uint8List.fromList(commitments.commitments.messageToSign);
      if (!_sameBytes(echoed, message)) {
        throw CosignerException(
          'the cosigner intends to sign different bytes than were asked for',
        );
      }

      final round2 = frostRound2(
        commitments: {
          for (final e in commitments.commitments.commitments.entries)
            e.key: (hiding: e.value.hiding, binding: e.value.binding),
        },
        message: message,
        round1: round1,
        keyPkg: keyPkg,
        groupPubKey: groupPubKey,
        applyTweak: applyTweak,
      );

      duplex.send(cs.SignClientMsg(
        sessionId: '',
        seq: Int64(1),
        share: cs.SignShare(signatureShare: round2.share),
      ));

      final done = await duplex.next('the aggregate');
      if (!done.hasComplete()) {
        throw CosignerException('expected the aggregate, got ${done.whichBody()}');
      }
      return frostFinish(
        rPoint: done.complete.rPoint,
        zScalar: done.complete.zScalar,
        pubPackage: round2.pubPackage,
        message: message,
      );
    } finally {
      await duplex.close();
    }
  }

  static bool _sameBytes(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
