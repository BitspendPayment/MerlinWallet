/// One FROST signature, as one bidirectional session.
///
/// Two exchanges: the message up and the cosigner's commitment back, then our commitments and our
/// share up together and the aggregate back. It was two unary calls once, which made the cosigner
/// hold a single-use nonce in memory between them — and a reused nonce leaks a secret share. On one
/// stream the nonce lives on the handler's stack and dies with it, so an interrupted ceremony
/// leaves nothing to reuse.
///
/// The wallet used to commit first, in the open. It cannot any more: its nonce is hedged with its
/// share, and it holds no share until the cosigner's first answer brings the half it dealt
/// (`passkey/operation_secrets.dart`). So the cosigner commits first — as it always has on the
/// `Send` and `Settle` streams, see `in_band_round.dart` — and nothing is lost by it: FROST needs
/// both commitments before either share, not ours before theirs, and the binding factor covers
/// every commitment whoever sent theirs last.
///
/// **Script-path only.** The cosigner signs untweaked and checks every share before aggregating, so
/// a key-path share — the taproot tweak compensated on the wallet's half alone — could never have
/// aggregated here. There was an `applyTweak` parameter that offered it anyway; nothing called it.
library;

import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:protocol/cosigner_v1.dart' as cs;

import '../cosigner/connection.dart';
import '../passkey/operation_secrets.dart';
import '../threshold/frost/ceremony.dart';
import '../threshold_types.dart' as threshold;

class SignSession {
  SignSession(this._conn);
  final CosignerConnection _conn;

  /// Sign [message] under this wallet's 2-of-2 key, untweaked.
  ///
  /// [identifier] is this wallet's, and [resolve] turns the dealt share the cosigner answers with
  /// into the key package — see `KeyResolver`. [fullTransaction] is the bytes the signature will
  /// authorize — the cosigner has nothing that reads it today, but it is what a policy must see,
  /// so it travels.
  ///
  /// The aggregate is verified against [groupPubKey] before it is returned. This is the one
  /// stream where the wallet sees the finished signature, so it is the one place it can notice
  /// that what came back does not sign what it asked about.
  Future<threshold.Signature> sign({
    required Uint8List message,
    required List<int> identifier,
    required KeyResolver resolve,
    required threshold.PublicKeyPackage groupPubKey,
    List<int>? fullTransaction,
  }) async {
    final duplex = _conn.openSign();
    try {
      duplex.send(cs.SignClientMsg(
        sessionId: '',
        seq: Int64(0),
        open: cs.SignOpen(
          messageToSign: message,
          fullTransaction: fullTransaction ?? const [],
          scriptPathSpend: true,
          identifier: identifier,
        ),
      ));

      final commitments = await duplex.next('the commitments');
      if (!commitments.hasCommitments()) {
        throw CosignerException('expected the commitments round, got ${commitments.whichBody()}');
      }
      final c = commitments.commitments;

      // The cosigner echoes what it will sign. Check it BEFORE rebuilding a share for it: it is
      // authoritative about the message on some paths, and a silent substitution is exactly what
      // this round is the chance to catch.
      final echoed = Uint8List.fromList(c.messageToSign);
      if (!_sameBytes(echoed, message)) {
        throw CosignerException(
          'the cosigner intends to sign different bytes than were asked for',
        );
      }

      if (c.commitments.isEmpty) {
        throw CosignerException('the cosigner sent no commitment of its own');
      }

      // The share comes to exist here, and the nonce after it: a nonce is hedged with the share.
      final keyPkg = resolve(c.walletDealtShare);
      final round1 = frostRound1(keyPkg);
      final ours = keyPkg.identifier.toScalar().toRadixString(16);

      final round2 = frostRound2(
        commitments: {
          for (final e in c.commitments.entries)
            e.key: (hiding: e.value.hiding, binding: e.value.binding),
          ours: (hiding: round1.hiding, binding: round1.binding),
        },
        message: message,
        round1: round1,
        keyPkg: keyPkg,
        groupPubKey: groupPubKey,
        applyTweak: false,
      );

      duplex.send(cs.SignClientMsg(
        sessionId: '',
        seq: Int64(1),
        share: cs.SignShare(
          signatureShare: round2.share,
          hidingCommitment: round1.hiding,
          bindingCommitment: round1.binding,
        ),
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
