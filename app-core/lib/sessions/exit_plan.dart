/// What the wallet checks before it signs an exit, and before it keeps one.
///
/// The cosigner builds the exit transactions and asks the wallet for its half of the signature. A
/// wallet that just signed whatever arrived would be a signing oracle for its own key: the round
/// could as easily be a transaction paying somebody else. So the wallet builds the same exits from
/// what it independently knows — the VTXOs it told the cosigner it holds, its own exit address, the
/// ASP's delays — and signs only if every sighash matches, in order. On the way back it checks each
/// returned transaction is that same transaction, signed.
///
/// The order is the order the VTXOs were sent in, minus any too small to leave a non-dust output,
/// which the cosigner skips and so does this.
library;

import 'package:app_core/ark/exit.dart' as ark_exit;
import 'package:app_core/asp/ark_info.dart';
import 'package:app_core/cosigner/connection.dart';
import 'package:protocol/cosigner_v1.dart' as cs;

/// One kept exit: a complete transaction, and what it is for.
class ExitTx {
  ExitTx({
    required this.outpoint,
    required this.txid,
    required this.rawTx,
    required this.sequence,
    required this.amountSats,
    required this.destination,
    required this.issuedAt,
  });

  factory ExitTx.fromJson(Map<String, dynamic> j) => ExitTx(
        outpoint: j['outpoint'] as String,
        txid: j['txid'] as String? ?? '',
        rawTx: j['rawTx'] as String,
        sequence: (j['sequence'] as num).toInt(),
        amountSats: (j['amountSats'] as num).toInt(),
        destination: j['destination'] as String? ?? '',
        issuedAt: DateTime.fromMillisecondsSinceEpoch((j['issuedAt'] as num).toInt() * 1000),
      );

  Map<String, dynamic> toJson() => {
        'outpoint': outpoint,
        'txid': txid,
        'rawTx': rawTx,
        'sequence': sequence,
        'amountSats': amountSats,
        'destination': destination,
        'issuedAt': issuedAt.millisecondsSinceEpoch ~/ 1000,
      };

  /// The VTXO it spends, `txid:vout`.
  final String outpoint;

  /// Its own txid — what to look for on-chain once it is broadcast.
  final String txid;

  /// The whole transaction, hex. Nothing else is needed to broadcast it — though it pays no fee,
  /// so it needs a child spending its anchor to be mined.
  final String rawTx;

  /// Its nSequence: the VTXO's exit delay. It cannot be mined until that long after the
  /// transaction that created the VTXO confirms.
  final int sequence;

  /// What it pays out, which is the whole VTXO.
  final int amountSats;

  /// The scriptPubKey it pays — the wallet's exit address at the time it was issued.
  final String destination;

  final DateTime issuedAt;
}

/// The exits a seal is about to sign, from the wallet's side.
class ExitPlan {
  ExitPlan({
    required this.ownerXOnlyHex,
    required ArkInfo info,
    required this.destinationScriptPubkeyHex,
    required List<IndexerVtxo> vtxos,
  }) : _spends = _build(ownerXOnlyHex, info, destinationScriptPubkeyHex, vtxos);

  static List<(String, ark_exit.ExitSpend)> _build(
    String ownerXOnlyHex,
    ArkInfo info,
    String destination,
    List<IndexerVtxo> vtxos,
  ) {
    final spends = <(String, ark_exit.ExitSpend)>[];
    for (final v in vtxos) {
      try {
        spends.add((
          '${v.txid}:${v.vout}',
          ark_exit.buildExitTx(
            ownerXOnlyHex: ownerXOnlyHex,
            aspPubkeyHex: info.signerPubkey,
            network: info.network,
            txid: v.txid,
            vout: v.vout,
            amountSats: v.amountSats,
            exitDelay: v.exitDelay,
            destinationScriptPubkeyHex: destination,
          )
        ));
      } catch (_) {
        // Dust, or anything else that cannot be exited. The cosigner skips it too; the wallet
        // shows it as uncovered rather than failing the seal over it.
      }
    }
    return spends;
  }

  /// A wallet with no exit address yet: nothing expected, nothing accepted. Its `checkAsked` is
  /// what refuses a cosigner that sends exit sighashes nobody asked it to build.
  static final ExitPlan none = ExitPlan._none();

  ExitPlan._none()
      : ownerXOnlyHex = '',
        destinationScriptPubkeyHex = '',
        _spends = const [];

  final String ownerXOnlyHex;
  final String destinationScriptPubkeyHex;
  final List<(String, ark_exit.ExitSpend)> _spends;

  bool get isEmpty => _spends.isEmpty;

  /// The sighashes this wallet expects to be asked for, in order.
  List<List<int>> get sighashes =>
      [for (final (_, s) in _spends) _hexBytes(s.sighash)];

  /// What the cosigner asked for must be what this wallet built. Throws otherwise, which abandons
  /// the seal — the delegate included, because a cosigner asking for the wrong exits is not one to
  /// finish a round with.
  void checkAsked(List<List<int>> asked) {
    final expected = sighashes;
    if (asked.length != expected.length) {
      throw CosignerException(
        'the cosigner asked for ${asked.length} exit signatures, and this wallet has '
        '${expected.length} exits to sign',
      );
    }
    for (var i = 0; i < expected.length; i++) {
      if (!_sameBytes(asked[i], expected[i])) {
        throw CosignerException(
          'the cosigner asked this wallet to sign something other than the exit of '
          '${_spends[i].$1}',
        );
      }
    }
  }

  /// Check what came back and turn it into what the wallet keeps.
  List<ExitTx> accept(List<cs.ExitTx> returned) {
    if (returned.length != _spends.length) {
      throw CosignerException(
        'the seal returned ${returned.length} exits for ${_spends.length} signed',
      );
    }
    final now = DateTime.now();
    final kept = <ExitTx>[];
    for (var i = 0; i < returned.length; i++) {
      final (outpoint, spend) = _spends[i];
      final exit = returned[i];
      if (exit.outpoint != outpoint) {
        throw CosignerException('the seal returned an exit for ${exit.outpoint}, not $outpoint');
      }
      final rawTx = _hex(exit.rawTx);
      // The whole check: same transaction, signed by this wallet's key, over the sighash it built.
      // Its identity comes out of that same parse rather than from what the cosigner said it was.
      final txid = ark_exit.verifyExitTx(
          spend: spend, ownerXOnlyHex: ownerXOnlyHex, rawTxHex: rawTx);
      kept.add(ExitTx(
        outpoint: outpoint,
        txid: txid,
        rawTx: rawTx,
        sequence: spend.sequence,
        amountSats: exit.amountSats.toInt(),
        destination: destinationScriptPubkeyHex,
        issuedAt: now,
      ));
    }
    return kept;
  }
}

List<int> _hexBytes(String hex) => [
      for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16),
    ];

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
