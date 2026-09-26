/// What the wallet checks before signing an exit, and before keeping one.
///
/// The point of these: a cosigner that asks for a signature over something other than this
/// wallet's own exit gets refused, and so does one that hands back a different transaction.
@Tags(['ffi'])
library;

import 'package:app_core/ark/exit.dart' as ark_exit;
import 'package:app_core/asp/ark_info.dart';
import 'package:app_core/cosigner/connection.dart';
import 'package:app_core/sessions/exit_plan.dart';
import 'package:fixnum/fixnum.dart';
import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:test/test.dart';

const owner = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const asp = '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';
final destination = '5120${'ab' * 32}';
final elsewhere = '5120${'cd' * 32}';

const info = ArkInfo(
  signerPubkey: asp,
  forfeitPubkey: asp,
  forfeitAddress: '',
  checkpointTapscript: '',
  network: 'regtest',
  sessionDuration: 0,
  unilateralExitDelay: 86016,
  boardingExitDelay: 172032,
  vtxoMinAmount: 1,
  dust: 330,
);

IndexerVtxo vtxo(String txid, int amount, {int delay = 86016}) => IndexerVtxo(
      txid: txid,
      vout: 0,
      amountSats: amount,
      script: '',
      isSpent: false,
      createdAt: 0,
      expiresAt: 0,
      exitDelay: delay,
    );

ExitPlan plan(List<IndexerVtxo> vtxos, {String? to}) => ExitPlan(
      ownerXOnlyHex: owner,
      info: info,
      destinationScriptPubkeyHex: to ?? destination,
      vtxos: vtxos,
    );

void main() {
  final vtxos = [vtxo('a' * 64, 130000), vtxo('b' * 64, 50000)];

  test('the wallet expects one sighash per VTXO, and its own', () {
    final p = plan(vtxos);
    expect(p.sighashes, hasLength(2));
    p.checkAsked(p.sighashes);
  });

  test('a VTXO too small to exit is skipped, as the cosigner skips it', () {
    final p = plan([...vtxos, vtxo('c' * 64, 200)]);
    expect(p.sighashes, hasLength(2));
  });

  test('being asked to sign something else is refused', () {
    final p = plan(vtxos);
    final tampered = [p.sighashes.first, List<int>.filled(32, 7)];
    expect(() => p.checkAsked(tampered), throwsA(isA<CosignerException>()));
  });

  test('being asked for a different number of signatures is refused', () {
    final p = plan(vtxos);
    expect(() => p.checkAsked([p.sighashes.first]), throwsA(isA<CosignerException>()));
    expect(() => p.checkAsked([]), throwsA(isA<CosignerException>()));
  });

  /// A wallet with no exit address must not be talked into signing exits it never asked for.
  test('a wallet with no exit address expects no exit sighashes at all', () {
    expect(
      () => ExitPlan.none.checkAsked([List<int>.filled(32, 1)]),
      throwsA(isA<CosignerException>()),
    );
    ExitPlan.none.checkAsked([]);
  });

  /// The exit the wallet keeps has to be the one it signed — the signature is checked against the
  /// wallet's own key, over its own sighash.
  test('an exit paying somewhere else is refused, however well formed', () {
    final p = plan([vtxos.first]);
    final other = plan([vtxos.first], to: elsewhere);
    // A transaction built for another destination, dressed up as the answer to ours.
    final raw = ark_exit.finalizeExitTx(
      spend: ark_exit.buildExitTx(
        ownerXOnlyHex: owner,
        aspPubkeyHex: asp,
        network: 'regtest',
        txid: 'a' * 64,
        vout: 0,
        amountSats: 130000,
        exitDelay: 86016,
        destinationScriptPubkeyHex: elsewhere,
      ),
      signatureHex: 'cd' * 64,
    );
    expect(other.sighashes.first, isNot(p.sighashes.first));
    expect(
      () => p.accept([
        cs.ExitTx(
          outpoint: '${'a' * 64}:0',
          rawTx: [for (var i = 0; i < raw.length; i += 2) int.parse(raw.substring(i, i + 2), radix: 16)],
          sequence: 0,
          amountSats: Int64(130000),
        )
      ]),
      throwsA(anything),
    );
  });

  test('an exit for a VTXO nobody signed for is refused', () {
    final p = plan([vtxos.first]);
    expect(
      () => p.accept([cs.ExitTx(outpoint: '${'z' * 64}:9', rawTx: const [], sequence: 0)]),
      throwsA(isA<CosignerException>()),
    );
  });
}
