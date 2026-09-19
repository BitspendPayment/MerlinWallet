/// The wallet's key material, from the passkey and nothing else.
///
/// These are the properties recovery rests on: the same passkey gives the same wallet, a different
/// one gives a different wallet, and no two purposes share a secret.
@Tags(['ffi'])
library;

import 'dart:typed_data';

import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;
import 'package:test/test.dart';

Uint8List seed(int fill) => Uint8List.fromList(List.filled(32, fill));

void main() {
  test('the same passkey gives the same polynomial, every time', () async {
    final first = await walletPolynomial(seed(7));
    final second = await walletPolynomial(seed(7));
    expect(first.a0.scalar, second.a0.scalar);
    expect(first.a1, second.a1);
  });

  /// The identifier is derived from a0's public point, so it reproduces too — and it has to, since
  /// the cosigner refuses a recovery whose identifier is not the one it sealed.
  test('the identifier reproduces with the polynomial', () async {
    threshold.Identifier identifierFor(threshold.SecretKey a0) =>
        threshold.Identifier.derive(
            threshold.elemSerializeCompressed(threshold.elemBaseMul(a0.scalar)));

    final a = await walletPolynomial(seed(7));
    final b = await walletPolynomial(seed(7));
    expect(identifierFor(a.a0).toScalar(), identifierFor(b.a0).toScalar());

    final other = await walletPolynomial(seed(8));
    expect(identifierFor(other.a0).toScalar(), isNot(identifierFor(a.a0).toScalar()));
  });

  test('a different passkey is a different wallet', () async {
    final mine = await walletPolynomial(seed(7));
    final theirs = await walletPolynomial(seed(8));
    expect(mine.a0.scalar, isNot(theirs.a0.scalar));
    expect(mine.a1, isNot(theirs.a1));
  });

  /// One seed, three purposes: each must be independent of the others. A blinding factor that
  /// equalled the secret it blinds would hide nothing.
  test('the labels give independent scalars', () async {
    final polynomial = await walletPolynomial(seed(7));
    final blind = await blindingScalar(seed(7));
    expect(polynomial.a0.scalar, isNot(polynomial.a1));
    expect(polynomial.a0.scalar, isNot(blind));
    expect(polynomial.a1, isNot(blind));
  });

  test('the blinding scalar reproduces, or nothing could be unblinded', () async {
    expect(await blindingScalar(seed(3)), await blindingScalar(seed(3)));
    expect(await blindingScalar(seed(3)), isNot(await blindingScalar(seed(4))));
  });

  /// Scalars have to be in range and usable: zero is not a key, and anything at or above the curve
  /// order is not a scalar.
  test('every derived scalar is a usable one', () async {
    for (var fill = 0; fill < 8; fill++) {
      final polynomial = await walletPolynomial(seed(fill));
      for (final scalar in [polynomial.a0.scalar, polynomial.a1, await blindingScalar(seed(fill))]) {
        expect(scalar, greaterThan(BigInt.zero));
        expect(scalar, lessThan(threshold.secp256k1Curve.n));
      }
    }
  });
}
