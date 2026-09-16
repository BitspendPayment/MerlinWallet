/// Signing a WebAuthn assertion, so a request can reach the guest.
///
/// enclave-runtime gates every request on an assertion bound to that exact method and path — see
/// [EnclaveGate]. Who signs it differs by platform: a phone uses its secure element, and a test
/// cannot. Both shapes are the same three fields, so both live behind [Authenticator].
///
/// The bytes here are not an approximation of what a platform authenticator produces; they are the
/// same bytes. `clientDataJSON`, the authenticator-data layout and the ECDSA signature are all
/// mirrored from enclave-runtime's own `SoftwareAuthenticator`, which is what its test suite and
/// its QEMU harness sign with. Anything looser would pass here and fail against a real device.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:blockchain_utils/blockchain_utils.dart';
import 'package:crypto/crypto.dart' as crypto;

/// Authenticator-data flags, as the specification names them.
class AuthFlags {
  /// User present — someone touched it.
  static const int up = 0x01;

  /// User verified — a biometric or a PIN, not merely presence. The runtime asks for
  /// `userVerification: "required"`, so an assertion without this is refused: a cosigner's
  /// approval is meant to mean a person did something.
  static const int uv = 0x04;
}

/// Something that can answer a WebAuthn challenge.
abstract class Authenticator {
  /// The credential this will assert as, base64url without padding.
  String get credentialId;

  /// Answer [publicKey] — the `PublicKeyCredentialRequestOptions` the runtime issued, whose
  /// `challenge` is base64url — for [origin], returning the `PublicKeyCredential` JSON a browser's
  /// `navigator.credentials.get()` would produce.
  ///
  /// The whole options object rather than the challenge alone, because a platform authenticator is
  /// handed exactly that, and may add to it: the app evaluates its PRF extension in the same gesture.
  /// Whatever it adds must not go back out — the runtime ignores extension outputs, and a PRF output
  /// is a secret.
  Future<Map<String, dynamic>> assertion(Map<String, dynamic> publicKey, String origin);
}

/// Something that can create a passkey.
abstract class PasskeyRegistrar {
  /// Create a credential for [publicKey] — the `PublicKeyCredentialCreationOptions` the runtime
  /// issued — claiming [origin], returning the `RegisterPublicKeyCredential` JSON.
  Future<Map<String, dynamic>> createCredential(Map<String, dynamic> publicKey, String origin);
}

/// A passkey in software, for tests and harnesses.
///
/// **Not for production.** It holds a private key in memory that a real authenticator would never
/// release, which is the whole reason a platform authenticator exists.
///
/// It reads the state file `passkey-client` writes, so enrolment — the one step that needs CBOR,
/// for the attestation object — stays in the tool that already does it, and this only ever asserts.
class SoftwareAuthenticator implements Authenticator {
  SoftwareAuthenticator({
    required this.rpId,
    required String credentialId,
    required List<int> privateKeyPkcs8,
    int counter = 0,
    this.onCounter,
  })  : _credentialId = credentialId,
        _signer = Nist256p1Signer.fromKeyBytes(_scalarFromPkcs8(privateKeyPkcs8)),
        _counter = counter;

  /// Restore the passkey `passkey-client --state <file>` persisted.
  ///
  /// The counter comes back with it, deliberately. An authenticator that restarted at zero would
  /// present a count no higher than the one registration recorded, and a relying party is entitled
  /// to read that as a cloned credential — which is exactly what it is guarding against.
  factory SoftwareAuthenticator.fromStateJson(
    String json, {
    required String rpId,
    void Function(int counter)? onCounter,
  }) {
    final state = jsonDecode(json) as Map<String, dynamic>;
    return SoftwareAuthenticator(
      rpId: rpId,
      credentialId: state['credential_id'] as String,
      privateKeyPkcs8: _b64uDecode(state['key_pkcs8'] as String),
      counter: (state['counter'] as num?)?.toInt() ?? 0,
      onCounter: onCounter,
    );
  }

  /// The relying party this passkey is bound to — `enclave.test` for the dev enclave. Hashed into
  /// every assertion, so the wrong one produces a signature over the wrong message.
  final String rpId;

  final String _credentialId;
  final Nist256p1Signer _signer;
  int _counter;

  /// Called with each new counter value, for a caller that persists the state file.
  final void Function(int counter)? onCounter;

  @override
  String get credentialId => _credentialId;

  int get counter => _counter;

  @override
  Future<Map<String, dynamic>> assertion(Map<String, dynamic> publicKey, String origin) async {
    // Echoed into `clientDataJSON` as the string it arrived as, never re-encoded.
    final challenge = publicKey['challenge'] as String;
    final clientData = _clientData('webauthn.get', challenge, origin);
    final authData = _authenticatorData(AuthFlags.up | AuthFlags.uv);
    final signature = _sign(authData, clientData);

    return {
      'id': _credentialId,
      'rawId': _credentialId,
      'type': 'public-key',
      'extensions': <String, dynamic>{},
      'response': {
        'authenticatorData': _b64u(authData),
        'clientDataJSON': _b64u(clientData),
        'signature': _b64u(signature),
        'userHandle': null,
      },
    };
  }

  /// `sha256(rpId) ‖ flags ‖ counter`, big-endian.
  Uint8List _authenticatorData(int flags) {
    _counter += 1;
    onCounter?.call(_counter);
    final out = BytesBuilder()
      ..add(crypto.sha256.convert(utf8.encode(rpId)).bytes)
      ..addByte(flags)
      ..add(Uint8List(4)..buffer.asByteData().setUint32(0, _counter, Endian.big));
    return out.toBytes();
  }

  /// Field order is the authenticator's to choose and a relying party must not depend on it, so
  /// this is written out rather than composed — the same order enclave-runtime's fixture uses, for
  /// no reason other than that a byte-for-byte match is easy to check.
  Uint8List _clientData(String kind, String challenge, String origin) => Uint8List.fromList(
        utf8.encode(
          '{"type":"$kind","challenge":"$challenge","origin":"$origin","crossOrigin":false}',
        ),
      );

  /// ES256 over `authenticatorData ‖ sha256(clientDataJSON)`, ASN.1 DER.
  Uint8List _sign(Uint8List authenticatorData, Uint8List clientData) {
    final message = BytesBuilder()
      ..add(authenticatorData)
      ..add(crypto.sha256.convert(clientData).bytes);
    // `hashMessage: true` makes this SHA-256-then-sign, which is what ES256 means.
    final raw = _signer.sign(message.toBytes(), hashMessage: true);
    return _derFromRaw(raw);
  }
}

/// The 32-byte private scalar out of a PKCS#8 P-256 key.
///
/// A full ASN.1 parser would be the general answer; this walks the one structure that arrives.
/// `PrivateKeyInfo` wraps an `ECPrivateKey`, whose second field is the scalar as a 32-byte OCTET
/// STRING — so the last `04 20` followed by 32 bytes, reached before the optional public-key
/// field, is it. Anything else is refused rather than guessed at, because a key read wrong here
/// signs perfectly well and is rejected by the relying party with nothing to say why.
List<int> _scalarFromPkcs8(List<int> pkcs8) {
  for (var i = 0; i + 34 <= pkcs8.length; i++) {
    if (pkcs8[i] == 0x04 && pkcs8[i + 1] == 0x20) {
      // The scalar sits inside the inner ECPrivateKey SEQUENCE, which follows `02 01 01`
      // (version 1). Requiring that prefix is what keeps this from matching the 32-byte OCTET
      // STRING of some other field.
      if (i >= 3 && pkcs8[i - 3] == 0x02 && pkcs8[i - 2] == 0x01 && pkcs8[i - 1] == 0x01) {
        return pkcs8.sublist(i + 2, i + 34);
      }
    }
  }
  throw ArgumentError('not a PKCS#8 P-256 private key: no version-1 ECPrivateKey scalar in it');
}

/// `SEQUENCE { INTEGER r, INTEGER s }` from a raw `r ‖ s`.
///
/// WebAuthn's ES256 signature is DER; `Nist256p1Signer` returns the fixed-width pair, so this is
/// the last step. Each integer is minimal two's complement: leading zero bytes dropped, and one
/// `0x00` put back when the top bit would otherwise read as a negative number.
Uint8List _derFromRaw(List<int> raw) {
  if (raw.length != 64) {
    throw ArgumentError('expected a 64-byte r‖s signature, got ${raw.length}');
  }
  final body = BytesBuilder()
    ..add(_derInteger(raw.sublist(0, 32)))
    ..add(_derInteger(raw.sublist(32, 64)));
  final bytes = body.toBytes();
  return Uint8List.fromList([0x30, bytes.length, ...bytes]);
}

Uint8List _derInteger(List<int> value) {
  var start = 0;
  while (start < value.length - 1 && value[start] == 0) {
    start++;
  }
  var trimmed = value.sublist(start);
  if (trimmed[0] & 0x80 != 0) {
    trimmed = [0x00, ...trimmed];
  }
  return Uint8List.fromList([0x02, trimmed.length, ...trimmed]);
}

String _b64u(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

List<int> _b64uDecode(String s) =>
    base64Url.decode(s.padRight(s.length + ((4 - s.length % 4) % 4), '='));
