/// The phone's passkey, as the enclave gate's authenticator and as the share's blinding seed.
///
/// One credential does two jobs, and usually in one gesture:
///
///  * **Approval.** enclave-runtime gates every request on an assertion bound to that request, so
///    this implements app-core's [Authenticator] and [PasskeyRegistrar] over Credential Manager
///    ([PasskeyChannel]).
///  * **The seed.** Every assertion also evaluates the credential's PRF extension at a fixed salt.
///    The 32-byte output blinds the wallet's FROST share, so the share is only usable after a
///    gesture. Because the PRF rides on the approval's own assertion, a spend — approved, then
///    signed — asks for the fingerprint once, not twice.
///
/// **The PRF output never leaves the device.** The runtime neither asks for nor reads extension
/// outputs, and it is stripped from the credential before it is sent.
///
/// ## What has to be true outside this code
///
/// Credential Manager signs `clientDataJSON` with the origin `android:apk-key-hash:<hash>`, never
/// `https://<rp id>`: the unpadded base64url SHA-256 of the certificate the APK is signed with. So:
///
///  * **The enclave allows that origin.** Its image lists it in `webauthnAllowedOrigins`
///    (`--webauthn-allowed-origin`), one per signing key. It is measured by PCR0, so a new signing
///    key is a new image. For this app: the checked-in debug keystore
///    (`2D:FD:50:23…`) is `android:apk-key-hash:Lf1QIwQnlPBYPwDFhloUkYC-0tYAKSpKCQbEiyz118s`, and
///    the other fingerprint published for the app (`BB:5A:4D:7A…`, the release key, whose keystore
///    is not in this repo) is `android:apk-key-hash:u1pNepeObJUpSkSqH964HvFRqbhC_ejQP3GHA3-lreI`.
///    Releases go through Firebase App Distribution, which does not re-sign, so the release key is
///    the one that counts — were the app ever on Play, it would be Play's app signing key instead.
///  * **The relying party vouches for the app.** `https://vtxos.com/.well-known/assetlinks.json`
///    lists `com.vtxos.app` with both fingerprints and `get_login_creds`; Android refuses the app
///    passkeys for the domain without it.
///
/// A dev enclave's relying party is `enclave.test`, which serves no asset links, so a phone cannot
/// register against one; the e2e suite and the CLI use a software passkey instead.
///
/// ## Android notes
///
/// The options-JSON shape Credential Manager expects and where it reports PRF results vary by
/// Credential Manager / Play services version. See [_extractPrf].
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:app_core/enclave/authenticator.dart';
import 'package:app_core/passkey/seed_source.dart';
import 'package:crypto/crypto.dart' show sha256;
import 'package:flutter/services.dart' show PlatformException;

import 'passkey_channel.dart';

class PlatformPasskey implements Authenticator, PasskeyRegistrar {
  PlatformPasskey({required this.rpId, String? credentialId}) : _credentialId = credentialId;

  /// The relying party the credential is bound to.
  final String rpId;

  String? _credentialId;

  /// Set once registered — see [adopt].
  @override
  String get credentialId =>
      _credentialId ?? (throw StateError('no passkey registered yet'));

  bool get isRegistered => _credentialId != null;

  /// Take the credential id the runtime assigned at registration.
  void adopt(String credentialId) => _credentialId = credentialId;

  /// The PRF salt: a fixed context tag. A constant so the same passkey always yields the same seed,
  /// which is what makes the blinded share reconstructable.
  static final Uint8List _prfSalt =
      Uint8List.fromList(sha256.convert(utf8.encode('mpcwallet-prf-v1')).bytes);

  /// How long one gesture's seed stays usable. An Ark operation is a burst — the approval, then a
  /// stream of FROST rounds — and without this each round would prompt. Short, so the seed does not
  /// idle in memory.
  static const Duration _seedTtl = Duration(minutes: 2);

  Uint8List? _seed;
  DateTime? _seedExpiry;

  /// A local assertion in flight, shared, so concurrent seed requests make one prompt, not several.
  Future<Uint8List>? _inflight;

  /// Whether an operation started now would ride the cached seed with no prompt. Requires it to stay
  /// valid a while longer: a signing round takes seconds, and a seed expiring mid-round would pop
  /// the very prompt the caller checked this to avoid.
  bool get hasFreshSeed =>
      _seed != null &&
      _seedExpiry != null &&
      DateTime.now().add(const Duration(seconds: 30)).isBefore(_seedExpiry!);

  /// The share's blinding seed. See [PlatformPasskey].
  SeedSource get seedSource => _PrfSeedSource(this);

  @override
  Future<Map<String, dynamic>> createCredential(Map<String, dynamic> publicKey, String origin) async {
    final options = Map<String, dynamic>.from(publicKey);
    // A passkey, not a security-key credential. The runtime asks for `residentKey: "discouraged"`,
    // and Play services before Android 14 takes that literally: it creates a non-discoverable FIDO
    // key outside Google Password Manager, which One Tap — the sign-in path on those versions — never
    // searches, so every later assertion fails with "Cannot find a matching credential". The runtime
    // does not enforce the resident-key choice at verification (webauthn-rs ignores it), so asking
    // for a platform passkey here is the client's call to make.
    options['authenticatorSelection'] = {
      ...?(options['authenticatorSelection'] as Map?)?.cast<String, dynamic>(),
      'authenticatorAttachment': 'platform',
      'residentKey': 'required',
      'requireResidentKey': true,
      'userVerification': 'required',
    };
    // Enable PRF at creation. No eval here — the salt is evaluated at assertion time.
    options['extensions'] = {
      ...?(options['extensions'] as Map?)?.cast<String, dynamic>(),
      'prf': <String, dynamic>{},
    };
    final credential = jsonDecode(await PasskeyChannel.create(jsonEncode(options))) as Map<String, dynamic>;
    _stripPrf(credential);
    return credential;
  }

  @override
  Future<Map<String, dynamic>> assertion(Map<String, dynamic> publicKey, String origin) =>
      _get(publicKey);

  /// Wait until the passkey just registered can actually sign, and take its seed while at it.
  ///
  /// A provider indexes a new passkey asynchronously. Asking for it straight away — which the DKG
  /// that follows registration does — finds nothing, and Credential Manager answers with its "Sign in
  /// another way" sheet, from which there is no getting the passkey back. So this asks with
  /// `immediate`, which fails quietly while the passkey is not there yet, until it is. The one that
  /// succeeds is the user's fingerprint for setup, and leaves the PRF seed the DKG blinds the share
  /// with.
  Future<void> waitUntilUsable({Duration timeout = const Duration(seconds: 30)}) async {
    final deadline = DateTime.now().add(timeout);
    var delay = const Duration(milliseconds: 500);
    while (true) {
      try {
        await _get(_localRequest(), immediate: true);
        return;
      } on PlatformException catch (e) {
        if (e.code != PasskeyChannel.noCredential || DateTime.now().isAfter(deadline)) rethrow;
      }
      await Future<void>.delayed(delay);
      if (delay < const Duration(seconds: 3)) delay *= 2;
    }
  }

  /// An assertion request that goes nowhere: a challenge made here, for this credential.
  Map<String, dynamic> _localRequest() => {
        'challenge': _b64u(List<int>.generate(32, (_) => _random.nextInt(256))),
        'rpId': rpId,
        'allowCredentials': [
          {'type': 'public-key', 'id': credentialId},
        ],
        'userVerification': 'required',
        'timeout': 300000,
      };

  /// Assert against [publicKey] with the PRF evaluated, keep the seed, and return the credential
  /// with the PRF output removed.
  Future<Map<String, dynamic>> _get(Map<String, dynamic> publicKey, {bool immediate = false}) async {
    final options = Map<String, dynamic>.from(publicKey);
    options['extensions'] = {
      ...?(options['extensions'] as Map?)?.cast<String, dynamic>(),
      'prf': {
        'eval': {'first': _b64u(_prfSalt)},
      },
    };
    final credential =
        jsonDecode(await PasskeyChannel.get(jsonEncode(options), immediate: immediate)) as Map<String, dynamic>;
    _seed = _extractPrf(credential);
    _seedExpiry = DateTime.now().add(_seedTtl);
    _stripPrf(credential);
    return credential;
  }

  /// A seed without asking the enclave for anything: an assertion over a challenge made here, which
  /// goes nowhere. Only when no recent approval left one behind.
  Future<Uint8List> _deriveSeed() {
    final cached = _seed;
    if (cached != null && _seedExpiry != null && DateTime.now().isBefore(_seedExpiry!)) {
      return Future.value(cached);
    }
    return _inflight ??= () async {
      try {
        await _get(_localRequest());
        return _seed!;
      } finally {
        _inflight = null;
      }
    }();
  }

  /// `clientExtensionResults.prf.results.first`, base64url, 32 bytes.
  ///
  /// ON-DEVICE: some versions nest results differently; if this throws, log the extension results
  /// and adjust the path.
  static Uint8List _extractPrf(Map<String, dynamic> credential) {
    final results = credential['clientExtensionResults'];
    final prf = results is Map ? results['prf'] : null;
    final values = prf is Map ? prf['results'] : null;
    final first = values is Map ? values['first'] : null;
    if (first is! String) {
      throw StateError(
        'the passkey returned no PRF output. The authenticator must support PRF and the credential '
        'must have been created with it.',
      );
    }
    final seed = base64Url.decode(first + '=' * ((4 - first.length % 4) % 4));
    if (seed.length != 32) {
      throw StateError('the passkey PRF output is ${seed.length} bytes, not 32');
    }
    return Uint8List.fromList(seed);
  }

  /// The PRF output is the secret that unblinds the share. It must never be sent anywhere; the
  /// assertion's signature covers authenticator data and the client data hash, not this.
  static void _stripPrf(Map<String, dynamic> credential) {
    for (final key in ['clientExtensionResults', 'extensions']) {
      final results = credential[key];
      if (results is Map) results.remove('prf');
    }
  }

  static final _random = Random.secure();
  static String _b64u(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
}

class _PrfSeedSource implements SeedSource {
  _PrfSeedSource(this._passkey);
  final PlatformPasskey _passkey;

  @override
  Future<Uint8List> deriveSeed() => _passkey._deriveSeed();
}
