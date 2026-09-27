/// The phone's passkey, as the enclave gate's authenticator and as the wallet's seed.
///
/// One credential does two jobs, and for an operation that signs, in one gesture:
///
///  * **Approval.** enclave-runtime gates every request on an assertion bound to that request, so
///    this implements app-core's [Authenticator] and [PasskeyRegistrar] over Credential Manager
///    ([PasskeyChannel]).
///  * **The seed.** The credential's PRF extension, evaluated at a fixed salt, gives 32 bytes the
///    wallet's half of its FROST share is derived from — again for every operation, because no
///    share is kept on the device. The PRF rides on the approval's own assertion, so a spend asks
///    for the fingerprint once, not twice.
///
/// ## The seed is handed over, not kept
///
/// The PRF is evaluated **only** for an assertion made inside [SeedSource.seedDuring], and its
/// output goes to the one caller that asked and nowhere else. Approving an escrow list, finding a
/// passkey, checking one still works: none of those evaluates the PRF at all.
///
/// It used to be evaluated on every assertion and kept for two minutes, so that the several FROST
/// rounds of one send would not each prompt. That made a clock the only limit on the seed's life,
/// and let any approval leave one behind. The rounds of an operation now share the *share* it
/// rebuilt, inside the operation (`app_core/passkey/operation_secrets.dart`); nothing here outlives
/// the call that asked for it.
///
/// What this cannot do is scrub the platform's own copies: the output crosses the platform channel
/// as base64 inside a JSON string, and Dart strings are immutable. The bytes this class decodes
/// are handed to a caller that overwrites them; the string they came from is the garbage
/// collector's.
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
  void adopt(String credentialId) {
    _credentialId = credentialId;
    _justRegistered = true;
  }

  /// Registered moments ago and not used yet — see [assertion].
  bool _justRegistered = false;

  /// The PRF salt: a fixed context tag. A constant so the same passkey always yields the same seed,
  /// which is what makes the wallet's key derivable again — tomorrow, and on another phone.
  static final Uint8List _prfSalt =
      Uint8List.fromList(sha256.convert(utf8.encode('mpcwallet-prf-v1')).bytes);

  /// The [SeedSource.seedDuring] in progress, if there is one: where the next assertion's PRF
  /// output goes. Null almost always, and while it is, no assertion evaluates the PRF.
  _SeedCapture? _capture;

  /// The wallet's seed. See [PlatformPasskey].
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

  /// The gate's approval — with the PRF evaluated in the same gesture.
  ///
  /// The first one after registering waits for the passkey to become findable, retrying quietly: a
  /// provider indexes a new passkey asynchronously, and asking too soon opens Credential Manager's
  /// "Sign in another way" sheet, from which there is no getting it back. Folding that wait into the
  /// first real approval, rather than a sign-in of its own beforehand, is what makes onboarding one
  /// fingerprint instead of two.
  @override
  Future<Map<String, dynamic>> assertion(Map<String, dynamic> publicKey, String origin) async {
    if (!_justRegistered) return _get(publicKey);
    final credential = await _whenFindable(() => _get(publicKey, immediate: true));
    _justRegistered = false;
    return credential;
  }

  Future<T> _whenFindable<T>(Future<T> Function() attempt,
      {Duration timeout = const Duration(seconds: 30)}) async {
    final deadline = DateTime.now().add(timeout);
    var delay = const Duration(milliseconds: 500);
    while (true) {
      try {
        return await attempt();
      } on PlatformException catch (e) {
        if (e.code != PasskeyChannel.noCredential || DateTime.now().isAfter(deadline)) rethrow;
      }
      await Future<void>.delayed(delay);
      if (delay < const Duration(seconds: 3)) delay *= 2;
    }
  }

  /// Find this app's passkey on a device that has never seen it, and become it.
  ///
  /// A wiped install knows the relying party and nothing else, but the gate's every call names a
  /// credential id. So this asks for an assertion with **no** `allowCredentials`: the platform lists
  /// the discoverable passkeys it holds for [rpId], the owner picks one, and its id is what the gate
  /// needs. Passkeys here are created discoverable for exactly this reason
  /// (`residentKey: required` — see [createCredential]).
  ///
  /// The assertion goes nowhere: the challenge is made here and the signature is thrown away. What
  /// is kept is the credential id, and only that — the PRF is not evaluated. The seed is taken by
  /// the `Recover` call that follows, from the gesture that approves it, so nothing secret sits in
  /// memory between the two.
  ///
  /// Throws [PasskeyChannel.noCredential] when the device holds none, which is the honest answer to
  /// "restore my wallet" on a phone the passkey never synced to.
  Future<String> discover() async {
    final credential = await _get({
      'challenge': _b64u(List<int>.generate(32, (_) => _random.nextInt(256))),
      'rpId': rpId,
      // No `allowCredentials`: that is the whole point.
      'userVerification': 'required',
      'timeout': 300000,
    });
    final id = credential['id'] ?? credential['rawId'];
    if (id is! String || id.isEmpty) {
      throw StateError('the passkey returned no credential id to recover with');
    }
    _credentialId = id;
    // Not newly registered: it is already findable, or it would not have answered.
    _justRegistered = false;
    return id;
  }

  /// Check that a stored passkey can still sign on this device, with a sign-in of its own that goes
  /// nowhere. Fails quietly with [PasskeyChannel.noCredential] while it cannot, until [timeout].
  /// A fingerprint — only for recovering an onboarding that stopped part-way.
  Future<void> waitUntilUsable({Duration timeout = const Duration(seconds: 30)}) =>
      _whenFindable(() => _get(_localRequest(), immediate: true), timeout: timeout);

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

  /// Assert against [publicKey] and return the credential, with any PRF output removed.
  ///
  /// The PRF is evaluated only while a [seedDuring] is waiting for one, and its output goes to
  /// that capture. Any other assertion does not ask for it, so there is nothing to keep.
  Future<Map<String, dynamic>> _get(Map<String, dynamic> publicKey, {bool immediate = false}) async {
    final capture = _capture;
    final wantSeed = capture != null && !capture.filled;
    final options = Map<String, dynamic>.from(publicKey);
    if (wantSeed) {
      options['extensions'] = {
        ...?(options['extensions'] as Map?)?.cast<String, dynamic>(),
        'prf': {
          'eval': {'first': _b64u(_prfSalt)},
        },
      };
    }
    final credential =
        jsonDecode(await PasskeyChannel.get(jsonEncode(options), immediate: immediate)) as Map<String, dynamic>;
    try {
      // Still the capture that asked: one that gave up while the prompt was showing gets nothing.
      if (wantSeed && identical(_capture, capture)) capture.fill(_extractPrf(credential));
    } finally {
      _stripPrf(credential);
    }
    return credential;
  }

  /// The seed for one operation, taken from the gesture that approves it.
  ///
  /// [approve] is the gate minting the operation's token, which asserts — and that assertion, made
  /// while the capture is armed, evaluates the PRF. If [approve] asserted nothing (no gate in
  /// front of this cosigner), one local assertion that goes nowhere asks for the seed by itself.
  ///
  /// One at a time: `MpcClient` serializes the operations that sign, and a second capture while
  /// one is armed would be two callers expecting the same gesture's output.
  Future<Uint8List> _seedDuring(Future<void> Function() approve) async {
    if (_capture != null) {
      throw StateError('a seed is already being taken for another operation');
    }
    final capture = _capture = _SeedCapture();
    try {
      await approve();
      if (!capture.filled) await _get(_localRequest());
      return capture.take();
    } finally {
      _capture = null;
      // Whatever was captured and not taken — the approval succeeded and something after it threw.
      capture.discard();
    }
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

  /// The PRF output is the secret the wallet's key is derived from. It must never be sent
  /// anywhere; the assertion's signature covers authenticator data and the client data hash, not
  /// this.
  static void _stripPrf(Map<String, dynamic> credential) {
    for (final key in ['clientExtensionResults', 'extensions']) {
      final results = credential[key];
      if (results is Map) results.remove('prf');
    }
  }

  static final _random = Random.secure();
  static String _b64u(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
}

/// One seed on its way from an assertion to the operation that asked for it.
class _SeedCapture {
  Uint8List? _seed;

  bool get filled => _seed != null;

  void fill(Uint8List seed) => _seed = seed;

  /// The seed, handed over: this holds it no longer, and the caller overwrites it when done.
  Uint8List take() {
    final seed = _seed;
    if (seed == null) throw StateError('the passkey returned no seed');
    _seed = null;
    return seed;
  }

  void discard() {
    _seed?.fillRange(0, 32, 0);
    _seed = null;
  }
}

class _PrfSeedSource implements SeedSource {
  _PrfSeedSource(this._passkey);
  final PlatformPasskey _passkey;

  @override
  Future<Uint8List> seedDuring(Future<void> Function() approve) => _passkey._seedDuring(approve);
}
