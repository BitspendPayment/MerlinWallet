import 'package:flutter/services.dart';

/// Thin Dart wrapper over the Android `PasskeyPlugin` (Jetpack Credential
/// Manager). Both methods take a WebAuthn options JSON string and return the
/// corresponding response JSON string produced by the authenticator.
///
/// Android-only: on other platforms `invokeMethod` throws a
/// [MissingPluginException]; callers gate on `Platform.isAndroid`.
class PasskeyChannel {
  static const _ch = MethodChannel('com.mpcwallet.ap/passkey');

  /// WebAuthn registration (create a passkey). Returns registrationResponseJson.
  static Future<String> create(String requestJson) async =>
      (await _ch.invokeMethod<String>('create', {'requestJson': requestJson}))!;

  /// WebAuthn assertion (use a passkey). Returns authenticationResponseJson.
  ///
  /// With [immediate], a passkey that is not usable right now fails fast with [noCredential]
  /// rather than showing the "Sign in another way" sheet.
  static Future<String> get(String requestJson, {bool immediate = false}) async =>
      (await _ch.invokeMethod<String>('get', {'requestJson': requestJson, 'immediate': immediate}))!;

  /// The error code for "no passkey on this device matches the request".
  static const noCredential = 'passkey_no_credential';

  /// The error code for the user dismissing the prompt.
  static const cancelled = 'passkey_cancelled';
}
