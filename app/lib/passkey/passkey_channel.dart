import 'package:flutter/services.dart';

/// Thin Dart wrapper over the Android `PasskeyPlugin` (Jetpack Credential
/// Manager). Both methods take a WebAuthn options JSON string and return the
/// corresponding response JSON string produced by the authenticator.
///
/// Android-only: on other platforms `invokeMethod` throws a
/// [MissingPluginException]; callers gate on `Platform.isAndroid`.
class PasskeyChannel {
  static const _ch = MethodChannel('com.mpcwallet.ap/passkey');

  static int _prompts = 0;

  /// Whether a passkey prompt is up. Its sheet can hide the app, and that is not the owner leaving.
  static bool get prompting => _prompts > 0;

  static Future<String> _prompt(String method, Map<String, Object> arguments) async {
    _prompts++;
    try {
      return (await _ch.invokeMethod<String>(method, arguments))!;
    } finally {
      _prompts--;
    }
  }

  /// WebAuthn registration (create a passkey). Returns registrationResponseJson.
  static Future<String> create(String requestJson) =>
      _prompt('create', {'requestJson': requestJson});

  /// WebAuthn assertion (use a passkey). Returns authenticationResponseJson.
  ///
  /// With [immediate], a passkey that is not usable right now fails fast with [noCredential]
  /// rather than showing the "Sign in another way" sheet.
  static Future<String> get(String requestJson, {bool immediate = false}) =>
      _prompt('get', {'requestJson': requestJson, 'immediate': immediate});

  /// The error code for "no passkey on this device matches the request".
  static const noCredential = 'passkey_no_credential';

  /// The error code for the user dismissing the prompt.
  static const cancelled = 'passkey_cancelled';
}
