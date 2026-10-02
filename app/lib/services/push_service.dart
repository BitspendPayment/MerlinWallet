/// FCM push handling.
///
/// Initializes Firebase and hands the device token — and each FCM rotation of
/// it — to [MpcService.offerDeviceToken], which has the cosigner enrol it on the
/// next call the user makes anyway. There is no enrolment call of its own: every
/// cosigner call is a passkey approval.
///
/// # A wake carries nothing
///
/// The runtime sends **data-only** messages — no title, no body, no
/// `notification` object, not behind a flag. Its payload is
/// `{"v": "1", "category": "...", "ref": "..."}` and that is all. The reason is
/// that an FCM payload travels through the parent instance and then through
/// Google, which are the two parties an enclave exists to exclude, so nothing
/// readable goes in it: the app wakes and fetches the detail over its own
/// connection.
///
/// Two consequences, both load-bearing here:
///
///  * **The OS displays nothing.** A `notification` block is rendered without
///    the app running, so a wake carrying one would show text and fail to wake
///    anything. [_handleBackgroundMessage] is the only thing that runs.
///  * **The key is `category`, not `type`.** Every handler in this file used to
///    read `msg.data['type']`, which the runtime never sets — so every one of
///    them early-returned and the whole push path was dead.
///
/// Safe to call on platforms or builds without Firebase config: any
/// initialization error is logged and the rest of the app continues without
/// push (the foreground refresh still catches up for users who open the app).
library;

import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';

import '../firebase_options.dart';
import 'mpc_service.dart';

class PushService {
  static bool _initialized = false;

  /// The live, logged-in service. Set by [onLoggedIn] so the foreground push
  /// handler can refresh while the app is open.
  static MpcService? _svc;

  /// The cosigner's watch found its sealed delegate due and could not run it
  /// itself — no ASP reachable, or the round failed — so it woke its owner to
  /// refresh in person. Mirrors `CATEGORY_SETTLE_DUE` in
  /// `cosigner/src/handlers/watch.rs`.
  static const String categorySettleDue = 'settle-due';

  /// The cosigner ran its sealed delegate: the funds were refreshed, and the
  /// VTXO that produced has no delegate yet. Mirrors
  /// `CATEGORY_DELEGATE_SETTLED`.
  static const String categoryDelegateSettled = 'delegate-settled';

  static bool _isOurs(RemoteMessage msg) =>
      msg.data['category'] == categorySettleDue ||
      msg.data['category'] == categoryDelegateSettled;

  /// Set when a wake reached us before the service was ready; acted on in
  /// [onLoggedIn] once it is.
  static bool _pendingWake = false;

  /// Foreground init. Called from `main()` before runApp.
  static Future<void> initialize() async {
    if (_initialized) return;
    try {
      await Firebase.initializeApp(
        options: DefaultFirebaseOptions.currentPlatform,
      );
    } catch (e) {
      debugPrint('[push] Firebase.initializeApp failed: $e — push disabled');
      return;
    }
    try {
      // iOS requires permission; Android <13 grants by default.
      await FirebaseMessaging.instance.requestPermission(
        alert: true,
        badge: true,
        sound: true,
      );
      FirebaseMessaging.onBackgroundMessage(_handleBackgroundMessage);
      FirebaseMessaging.onMessage.listen(_handleForegroundMessage);
      // "boarding_deposit" is a visible notification; tapping it opens the app.
      FirebaseMessaging.onMessageOpenedApp.listen(_handleOpenedApp);
      final initial = await FirebaseMessaging.instance.getInitialMessage();
      if (initial != null) {
        await _handleOpenedApp(initial);
      }
      _initialized = true;
    } catch (e) {
      debugPrint('[push] permission/handler setup failed: $e');
    }
  }

  /// Offer this device's FCM token, and every rotation of it, to [svc]. Call
  /// as soon as the service exists — before onboarding, so the DKG can carry
  /// it. Asks the cosigner nothing itself; see [MpcService.offerDeviceToken].
  ///
  /// This is what makes the cosigner's settle watch able to reach anybody: it
  /// forwards the enrolment to the runtime, which owns the FCM credentials.
  /// Without it `wake` has no devices and the watch runs and notifies nothing.
  static Future<void> offerToken(MpcService svc) async {
    if (!_initialized) return;
    try {
      FirebaseMessaging.instance.onTokenRefresh.listen(svc.offerDeviceToken);
      final token = await FirebaseMessaging.instance.getToken();
      if (token == null || token.isEmpty) {
        debugPrint('[push] FCM returned no token — no wakes will arrive');
        return;
      }
      svc.offerDeviceToken(token);
    } catch (e) {
      // Not fatal: the wallet works, it just will not be woken before a
      // renewal falls due. Worth being loud about rather than silent.
      debugPrint('[push] no FCM token — no wakes will arrive: $e');
    }
  }

  /// The wallet is open: wakes can be acted on.
  static Future<void> onLoggedIn(MpcService svc) async {
    _svc = svc;

    // A wake reached us before the service was ready. Refreshing is the whole
    // response: it recomputes whether the sealed delegate still covers what we
    // hold, and raises the Ark-tab banner if it does not.
    if (_pendingWake) {
      _pendingWake = false;
      try {
        await svc.refreshVtxos();
      } catch (e) {
        debugPrint('[push] pending wake refresh failed: $e');
      }
    }
  }

  /// A wake arriving while the app is open.
  ///
  /// The branches for `boarding_deposit`, `payment_request` and `vtxo_received`
  /// are gone with the sender: those came from the old always-on server's own
  /// FCM client, and the cosigner that replaced it calls `wake` with exactly
  /// one category. Bringing any of them back is a `wake` call in the cosigner
  /// plus a branch here — not a branch here on its own, which is what they had
  /// become.
  static Future<void> _handleForegroundMessage(RemoteMessage msg) async {
    debugPrint('[push] foreground: ${msg.data}');
    final svc = _svc;
    if (svc == null) {
      debugPrint('[push] foreground wake but no live service yet');
      return;
    }
    if (!_isOurs(msg)) return;
    // Refreshing is the response: it recomputes whether a sealed delegate
    // still covers what we hold and raises the Ark-tab banner if it does not.
    try {
      await svc.refreshVtxos();
      debugPrint('[push] foreground settle-due: refreshed');
    } catch (e) {
      debugPrint('[push] foreground settle-due refresh failed: $e');
    }
  }

  /// The app was opened from a message.
  ///
  /// Reachable today only via `getInitialMessage()` on a cold start, not via a
  /// tap: nothing the runtime sends is displayable, so there is no notification
  /// for a user to tap. Kept because the cold-start path is real and because
  /// this is where a tap would land once wakes are surfaced locally.
  static Future<void> _handleOpenedApp(RemoteMessage msg) async {
    if (!_isOurs(msg)) return;
    final svc = _svc;
    if (svc == null) {
      // Opened before the service was ready; acted on in onLoggedIn.
      _pendingWake = true;
      return;
    }
    try {
      await svc.refreshVtxos();
      debugPrint('[push] opened on settle-due: refreshed');
    } catch (e) {
      debugPrint('[push] opened settle-due refresh failed: $e');
    }
  }

}

/// Top-level background handler. Flutter requires this to be a top-level
/// (non-class) function and annotated with `@pragma('vm:entry-point')` so the
/// background isolate can resolve it after Tree Shaking.
///
/// # There is nothing for it to do
///
/// Renewal is the cosigner's: it runs the sealed delegate itself, from the
/// enclave, against the ASP. The wakes that reach this isolate say that it did
/// (`delegate-settled`) or that it could not (`settle-due`), and either way what
/// follows needs the user — renewing the delegate, or refreshing in person —
/// which a background isolate cannot ask for. The wake is data-only, so there is
/// nothing to display; the next foreground refresh raises the Ark-tab banner.
@pragma('vm:entry-point')
Future<void> _handleBackgroundMessage(RemoteMessage msg) async {
  if (!PushService._isOurs(msg)) return;
  debugPrint('[push:bg] ${msg.data['category']} wake — the next foreground refreshes');
}
