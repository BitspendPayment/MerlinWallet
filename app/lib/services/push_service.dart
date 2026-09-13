/// FCM push handling.
///
/// Initializes Firebase, enrols the device token with the cosigner, and keeps
/// that enrolment in sync with FCM rotations.
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

  /// The live, logged-in service. Set by [registerCurrentToken] so the
  /// foreground push handler can drive a re-delegate while the app is open.
  static MpcService? _svc;

  /// The one category anything sends today: the cosigner's settle watch found
  /// its sealed delegate due and woke its owner to come and finish the round.
  /// Mirrors `CATEGORY_SETTLE_DUE` in `cosigner/src/handlers/watch.rs`.
  static const String categorySettleDue = 'settle-due';

  /// Set when a wake reached us before the service was ready; acted on in
  /// [registerCurrentToken] once it is.
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

  /// Enrol the current FCM token with the cosigner. Call after login, once
  /// `MpcService` has a client. Idempotent — enrolling a token the tenant
  /// already has is success and changes nothing.
  ///
  /// This is what makes the cosigner's settle watch able to reach anybody. The
  /// cosigner never sees the token twice and has no channel to send on; it
  /// forwards the enrolment to the runtime, which owns the FCM credentials.
  /// Without it `wake` has no devices and the watch runs and notifies nothing.
  static Future<void> registerCurrentToken(MpcService svc) async {
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

    final client = svc.client;
    if (client == null) {
      debugPrint('[push] no client yet — cannot enrol for wakes');
      return;
    }
    try {
      final token = await FirebaseMessaging.instance.getToken();
      if (token == null || token.isEmpty) {
        debugPrint('[push] FCM returned no token — not enrolled');
        return;
      }
      await client.registerDevice(token);
      debugPrint('[push] enrolled for wakes');
    } catch (e) {
      // Not fatal: the wallet works, it just will not be woken before a
      // renewal falls due. Worth being loud about rather than silent.
      debugPrint('[push] device enrolment failed — no wakes will arrive: $e');
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
    if (msg.data['category'] != categorySettleDue) return;
    // Refreshing is the response: it recomputes whether the sealed delegate
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
    if (msg.data['category'] != categorySettleDue) return;
    final svc = _svc;
    if (svc == null) {
      // Opened before the service was ready; acted on in registerCurrentToken.
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
/// # It cannot do the work, and it cannot yet say so
///
/// This used to restore the wallet from Hive and call
/// `settleDelegate(storeOnly: true)` — have the cosigner seal a renewal for its
/// own later use. That is gone on both ends: there is no `storeOnly`, because
/// renewing now means driving a real ASP batch round that waits on the ASP's
/// schedule rather than an 8-second timeout in an isolate the OS may kill; and
/// the cosigner could not use a sealed renewal by itself anyway, since a Wasm
/// guest has no egress at all. Waking its owner is what it does *instead*, so a
/// background isolate finishing the job on the owner's behalf is precisely the
/// thing that cannot happen.
///
/// What it should do is tell the user to open the app. **It cannot**: the wake
/// is data-only by design and the app has no local-notification plugin, so
/// there is nothing to display with. Until one is added, a wake that arrives
/// while the app is backgrounded is logged and the user finds out on next open
/// — `registerCurrentToken` and the foreground handler both refresh, and the
/// Ark tab raises its banner if the renewal no longer covers what is held.
@pragma('vm:entry-point')
Future<void> _handleBackgroundMessage(RemoteMessage msg) async {
  if (msg.data['category'] != PushService.categorySettleDue) return;
  debugPrint('[push:bg] settle-due wake — nothing to display and nothing a '
      'background isolate can settle; the next foreground refreshes');
}
