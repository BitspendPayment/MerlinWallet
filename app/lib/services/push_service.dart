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
/// What a wake becomes is a local notification, composed on the device —
/// [_handleBackgroundMessage] — saying only that the owner is wanted. Opening
/// the app is an entry, and an entry re-arms the renewal.
///
/// Safe to call on platforms or builds without Firebase config: any
/// initialization error is logged and the rest of the app continues without
/// push (every entry to the app still re-arms the renewal).
library;

import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';

import 'dart:ui' show DartPluginRegistrant;

import 'package:flutter_local_notifications/flutter_local_notifications.dart';

import '../firebase_options.dart';
import 'mpc_service.dart';

class PushService {
  static bool _initialized = false;

  /// The live, logged-in service. Set by [onLoggedIn] so a wake can reach it
  /// while the app is open.
  static MpcService? _svc;

  /// The cosigner's watch found its sealed delegate due and could not run it
  /// itself — no ASP reachable, or the round failed — so it woke its owner to
  /// refresh in person. Mirrors `CATEGORY_SETTLE_DUE` in
  /// `cosigner/src/cosigner.rs`.
  static const String categorySettleDue = 'settle-due';

  /// The cosigner ran its sealed delegate: the funds were refreshed, and the
  /// VTXO that produced has no delegate yet. Mirrors
  /// `CATEGORY_DELEGATE_SETTLED`.
  static const String categoryDelegateSettled = 'delegate-settled';

  static bool _isOurs(RemoteMessage msg) =>
      msg.data['category'] == categorySettleDue ||
      msg.data['category'] == categoryDelegateSettled;


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
      // No `onMessageOpenedApp` or `getInitialMessage`: a wake is data-only, so FCM never shows
      // one for a user to tap. The notification a wake becomes is ours, and its tap lands here —
      // a backstop, since opening the app is already an entry that locks.
      await FlutterLocalNotificationsPlugin().initialize(
        settings: _notificationSettings,
        onDidReceiveNotificationResponse: (_) => _svc?.lock(),
      );
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
  }

  // --- Telling the owner -------------------------------------------------------------------------
  //
  // A wake is data-only, so FCM shows nothing; this does. Composed here, on the device, so nothing
  // readable goes through FCM — and it says nothing about the wallet anyway: no amount, no time,
  // only that the owner is wanted.

  static const _notificationSettings =
      InitializationSettings(android: AndroidInitializationSettings('@mipmap/ic_launcher'));

  static const _reminders = AndroidNotificationDetails(
    'wakes',
    'Reminders',
    channelDescription: 'When your funds need you to open the app',
    importance: Importance.high,
    priority: Priority.high,
    onlyAlertOnce: true,
  );

  /// One notification for every wake: a `settle-due` repeats every half hour until it is answered,
  /// and each replaces the last.
  static const int _wakeNotification = 1;

  static Future<void> _show(String? category) async {
    final plugin = FlutterLocalNotificationsPlugin();
    await plugin.initialize(settings: _notificationSettings);
    await plugin.show(
      id: _wakeNotification,
      title: 'Merlin Wallet',
      // `settle-due`: the cosigner could not renew, so it is the owner's to do, and soon.
      body: category == categorySettleDue
          ? 'Open Merlin Wallet soon to keep your funds protected.'
          : 'Open Merlin Wallet to keep your funds protected.',
      notificationDetails: const NotificationDetails(android: _reminders),
    );
  }

  /// A wake arriving while the app is open.
  ///
  /// The branches for `boarding_deposit`, `payment_request` and `vtxo_received`
  /// are gone with the sender: those came from the old always-on server's own
  /// FCM client, and the cosigner that replaced it calls `wake` with exactly
  /// one category. Bringing any of them back is a `wake` call in the cosigner
  /// plus a branch here — not a branch here on its own, which is what they had
  /// become.
  ///
  /// `settle-due` locks the wallet: the cosigner could not renew, the funds are
  /// close to expiring, and only the owner's passkey can refresh them — which
  /// the unlock does. `delegate-settled` is not urgent — the funds were just
  /// renewed — so it only refreshes, and the next entry re-arms.
  static Future<void> _handleForegroundMessage(RemoteMessage msg) async {
    debugPrint('[push] foreground: ${msg.data}');
    final svc = _svc;
    if (svc == null) {
      debugPrint('[push] foreground wake but no live service yet');
      return;
    }
    if (!_isOurs(msg)) return;
    if (msg.data['category'] == categorySettleDue) {
      svc.lock();
      return;
    }
    try {
      await svc.refreshVtxos();
    } catch (e) {
      debugPrint('[push] foreground wake refresh failed: $e');
    }
  }
}

/// Top-level background handler. Flutter requires this to be a top-level
/// (non-class) function and annotated with `@pragma('vm:entry-point')` so the
/// background isolate can resolve it after Tree Shaking.
///
/// # It tells the owner
///
/// Renewal is the cosigner's: it runs the sealed delegate itself, from the
/// enclave, against the ASP. The wakes that reach this isolate say that it did
/// (`delegate-settled`) or that it could not (`settle-due`), and either way what
/// follows needs the owner's passkey — a new delegate, or a refresh in person —
/// which a background isolate cannot ask for. So it shows a notification, and
/// the owner opening the app is the entry that does the rest.
@pragma('vm:entry-point')
Future<void> _handleBackgroundMessage(RemoteMessage msg) async {
  if (!PushService._isOurs(msg)) return;
  // FlutterFire's dispatcher starts the binding, not the plugin registrant, and the notification
  // plugin is one.
  DartPluginRegistrant.ensureInitialized();
  await PushService._show(msg.data['category'] as String?);
}
