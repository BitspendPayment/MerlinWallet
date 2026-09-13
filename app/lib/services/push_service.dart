/// FCM push handling.
///
/// Initializes Firebase, registers the device token with the cosigner, and
/// keeps the token registration in sync with FCM rotations. Wakes
/// [MpcService] from a background message so the app re-delegates after a
/// receive even when the user hasn't opened it.
///
/// Safe to call on platforms or builds without Firebase config: any
/// initialization error is logged and the rest of the app continues without
/// push (auto-settle still fires for users who open the app).
library;


import 'package:app_core/client.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';
import 'package:hive/hive.dart';
import 'package:app_core/passkey/session_token_source.dart'
    show StaticSessionToken;
import 'package:path_provider/path_provider.dart';

import '../firebase_options.dart';
import 'mpc_service.dart';
import 'server_host.dart' as server_host;

class PushService {
  static bool _initialized = false;

  /// The live, logged-in service. Set by [registerCurrentToken] so the
  /// foreground push handler can drive a re-delegate while the app is open.
  static MpcService? _svc;

  /// Set when a "boarding_deposit" notification opened the app from a
  /// terminated state before the service was ready; acted on in
  /// [registerCurrentToken] once it is.
  static bool _pendingBoarding = false;

  /// Set when a "contract_share" notification opened the app from a terminated
  /// state before the service was ready; acted on in [registerCurrentToken].

  /// Set when a "vtxo_received" notification opened the app from a terminated
  /// state before the service was ready; acted on in [registerCurrentToken]
  /// (a refresh, which raises the Ark-tab delegate banner if needed).
  static bool _pendingVtxoReceived = false;

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

  /// Register the current FCM token with the cosigner. Call after login,
  /// once `MpcService` has a client. Idempotent.
  static Future<void> registerCurrentToken(MpcService svc) async {
    _svc = svc;
    // A boarding notification opened the app before the service was ready.
    if (_pendingBoarding) {
      _pendingBoarding = false;
      try {
        await svc.boardFunds();
      } catch (e) {
        debugPrint('[push] pending boardFunds failed: $e');
      }
    }
    // A funds-received notification opened the app before the service was
    // ready; refresh so the Ark tab raises its delegate banner if needed.
    if (_pendingVtxoReceived) {
      _pendingVtxoReceived = false;
      try {
        await svc.refreshVtxos();
      } catch (e) {
        debugPrint('[push] pending refreshVtxos failed: $e');
      }
    }
    // No token registration. The cosigner had a `RegisterDeviceToken` RPC and pushed from its
    // own FCM client; it is called rather than running and has no outbound sockets, so the host
    // owns the push channel and the registry that feeds it. Display still works — what is gone is
    // this side telling the cosigner where to reach us.
  }

  static Future<void> _handleForegroundMessage(RemoteMessage msg) async {
    debugPrint('[push] foreground: ${msg.data}');
    final type = msg.data['type'];
    final svc = _svc;
    if (svc == null) {
      debugPrint('[push] foreground $type but no live service yet');
      return;
    }
    if (type == 'vtxo_received') {
      // App is open: refresh so _delegateIfNeeded() runs — it re-delegates
      // silently when no biometric prompt would appear, otherwise it raises
      // the Ark-tab delegate banner for the user to act on.
      try {
        await svc.refreshVtxos();
        debugPrint('[push] foreground re-delegate via refreshVtxos ok');
      } catch (e) {
        debugPrint('[push] foreground refreshVtxos failed: $e');
      }
    } else if (type == 'boarding_deposit') {
      // App is open: reflect the pending deposit so the user can board from UI.
      try {
        await svc.refreshBoardingBalance();
        debugPrint('[push] foreground boarding balance refreshed');
      } catch (e) {
        debugPrint('[push] foreground refreshBoardingBalance failed: $e');
      }
    } else if (type == 'payment_request') {
      // App is open: an allowlisted contact asked us to pay. The intent is already sealed
      // cosigner-side, so this is only a nudge to refresh the inbox.
      try {
        await svc.refreshPaymentRequests();
        debugPrint('[push] foreground payment requests refreshed');
      } catch (e) {
        debugPrint('[push] foreground refreshPaymentRequests failed: $e');
      }
    }
  }

  /// User tapped a notification (app backgrounded or cold-started). Handles the
  /// visible/tappable notifications: "vtxo_received" (funds arrived — refresh
  /// so the Ark tab raises its delegate banner; the user taps Delegate there,
  /// which is where the passkey prompt belongs), "boarding_deposit" and
  /// "contract_share".
  static Future<void> _handleOpenedApp(RemoteMessage msg) async {
    final type = msg.data['type'];
    final svc = _svc;
    if (type == 'vtxo_received') {
      if (svc == null) {
        _pendingVtxoReceived = true;
        return;
      }
      try {
        await svc.refreshVtxos();
        debugPrint('[push] tap vtxo_received: refreshed (banner if needed)');
      } catch (e) {
        debugPrint('[push] tap vtxo_received refreshVtxos failed: $e');
      }
    } else if (type == 'boarding_deposit') {
      if (svc == null) {
        // App cold-started from the tap; act once the service is ready.
        _pendingBoarding = true;
        return;
      }
      try {
        await svc.boardFunds();
        debugPrint('[push] tap-to-board: boardFunds ok');
      } catch (e) {
        debugPrint('[push] tap-to-board boardFunds failed: $e');
      }
    }
  }

  /// Run the same code path `_handleBackgroundMessage` runs for a
  /// `vtxo_received` payload, but synchronously from the calling isolate.
  /// Integration tests use this because Flutter test bindings can't deliver
  /// real OS push events — but the test still wants to prove the handler's
  /// work (load Hive, restore client, store delegate) actually runs.
  @visibleForTesting
  static Future<void> handleBackgroundMessageForTest(
      Map<String, String> data) async {
    if (data['type'] != 'vtxo_received') return;
    await _runBackgroundDelegate();
  }
}

/// Construct a fresh REST client, restore identity from Hive, run
/// `settleDelegate(storeOnly: true)`. Used by both the real background
/// handler and the test-only entry point.
///
/// No hardware signer needed — FROST signing here uses the wallet's own
/// share (`_normalPolicy.keyPackage`), which `restoreState()` rehydrates
/// from Hive.
Future<void> _runBackgroundDelegate({Duration? timeout}) async {
  final dir = await getApplicationDocumentsDirectory();
  // Must match the main app's Hive root. MpcService.init() initialises
  // persistence at '<docs>/mpc_client' (via MpcClient.initPersistence), so the
  // identity box and wallet state live there. A bare Hive.init(dir.path) opens
  // an empty box in the wrong directory — identity + wallet state come back
  // missing and the delegate silently no-ops.
  await MpcClient.initPersistence(path: '${dir.path}/mpc_client');
  final identityBox = await Hive.openBox('mpc_service_identity');
  final host = identityBox.get('serverHost') as String?;
  final storageId = identityBox.get('storageId') as String?;
  if (host == null || storageId == null) {
    debugPrint('[push:bg] missing serverHost or storageId in Hive');
    return;
  }
  final client = MpcClient.rest(
    server_host.baseUrlFor(host),
    storageId: storageId,
  );
  try {
    final restored = await client.restoreState();
    if (!restored) {
      debugPrint('[push:bg] restoreState returned false (no wallet)');
      return;
    }

    // Carry the persisted session token. Without it every request here went out
    // with an empty Schnorr signature and no Bearer header, so a passkey-gated
    // wallet got a flat 401 — and the failure was swallowed as "foreground will
    // catch up", which made this whole path look like it worked.
    final token = identityBox.get('passkeySessionToken') as String?;
    if (token != null) {
      client.setSessionTokenSource(StaticSessionToken(token));
    }

    // A gated share cannot be reconstructed without the passkey PRF, and a PRF
    // evaluation needs a user gesture — impossible in a background isolate. So
    // this path is genuinely foreground-only for passkey wallets; say so plainly
    // instead of failing deep inside FROST signing with a confusing StateError.
    if (client.isShareGated) {
      debugPrint('[push:bg] share is passkey-gated — re-delegate needs the '
          'foreground (PRF requires a user gesture); skipping');
      return;
    }
    if (token == null) {
      debugPrint('[push:bg] no persisted session token; '
          'falling back to Schnorr auth');
    }

    final future = client.settleDelegate(storeOnly: true);
    await (timeout != null ? future.timeout(timeout) : future);
    debugPrint('[push:bg] settleDelegate(storeOnly:true) ok');
  } finally {
    // No explicit dispose on MpcClient; falls out of scope.
  }
}

/// Top-level background handler. Flutter requires this to be a top-level
/// (non-class) function and annotated with `@pragma('vm:entry-point')` so the
/// background isolate can resolve it after Tree Shaking.
///
/// FROST signing happens with the wallet's own share — no hardware signer
/// reachability required.
@pragma('vm:entry-point')
Future<void> _handleBackgroundMessage(RemoteMessage msg) async {
  if (msg.data['type'] != 'vtxo_received') return;
  try {
    await Firebase.initializeApp(
      options: DefaultFirebaseOptions.currentPlatform,
    );
  } catch (e) {
    debugPrint('[push:bg] Firebase.initializeApp failed: $e');
    return;
  }
  try {
    await _runBackgroundDelegate(timeout: const Duration(seconds: 8));
  } catch (e) {
    debugPrint('[push:bg] settleDelegate failed: $e — foreground will catch up');
  }
}
