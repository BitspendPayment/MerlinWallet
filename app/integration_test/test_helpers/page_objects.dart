import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'test_setup.dart';

Future<void> _tapKey(WidgetTester tester, String keyName) async {
  // Wait until the widget is in the tree AND actually hit-testable (i.e. not
  // behind a route-transition Offstage/AbsorbPointer overlay). pumpAndSettle
  // alone has been observed to return while the outgoing route is still
  // absorbing pointer events.
  final hit = find.byKey(Key(keyName)).hitTestable();
  final deadline = DateTime.now().add(const Duration(seconds: 10));
  while (hit.evaluate().isEmpty && DateTime.now().isBefore(deadline)) {
    await tester.pump(const Duration(milliseconds: 100));
  }
  if (hit.evaluate().isEmpty) {
    throw StateError('_tapKey: $keyName never became hit-testable');
  }
  await tester.tap(hit);
  await tester.pump();
}

Future<void> _enterText(
    WidgetTester tester, String keyName, String text) async {
  await tester.enterText(find.byKey(Key(keyName)), text);
  await tester.pump();
}

/// Closes the on-screen keyboard. On the small CI emulator (320x640) the IME
/// covers buttons that sit below a text field, so dismiss it before tapping.
///
/// Uses pump(), NOT pumpAndSettle(): some screens (e.g. the signing screen)
/// keep a CircularProgressIndicator running, so pumpAndSettle() would block
/// until the test times out. ~500ms is enough for the IME-hide animation and
/// the viewInsets reflow.
Future<void> _dismissKeyboard(WidgetTester tester) async {
  FocusManager.instance.primaryFocus?.unfocus();
  await tester.pump(const Duration(milliseconds: 500));
}

class WelcomePage {
  static Future<void> tapCreate(WidgetTester tester) =>
      _tapKey(tester, 'welcomeCreateBtn');
}

class PasskeySetupPage {
  static Future<void> create(WidgetTester tester) =>
      _tapKey(tester, 'passkeyCreateBtn');
}

class ServerConnectPage {
  static Future<void> pickRegtest(WidgetTester tester) =>
      _tapKey(tester, 'serverPresetRegtest');
  static Future<void> pickMutiny(WidgetTester tester) =>
      _tapKey(tester, 'serverPresetMutiny');
}

class DkgProgressPage {
  static Future<void> waitForExitAddress(
    WidgetTester tester, {
    Duration timeout = const Duration(seconds: 90),
  }) async {
    await pumpUntilFound(
      tester,
      find.byKey(const Key('exitAddressField')),
      timeout: timeout,
    );
  }
}

class WalletReadyPage {
  static Future<void> tapGoToWallet(WidgetTester tester) =>
      _tapKey(tester, 'walletReadyBtn');
}

/// Where the money goes if the service disappears — asked once, after the key exists.
class ExitAddressPage {
  static Future<void> enter(WidgetTester tester, String address) async {
    await _enterText(tester, 'exitAddressField', address);
    await _dismissKeyboard(tester);
    await _tapKey(tester, 'exitAddressSaveBtn');
  }
}

class ExitPage {
  static Future<void> open(WidgetTester tester) async {
    await tester.tap(find.descendant(
      of: find.byType(BottomNavigationBar),
      matching: find.text('Exit'),
    ));
    await tester.pumpAndSettle();
  }

  static Future<void> signExits(WidgetTester tester) => _tapKey(tester, 'exitProtectBtn');
}

class ArkPage {
  /// Receiving IS boarding: on-chain to the boarding address, then settle.
  static Future<void> tapReceive(WidgetTester tester) =>
      _tapKey(tester, 'arkReceiveBtn');
  static Future<void> tapBoard(WidgetTester tester) => tapReceive(tester);
}

class ArkBoardPage {
  static Future<void> tapBoardNow(WidgetTester tester) =>
      _tapKey(tester, 'arkBoardNowBtn');
  static Future<void> tapDone(WidgetTester tester) =>
      _tapKey(tester, 'arkBoardDoneBtn');
  static Future<void> waitForFundsDetected(
    WidgetTester tester, {
    Duration timeout = const Duration(minutes: 2),
  }) async {
    await pumpUntilFound(
      tester,
      find.text('Board Now'),
      timeout: timeout,
    );
  }
}
