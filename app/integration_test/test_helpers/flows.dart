import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'page_objects.dart';
import 'test_setup.dart';

class Flows {
  /// Onboarding, up to the wallet opening. [exitAddress] is where unilateral exits will pay; the
  /// step is blocking, because without one nothing can be pre-signed.
  static Future<void> completeOnboarding(
    WidgetTester tester, {
    String pin = '123456',
    required String exitAddress,
  }) async {
    await pumpUntilFound(
      tester,
      find.byKey(const Key('welcomeCreateBtn')),
      timeout: const Duration(seconds: 30),
    );
    await WelcomePage.tapCreate(tester);
    await tester.pumpAndSettle();
    await PinPage.enter(tester, pin);
    await tester.pumpAndSettle();
    // Onboarding goes straight to the server step after the PIN.
    await ServerConnectPage.pickRegtest(tester);
    // Don't pumpAndSettle here — the DKG screen has a CircularProgressIndicator
    // that never "settles" until DKG completes, so pumpAndSettle would block
    // (up to its 10-min cap). waitForReady polls via pump() instead, which is
    // unaffected by ongoing animations.
    await DkgProgressPage.waitForReady(
      tester,
      timeout: const Duration(minutes: 3),
    );
    await pumpUntilFound(tester, find.byKey(const Key('exitAddressField')));
    await ExitAddressPage.enter(tester, exitAddress);
    await pumpUntilFound(tester, find.byKey(const Key('walletReadyBtn')));
    await WalletReadyPage.tapGoToWallet(tester);
    await tester.pumpAndSettle();
  }

}
