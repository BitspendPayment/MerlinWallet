import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'page_objects.dart';
import 'test_setup.dart';

class Flows {
  /// Onboarding, up to the wallet opening. [exitAddress] is where unilateral exits will pay; the
  /// step is blocking, because without one nothing can be pre-signed.
  static Future<void> completeOnboarding(
    WidgetTester tester, {
    required String exitAddress,
  }) async {
    await pumpUntilFound(
      tester,
      find.byKey(const Key('welcomeCreateBtn')),
      timeout: const Duration(seconds: 30),
    );
    await WelcomePage.tapCreate(tester);
    await pumpUntilFound(tester, find.byKey(const Key('serverPresetRegtest')));
    await ServerConnectPage.pickRegtest(tester);
    await pumpUntilFound(tester, find.byKey(const Key('passkeyCreateBtn')));
    await PasskeySetupPage.create(tester);
    // Credential Manager requires the owner's approval on a device. DKG and passkey setup
    // animate while waiting, so poll for the next step instead of waiting for animations to stop.
    await DkgProgressPage.waitForExitAddress(
      tester,
      timeout: const Duration(minutes: 3),
    );
    await ExitAddressPage.enter(tester, exitAddress);
    await pumpUntilFound(tester, find.byKey(const Key('walletReadyBtn')));
    await WalletReadyPage.tapGoToWallet(tester);
    await tester.pumpAndSettle();
  }

}
