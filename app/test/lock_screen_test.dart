import 'dart:async';

import 'package:app/main.dart';
import 'package:app/passkey/passkey_channel.dart';
import 'package:app/screens/lock_screen.dart';
import 'package:app/screens/splash_screen.dart';
import 'package:app/services/mpc_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

/// A wallet behind its passkey, whose unlocks go as [script] says: an error to throw, or null for a
/// passkey given.
class _LockedWallet extends MpcService {
  _LockedWallet(this.script) {
    // The splash waits on this; it never comes, so the app stays where the test can see it.
    initFuture = Completer<void>().future;
  }

  final List<Object?> script;
  int unlocks = 0;
  bool _locked = true;

  @override
  bool get locked => _locked;

  @override
  Future<void> unlock() async {
    final outcome = script[unlocks++];
    if (outcome != null) throw outcome;
    _locked = false;
    notifyListeners();
  }
}

void main() {
  setUpAll(() => GoogleFonts.config.allowRuntimeFetching = false);

  testWidgets('the app stays behind the lock until the passkey is given', (tester) async {
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    final wallet = _LockedWallet([PlatformException(code: PasskeyChannel.cancelled), null]);
    await tester.pumpWidget(ChangeNotifierProvider<MpcService>.value(
      value: wallet,
      child: const MerlinWalletApp(),
    ));
    await tester.pump();

    // Locked: the lock is what shows, and the app under it neither shows nor takes a tap.
    expect(find.byType(LockScreen), findsOneWidget);
    expect(find.byType(SplashScreen), findsNothing);
    expect(find.byType(SplashScreen, skipOffstage: false), findsOneWidget,
        reason: 'kept, with its state, behind the lock');

    // It asked by itself, and the owner dismissed the prompt: still locked, and told why.
    expect(wallet.unlocks, 1, reason: 'an entry asks for the passkey without waiting for a tap');
    expect(find.text('The passkey prompt was cancelled.'), findsOneWidget);
    expect(find.byType(SplashScreen), findsNothing);

    // Asked again, and given: the lock lifts, and the app is where it was.
    await tester.tap(find.byKey(const Key('unlockBtn')));
    await tester.pump();
    expect(wallet.unlocks, 2);
    expect(find.byType(LockScreen), findsNothing);
    expect(find.byType(SplashScreen), findsOneWidget);
  });
}
