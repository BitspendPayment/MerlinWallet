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

/// An open wallet whose work the test starts and stops: [busy] is an operation, or a flow, running.
class _OpenWallet extends MpcService {
  _OpenWallet() {
    initFuture = Completer<void>().future;
  }

  bool busy = false;
  bool _locked = false;

  @override
  bool get idle => !busy;

  @override
  bool get locked => _locked;

  // As the real one, less its wallet check: a widget test has no client.
  @override
  void lock() {
    if (_locked || !idle) return;
    _locked = true;
    notifyListeners();
  }

  @override
  Future<void> unlock() async {}
}

/// Away from the app and back again, as the platform says it: hidden, then shown.
void leaveAndReturn(WidgetTester tester) {
  for (final state in [
    AppLifecycleState.inactive,
    AppLifecycleState.hidden,
    AppLifecycleState.inactive,
    AppLifecycleState.resumed,
  ]) {
    tester.binding.handleAppLifecycleStateChanged(state);
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

  testWidgets('under the lock the app is inert: back is nobody\'s, and its snackbars stay under',
      (tester) async {
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    final wallet = _LockedWallet([PlatformException(code: PasskeyChannel.cancelled)]);
    await tester.pumpWidget(ChangeNotifierProvider<MpcService>.value(
      value: wallet,
      child: const MerlinWalletApp(),
    ));
    await tester.pump();

    expect(await tester.binding.handlePopRoute(), isTrue,
        reason: 'the pages under the lock are not the owner\'s to leave yet');

    final under = tester.element(find.byType(SplashScreen, skipOffstage: false));
    ScaffoldMessenger.of(under).showSnackBar(const SnackBar(content: Text('from under the lock')));
    await tester.pump();
    expect(find.text('from under the lock'), findsNothing, reason: 'not drawn on the lock');
    ScaffoldMessenger.of(under).clearSnackBars();
    await tester.pump();
  });

  testWidgets('leaving while something runs is still leaving: the lock lands once it is done',
      (tester) async {
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    final wallet = _OpenWallet()..busy = true;
    await tester.pumpWidget(ChangeNotifierProvider<MpcService>.value(
      value: wallet,
      child: const MerlinWalletApp(),
    ));

    leaveAndReturn(tester);
    await tester.pump();
    expect(find.byType(LockScreen), findsNothing, reason: 'what runs is not interrupted');

    wallet.busy = false;
    await tester.pump(const Duration(seconds: 1));
    await tester.pump();
    expect(find.byType(LockScreen), findsOneWidget, reason: 'but the return was an entry');
  });

  testWidgets('a passkey sheet that hides the app is not the owner leaving', (tester) async {
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    final wallet = _OpenWallet();
    await tester.pumpWidget(ChangeNotifierProvider<MpcService>.value(
      value: wallet,
      child: const MerlinWalletApp(),
    ));

    // A prompt is up — the platform has not answered — and its sheet hides the app.
    const channel = MethodChannel('com.mpcwallet.ap/passkey');
    final sheet = Completer<Object?>();
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, (_) => sheet.future);
    final prompt = PasskeyChannel.get('{}');
    leaveAndReturn(tester);
    await tester.pump(const Duration(seconds: 1));
    expect(find.byType(LockScreen), findsNothing);

    sheet.complete('{}');
    await prompt;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, null);
  });
}
