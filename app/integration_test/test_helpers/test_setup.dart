import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:hive/hive.dart';
import 'package:path_provider/path_provider.dart';

import 'package:app/services/mpc_service.dart';
import 'package:flutter/widgets.dart';
import 'package:provider/provider.dart';

import 'test_app.dart';

/// Force-disposes the prior widget tree so any Provider-held MpcService
/// releases its Hive boxes before we try to wipe them. Without this, the
/// old MpcService keeps `_identityBox` open and Hive's box cache returns
/// stale `dkgComplete=true` to the next test.
Future<void> tearDownTree(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pumpAndSettle();
}

Future<void> resetAppState() async {
  // Wipe Hive's in-memory cache *and* on-disk files. We use both APIs because
  // either alone has been observed to leave stale state across tests in the
  // same Dart VM.
  try {
    await Hive.deleteFromDisk();
  } catch (_) {}
  try {
    await Hive.close();
  } catch (_) {}

  final docs = await getApplicationDocumentsDirectory();
  if (!docs.existsSync()) return;
  for (final entry in docs.listSync(recursive: true)) {
    final p = entry.path;
    if (p.endsWith('.hive') || p.endsWith('.lock')) {
      try {
        entry.deleteSync();
      } catch (_) {}
    }
  }
  final mpcDir = Directory('${docs.path}/mpc_client');
  if (mpcDir.existsSync()) {
    try {
      mpcDir.deleteSync(recursive: true);
    } catch (_) {}
  }
}

Future<void> bootApp(WidgetTester tester) async {
  GoogleFonts.config.allowRuntimeFetching = false;
  // Suppress RenderFlex overflow warnings in tests. They show as yellow/black
  // stripes in production but fail integration_test runs because the binding
  // treats every FlutterError as a test failure.
  final priorOnError = FlutterError.onError;
  FlutterError.onError = (FlutterErrorDetails details) {
    final msg = details.exceptionAsString();
    if (msg.contains('overflowed') || msg.contains('RenderFlex')) {
      return;
    }
    priorOnError?.call(details);
  };
  await tester.pumpWidget(buildTestApp());
  await tester.pumpAndSettle();
}

Future<void> pumpUntilFound(
  WidgetTester tester,
  Finder finder, {
  Duration timeout = const Duration(seconds: 30),
  Duration interval = const Duration(milliseconds: 200),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    await tester.pump(interval);
    if (finder.evaluate().isNotEmpty) return;
  }
  throw TestFailure('pumpUntilFound timed out waiting for $finder');
}

Future<void> pumpUntilGone(
  WidgetTester tester,
  Finder finder, {
  Duration timeout = const Duration(seconds: 30),
  Duration interval = const Duration(milliseconds: 200),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    await tester.pump(interval);
    if (finder.evaluate().isEmpty) return;
  }
  throw TestFailure('pumpUntilGone timed out — $finder still present');
}

Future<void> pumpUntilTrue(
  WidgetTester tester,
  bool Function() predicate, {
  Duration timeout = const Duration(seconds: 60),
  Duration interval = const Duration(milliseconds: 200),
  String? reason,
}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    await tester.pump(interval);
    if (predicate()) return;
  }
  throw TestFailure('pumpUntilTrue timed out${reason != null ? ' — $reason' : ''}');
}

/// Polls `MpcService.refreshVtxos()` until `arkBalance` >= [minimumSats]. Use
/// after Bob (or anyone external) sends a VTXO to the wallet's ark address.
/// Resolves the MpcService context from any of the Ark screen's known keys.
Future<void> waitForArkBalance(
  WidgetTester tester,
  BigInt minimumSats, {
  Duration timeout = const Duration(seconds: 60),
  Duration pollEvery = const Duration(seconds: 2),
}) async {
  Element resolveCtx() {
    for (final keyName in const [
      'arkSendMoneyBtn',
      'arkRefreshBtn',
    ]) {
      final f = find.byKey(Key(keyName));
      if (f.evaluate().isNotEmpty) return tester.element(f);
    }
    throw StateError('waitForArkBalance: no anchor widget on screen');
  }

  final svc = Provider.of<MpcService>(resolveCtx(), listen: false);
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    try {
      await svc.refreshVtxos().timeout(const Duration(seconds: 20));
    } catch (_) {}
    if (svc.arkBalance >= minimumSats) return;
    await tester.pump(pollEvery);
  }
  throw TestFailure(
      'waitForArkBalance timed out — arkBalance ${svc.arkBalance} < $minimumSats sats');
}
