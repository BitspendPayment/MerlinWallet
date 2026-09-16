// One end-to-end testWidgets covering the user lifecycle:
//   onboarding (DKG) → on-chain send → Ark board/send/receive.

// ignore_for_file: avoid_print

import 'package:app/services/mpc_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:provider/provider.dart';

import 'test_helpers/bob_client.dart';
import 'test_helpers/flows.dart';
import 'test_helpers/page_objects.dart';
import 'test_helpers/regtest_helper.dart';
import 'test_helpers/test_setup.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets(
    'full flow: onboarding → send → ark',
    (tester) async {
      const pin = '123456';
      final btc = RegtestHelper();
      await btc.ensureWalletLoaded('default');

      // ── Onboarding ───────────────────────────────────────────────────────
      await resetAppState();
      await bootApp(tester);
      await Flows.completeOnboarding(tester, pin: pin);
      await pumpUntilFound(tester, find.byKey(const Key('homeSendBtn')));
      expect(find.byKey(const Key('homeSendBtn')), findsOneWidget);

      final ctxOnboard = tester.element(find.byKey(const Key('homeSendBtn')));
      final originalAddress =
          Provider.of<MpcService>(ctxOnboard, listen: false).receiveAddress;
      expect(originalAddress, isNotNull);

      // ── On-chain send ────────────────────────────────────────────────────
      await HomePage.tapReceive(tester);
      await pumpUntilFound(tester, find.byType(SelectableText));
      final receiveAddress =
          tester.widget<SelectableText>(find.byType(SelectableText)).data!;

      await btc.sendToAddress(receiveAddress, 0.01);
      final minerAddr = await btc.getNewAddress();
      await btc.generateToAddress(1, minerAddr);

      await tester.pageBack();
      await pumpUntilFound(tester, find.byKey(const Key('homeSendBtn')));

      await waitForBalance(tester, BigInt.from(1000000));

      final destination = await btc.getNewAddress();
      await HomePage.tapSend(tester);
      await tester.pumpAndSettle();
      await SendPage.enterAddress(tester, destination);
      await SendPage.enterAmount(tester, '50000');
      await SendPage.tapReview(tester);
      await pumpUntilFound(tester, find.byKey(const Key('reviewSignBtn')));
      await ReviewPage.tapSign(tester);
      await pumpUntilFound(
        tester,
        find.byKey(const Key('homeSendBtn')),
        timeout: const Duration(seconds: 90),
      );

      // ── Ark boarding (skipped when ASP not configured) ──────────────────
      await HomePage.tapArkTab(tester);
      await tester.pumpAndSettle();
      final arkAvailable = find.text('Ark Not Available').evaluate().isEmpty;
      if (!arkAvailable) {
        print('Ark not available — skipping ark sub-flow');
      } else {
        await ArkPage.tapBoard(tester);
        await pumpUntilFound(tester, find.byKey(const Key('arkBoardNowBtn')));

        final ctxBoard = tester.element(find.byKey(const Key('arkBoardNowBtn')));
        final svcBoard = Provider.of<MpcService>(ctxBoard, listen: false);
        final boardingAddress = svcBoard.boardingAddress;
        expect(boardingAddress, isNotNull,
            reason: 'boardingAddress should be populated by the ark wallet');

        await btc.sendToAddress(boardingAddress!, 0.005);
        await btc.generateToAddress(1, minerAddr);

        await ArkBoardPage.waitForFundsDetected(tester);
        await ArkBoardPage.tapBoardNow(tester);
        await pumpUntilFound(
          tester,
          find.byKey(const Key('arkBoardDoneBtn')),
          timeout: const Duration(minutes: 2),
        );
        await ArkBoardPage.tapDone(tester);
        await pumpUntilFound(tester, find.byKey(const Key('arkSendBtn')));
        expect(svcBoard.arkBalance > BigInt.zero, isTrue,
            reason: 'ark balance should be non-zero after boarding');

        // Auto-delegate regression guard. MpcService.refreshVtxos() ends
        // with _delegateIfNeeded, which calls settleDelegate(storeOnly:
        // true) when vtxos are non-empty and no delegate is yet stored.
        // After boarding settles, both conditions are true → delegate
        // should be stored within seconds.
        await svcBoard.refreshVtxos();
        final delegDeadline =
            DateTime.now().add(const Duration(seconds: 30));
        while (!svcBoard.fundsProtected &&
            DateTime.now().isBefore(delegDeadline)) {
          await tester.pump(const Duration(seconds: 1));
        }
        expect(svcBoard.fundsProtected, isTrue,
            reason:
                'after boarding + refresh, _delegateIfNeeded must have '
                'stored a delegate intent. If false, the foreground '
                'auto-delegate path regressed.');

        // ── Ark send (App → Bob, an external ark-sample wallet) ─────
        final bob = BobClient();
        final bobArkAddress = await bob.arkAddress();
        final bobBalanceBefore = await bob.spendableSats();
        final appArkBalanceBefore = svcBoard.arkBalance;

        await ArkPage.tapSend(tester);
        await pumpUntilFound(tester, find.byKey(const Key('arkSendVtxoBtn')));
        await ArkSendPage.enterAddress(tester, bobArkAddress);
        await ArkSendPage.enterAmount(tester, '5000');
        await ArkSendPage.tapSend(tester);
        await pumpUntilFound(
          tester,
          find.byKey(const Key('arkSendBtn')),
          timeout: const Duration(seconds: 90),
        );
        expect(svcBoard.arkBalance < appArkBalanceBefore, isTrue,
            reason: 'app ark balance should drop after sending to Bob');

        // Poll Bob's balance — the off-chain transfer settles in <30s.
        final bobDeadline = DateTime.now().add(const Duration(seconds: 30));
        var bobNow = await bob.spendableSats();
        while (bobNow < bobBalanceBefore + 5000 &&
            DateTime.now().isBefore(bobDeadline)) {
          await tester.pump(const Duration(seconds: 2));
          bobNow = await bob.spendableSats();
        }
        expect(bobNow, greaterThanOrEqualTo(bobBalanceBefore + 5000),
            reason: 'Bob should have received the 5000-sat VTXO');

        // ── Ark receive (Bob → App) ─────────────────────────────────
        // Send small (3000 sats) — Bob's boarding-output settle into VTXO is
        // currently flaky in ark-client-sample, so he only has the change/
        // received VTXOs. 3000 fits comfortably under that.
        final myArkAddress = svcBoard.arkAddress!;
        final appArkBalanceMid = svcBoard.arkBalance;
        await bob.sendTo(myArkAddress, 3000);
        await waitForArkBalance(
          tester,
          appArkBalanceMid + BigInt.from(2500),
          timeout: const Duration(seconds: 60),
        );

        // ── A receive re-arms the renewal ───────────────────────────
        //
        // This used to drive PushService.handleBackgroundMessageForTest and
        // assert the background isolate had stored a delegate. Both ends of
        // that are gone: the isolate cannot drive an ASP batch round, and the
        // cosigner could not have used a stored delegate by itself anyway —
        // a Wasm guest has no egress, so waking its owner is what it does
        // instead. The renewal happens in the foreground now, which is what
        // this exercises.
        //
        // 1500 sats fits Bob's residual budget after the 3000-sat send above.
        final preBgArkBalance = svcBoard.arkBalance;
        await bob.sendTo(myArkAddress, 1500);
        await Future<void>.delayed(const Duration(seconds: 15));

        // A fresh outpoint makes the sealed renewal stale, so refreshVtxos ->
        // _delegateIfNeeded settles again and re-arms it.
        await svcBoard.refreshVtxos();
        final bgDeadline = DateTime.now().add(const Duration(minutes: 3));
        while (!svcBoard.fundsProtected &&
            DateTime.now().isBefore(bgDeadline)) {
          await tester.pump(const Duration(seconds: 1));
          await svcBoard.refreshVtxos();
        }
        expect(svcBoard.arkBalance, greaterThanOrEqualTo(
            preBgArkBalance + BigInt.from(1000)),
            reason: 'Alice should hold Bob\'s 1500-sat VTXO (after fees)');
        expect(svcBoard.fundsProtected, isTrue,
            reason:
                'a fresh outpoint should have triggered a settle, leaving a '
                'renewal that covers it. If false, _delegateIfNeeded did not '
                'run or the settle round failed — the round waits on the ASP\'s '
                'own schedule, so give it longer before suspecting the wiring.');
      }
    },
    timeout: const Timeout(Duration(minutes: 12)),
  );
}
