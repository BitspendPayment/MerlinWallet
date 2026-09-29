// One end-to-end testWidgets covering the user lifecycle:
//   server → passkey → DKG → exit address → Ark board/send/receive.

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
      final btc = RegtestHelper();
      await btc.ensureWalletLoaded('default');

      // ── Onboarding ───────────────────────────────────────────────────────
      //
      // The wallet is Ark-only now: there is no on-chain balance, no on-chain send, and no home
      // screen for either. What onboarding gained instead is the exit address, which is asked for
      // before the wallet opens because every later seal pre-signs a spend to it.
      await resetAppState();
      await bootApp(tester);
      final exitAddress = await btc.getNewAddress();
      await Flows.completeOnboarding(tester, exitAddress: exitAddress);
      await pumpUntilFound(tester, find.byKey(const Key('arkSendMoneyBtn')));

      final ctxOnboard = tester.element(find.byKey(const Key('arkSendMoneyBtn')));
      final service = Provider.of<MpcService>(ctxOnboard, listen: false);
      expect(service.exitAddress, exitAddress,
          reason: 'the address given at onboarding is what exits will pay');

      final minerAddr = await btc.getNewAddress();

      // ── Ark boarding (skipped when ASP not configured) ──────────────────
      final arkAvailable = find.text('Ark Not Available').evaluate().isEmpty;
      if (!arkAvailable) {
        print('Ark not available — skipping ark sub-flow');
      } else {
        await ArkPage.tapBoard(tester);
        await pumpUntilFound(tester, find.byKey(const Key('arkBoardNowBtn')));

        final svcBoard = service;
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
        await pumpUntilFound(tester, find.byKey(const Key('arkSendMoneyBtn')));
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

        // ── The exits are real ───────────────────────────────────────
        //
        // Sealing a delegate also signs one unilateral exit per VTXO. This is the thing the
        // cosigner cannot be asked for later: if it stops answering, these are the money.
        expect(svcBoard.exits, isNotEmpty,
            reason: 'boarding sealed a delegate, which must also have signed an exit');
        expect(svcBoard.vtxosWithoutExit, isEmpty,
            reason: 'every held VTXO should have an exit after a seal');
        final boardedExit = svcBoard.exits.first;
        expect(boardedExit.rawTx, isNotEmpty);
        expect(boardedExit.amountSats, greaterThan(0));
        expect(boardedExit.sequence, greaterThan(0),
            reason: 'an exit waits out its VTXO\'s exit delay');

        final bob = BobClient();

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
        expect(svcBoard.vtxosWithoutExit, isEmpty,
            reason: 'the seal that covered the received funds also signed their exit');

        // ── The Exit tab shows them ─────────────────────────────────
        await ExitPage.open(tester);
        await tester.pumpAndSettle();
        expect(find.text('Your exit address'), findsOneWidget);
        expect(find.byKey(const Key('exitCopyBtn')), findsWidgets,
            reason: 'each signed exit can be copied out of the app');
      }
    },
    timeout: const Timeout(Duration(minutes: 12)),
  );
}
