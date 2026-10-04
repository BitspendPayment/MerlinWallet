// One end-to-end testWidgets covering the user lifecycle:
//   server → passkey → DKG → exit address → Ark board → the cosigner renews on its own → an entry
//   to the app re-arms the renewal.

// ignore_for_file: avoid_print

import 'package:app/services/mpc_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:provider/provider.dart';

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
      // before the wallet opens because every later renewal pre-signs a spend to it.
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

        // Boarding re-arms the renewal on its way out, on the same approval: the board stream
        // renews the delegate once the indexer shows the new VTXO.
        await svcBoard.refreshVtxos();
        final delegDeadline =
            DateTime.now().add(const Duration(seconds: 30));
        while (!svcBoard.fundsProtected &&
            DateTime.now().isBefore(delegDeadline)) {
          await tester.pump(const Duration(seconds: 1));
        }
        expect(svcBoard.fundsProtected, isTrue,
            reason: 'boarding should have renewed the delegate on its way out. If false, its '
                'trailing renewal gave up: the indexer was slow, or the renewal failed.');

        // ── The exits are real ───────────────────────────────────────
        //
        // Renewing a delegate also signs one unilateral exit per VTXO. This is the thing the
        // cosigner cannot be asked for later: if it stops answering, these are the money.
        expect(svcBoard.exits, isNotEmpty,
            reason: 'boarding renewed the delegate, which must also have signed an exit');
        expect(svcBoard.vtxosWithoutExit, isEmpty,
            reason: 'every held VTXO should have an exit after a renewal');
        final boardedExit = svcBoard.exits.first;
        expect(boardedExit.rawTx, isNotEmpty);
        expect(boardedExit.amountSats, greaterThan(0));
        expect(boardedExit.sequence, greaterThan(0),
            reason: 'an exit waits out its VTXO\'s exit delay');

        // ── The cosigner renews on its own, and the next entry re-arms ──
        //
        // The delegate boarding signed is worth one renewal. The cosigner runs it before the VTXO
        // expires — on regtest, about five minutes after the VTXO was made — and the VTXO that
        // produces has no delegate: only the owner's passkey can sign the next. Every entry to the
        // app asks for that passkey, and re-arms with it.
        final renewedBy = DateTime.now().add(const Duration(minutes: 8));
        while (svcBoard.fundsProtected && DateTime.now().isBefore(renewedBy)) {
          await tester.pump(const Duration(seconds: 5));
          await svcBoard.refreshVtxos();
        }
        expect(svcBoard.fundsProtected, isFalse,
            reason: 'the cosigner should have run its delegate, leaving a VTXO nothing covers');

        // An entry. The lock asks for the passkey by itself — approve it on the device — and the
        // approval re-arms the renewal.
        svcBoard.lock();
        await pumpUntilFound(tester, find.byKey(const Key('unlockBtn')));
        final unlockedBy = DateTime.now().add(const Duration(minutes: 2));
        while (svcBoard.locked && DateTime.now().isBefore(unlockedBy)) {
          await tester.pump(const Duration(seconds: 1));
        }
        expect(svcBoard.locked, isFalse, reason: 'the passkey given, the lock lifts');
        final armedBy = DateTime.now().add(const Duration(minutes: 1));
        while ((!svcBoard.fundsProtected || svcBoard.vtxosWithoutExit.isNotEmpty) &&
            DateTime.now().isBefore(armedBy)) {
          await tester.pump(const Duration(seconds: 1));
          await svcBoard.refreshVtxos();
        }
        expect(svcBoard.fundsProtected, isTrue,
            reason: 'the entry re-armed the renewal over what the cosigner produced');
        expect(svcBoard.vtxosWithoutExit, isEmpty,
            reason: 'and signed its exit with the same approval');

        // ── The Exit tab shows them ─────────────────────────────────
        await ExitPage.open(tester);
        await tester.pumpAndSettle();
        expect(find.text('Your exit address'), findsOneWidget);
        expect(find.byKey(const Key('exitCopyBtn')), findsWidgets,
            reason: 'each signed exit can be copied out of the app');
      }
    },
    // Boarding, then the cosigner's own renewal about five minutes after it, then an entry.
    timeout: const Timeout(Duration(minutes: 20)),
  );
}
