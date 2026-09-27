import 'package:app/screens/send/payout_form_screen.dart';
import 'package:app/services/mpc_service.dart';
import 'package:app/services/payout_service.dart';
import 'package:app_core/platform/platform_client.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

/// The form as the platform describes a rail, with no wallet behind it: it asks nothing of one
/// until Continue passes its checks.
Future<void> _pumpForm(WidgetTester tester, Map<String, dynamic> corridor) async {
  final c = Corridor(corridor);
  final mpc = MpcService();
  await tester.pumpWidget(MultiProvider(
    providers: [
      ChangeNotifierProvider.value(value: mpc),
      ChangeNotifierProvider(create: (_) => PayoutService(mpc)),
    ],
    child: MaterialApp(home: PayoutFormScreen(args: PayoutFormArgs(c, c.rails.single))),
  ));
}

void main() {
  setUpAll(() => GoogleFonts.config.allowRuntimeFetching = false);

  testWidgets('mobile money: the number is checked, and the only operator is already chosen',
      (tester) async {
    await _pumpForm(tester, {
      'country': 'KE',
      'name': 'Kenya',
      'currency': 'KES',
      'decimals': 2,
      'rails': [
        {
          'rail': 'mobile_money',
          'label': 'M-PESA',
          'min_minor': 13000,
          'max_minor': 13000000,
          'fields': [
            {
              'key': 'phoneNumber',
              'label': 'M-PESA number',
              'prefix': '+254',
              'digits': {'min': 9, 'max': 9},
            },
            {
              'key': 'provider',
              'label': 'Provider',
              'options': ['M-PESA'],
            },
          ],
        },
      ],
    });
    await tester.enterText(find.widgetWithText(TextFormField, 'M-PESA number'), '71234');
    await tester.enterText(find.byKey(const Key('payoutAmountField')), '100');
    await tester.tap(find.byKey(const Key('payoutContinueBtn')));
    await tester.pump();

    expect(find.text('Must be 9 digits after +254'), findsOneWidget);
    expect(find.textContaining('At least'), findsOneWidget);
    expect(find.text('Required'), findsOneWidget); // the recipient's name
    expect(find.text('Choose one'), findsNothing); // M-PESA, the only choice
  });

  testWidgets('bank: the bank has to be picked from the list', (tester) async {
    await _pumpForm(tester, {
      'country': 'NG',
      'name': 'Nigeria',
      'currency': 'NGN',
      'decimals': 2,
      'rails': [
        {
          'rail': 'bank',
          'label': 'Bank account',
          'min_minor': 150000,
          'max_minor': 150000000,
          'fields': [
            {
              'key': 'accountNumber',
              'label': 'Account number',
              'digits': {'min': 10, 'max': 10},
            },
            {'key': 'bankName', 'label': 'Bank', 'from_bank_list': true},
          ],
        },
      ],
    });
    await tester.enterText(find.widgetWithText(TextFormField, 'Account number'), '0123456789');
    await tester.enterText(find.byKey(const Key('payoutNameField')), 'Ada Obi');
    await tester.enterText(find.byKey(const Key('payoutAmountField')), '30,000');
    await tester.tap(find.byKey(const Key('payoutContinueBtn')));
    await tester.pump();

    expect(find.text('Choose one'), findsOneWidget);
    expect(find.textContaining('digits'), findsNothing);
    expect(find.textContaining('At least'), findsNothing);
  });
}
