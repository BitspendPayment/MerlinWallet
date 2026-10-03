import 'package:app/screens/send/payout_form_screen.dart';
import 'package:app/services/payout_service.dart';
import 'package:app_core/platform/platform_client.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('amounts', () {
    test('an amount typed in the currency is its minor units', () {
      expect(toMinor('1500', 2), 150000);
      expect(toMinor('1,500.5', 2), 150050);
      expect(toMinor(' 0.05 ', 2), 5);
      expect(toMinor('.5', 2), 50);
      expect(toMinor('5.', 2), 500);
      expect(toMinor('7', 0), 7);
    });

    test('what is not an amount in that currency is refused', () {
      for (final t in ['', '.', 'abc', '-5', '1e3', '1.5.0', '1.234']) {
        expect(toMinor(t, 2), isNull, reason: t);
      }
      expect(toMinor('7.5', 0), isNull);
    });

    /// A comma groups thousands or it is refused — never a decimal point read a hundred times
    /// too large.
    test('a comma where a decimal point belongs is refused, not misread', () {
      expect(toMinor('1500,50', 2), isNull);
      expect(toMinor('1,50', 2), isNull);
      expect(toMinor('12,345,678', 2), 1234567800);
    });

    test('minor units read back as they would be typed', () {
      expect(plainAmount(150050, 2), '1500.50');
      expect(plainAmount(5, 2), '0.05');
      expect(plainAmount(7, 0), '7');
      for (final m in [0, 1, 99, 100, 150050, 150000000]) {
        expect(toMinor(plainAmount(m, 2), 2), m, reason: '$m');
      }
    });

    test('an amount is shown in its currency', () {
      expect(formatMinor(150050, 'NGN', 2), contains('1,500.50'));
    });
  });

  group('the form', () {
    final phone = RailField({
      'key': 'phoneNumber',
      'label': 'M-PESA number',
      'prefix': '+254',
      'digits': {'min': 9, 'max': 9},
    });
    final account = RailField({
      'key': 'accountNumber',
      'label': 'Account number',
      'digits': {'min': 10, 'max': 10},
    });
    final bank = RailField({'key': 'bankName', 'label': 'Bank', 'from_bank_list': true});

    test('a phone number is sent with its prefix, however it was typed', () {
      expect(fieldValue(phone, '712 345 678'), '+254712345678');
      expect(fieldValue(phone, '+254 712-345-678'), '+254712345678');
      expect(fieldValue(phone, '0712345678'), '+254712345678');
    });

    test('digits are checked before a quote is asked for', () {
      String? check(RailField f, String typed) => fieldError(f, fieldValue(f, typed));
      expect(check(phone, '712345678'), isNull);
      expect(check(phone, '71234567'), 'Must be 9 digits after +254');
      expect(check(phone, '71234567a'), 'Digits only after +254');
      expect(check(phone, ''), 'Required');
      expect(check(account, '0123 456 789'), isNull);
      expect(check(account, '012345678'), 'Must be 10 digits');
    });

    test('a bank name is sent exactly as it was picked', () {
      expect(fieldValue(bank, 'Gcb Bank Ltd'), 'Gcb Bank Ltd');
      expect(fieldError(bank, ''), 'Required');
      expect(fieldError(bank, 'Gcb Bank Ltd'), isNull);
    });

    test('the amount has to be one the rail takes', () {
      final ng = Corridor({
        'country': 'NG',
        'name': 'Nigeria',
        'currency': 'NGN',
        'decimals': 2,
        'rails': [
          {'rail': 'bank', 'min_minor': 150000, 'max_minor': 150000000},
        ],
      });
      final rail = ng.rails.single;
      expect(amountError('1500', ng, rail), isNull);
      expect(amountError('1,500,000.00', ng, rail), isNull);
      expect(amountError('1499.99', ng, rail), startsWith('At least'));
      expect(amountError('1500000.01', ng, rail), startsWith('At most'));
      expect(amountError('0', ng, rail), startsWith('Enter an amount'));
      expect(amountError('1500,50', ng, rail), startsWith('Enter an amount'));
    });

    test("the recipient's name is required, and no longer than Grid takes", () {
      expect(nameError('  '), 'Required');
      expect(nameError('Ada Obi'), isNull);
      expect(nameError('a' * 251), isNotNull);
    });
  });
}
