import 'dart:convert';

import 'package:app_core/platform/platform_client.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

void main() {
  final base = Uri.parse('http://127.0.0.1:7200');

  test('a quote goes out with what the sender typed and comes back typed', () async {
    late Map<String, dynamic> sent;
    final platform = PlatformClient(base, client: MockClient((request) async {
      expect(request.method, 'POST');
      expect(request.url.path, '/payouts');
      sent = jsonDecode(request.body) as Map<String, dynamic>;
      return http.Response(
        jsonEncode({
          'request_id': 'reimb-0001',
          'deal_tag': sent['deal_tag'],
          'external_account_id': 'ExternalAccount:1',
          'payee': {'name_given': 'Ada Obi', 'name_at_bank': 'ADA OBI', 'name_check': 'MATCHED'},
          'currency': 'NGN',
          'amount_minor': 3000000,
          'sats': 23010,
          'expires_at': '2026-09-27T12:00:00Z',
          'deal_seconds': 1800,
          'policy': {'op': 'never'},
        }),
        200,
      );
    }));
    final quote = await platform.quote(
      country: 'NG',
      rail: 'bank',
      fields: const {'accountNumber': '0123456789', 'bankName': 'OPay'},
      fullName: 'Ada Obi',
      amountMinor: 3000000,
      dealTag: 'tag',
    );
    expect(sent['fields'], {'accountNumber': '0123456789', 'bankName': 'OPay'});
    expect(sent['amount_minor'], 3000000);
    expect(sent.containsKey('escrow_key'), isFalse, reason: 'a quote comes before any escrow');
    expect(quote.sats, 23010);
    expect(quote.nameAtBank, 'ADA OBI');
    expect(quote.nameCheck, 'MATCHED');
    expect(quote.dealTag, 'tag');
  });

  test('a refusal is told apart from a platform that is down', () async {
    final refusing = PlatformClient(base,
        client: MockClient((_) async => http.Response('{"error":"no such bank"}', 400)));
    await expectLater(
      refusing.status('tag'),
      throwsA(isA<PlatformException>()
          .having((e) => e.refused, 'refused', isTrue)
          .having((e) => e.message, 'message', 'no such bank')),
    );
    final down = PlatformClient(base, client: MockClient((_) async => throw Exception('refused')));
    await expectLater(
        down.corridors(), throwsA(isA<PlatformException>().having((e) => e.refused, 'refused', isFalse)));
  });

  test('corridors and their fields read the way the forms need them', () async {
    final platform = PlatformClient(base, client: MockClient((_) async => http.Response(
        jsonEncode({'countries': [
          {
            'country': 'KE',
            'name': 'Kenya',
            'currency': 'KES',
            'decimals': 2,
            'rails': [
              {
                'rail': 'mobile_money',
                'fields': [
                  {
                    'key': 'phoneNumber',
                    'label': 'Phone number',
                    'prefix': '+254',
                    'digits': {'min': 9, 'max': 9},
                  },
                  {'key': 'provider', 'label': 'Provider', 'options': ['M-PESA']},
                ],
              }
            ],
          }
        ]}),
        200)));
    final kenya = (await platform.corridors()).single;
    expect(kenya.currency, 'KES');
    final rail = kenya.rails.single;
    expect(rail.kind, 'mobile_money');
    expect(rail.fields.map((f) => f.key), ['phoneNumber', 'provider']);
    expect(rail.fields.last.options, ['M-PESA']);
    expect(rail.fields.first.prefix, '+254');
    expect(rail.fields.first.minDigits, 9);
  });
}
