import 'package:app_core/platform/policy_check.dart';
import 'package:test/test.dart';

const origin = 'http://192.168.127.254:7300';
const api = '/grid/2025-10-13';
const account = 'ExternalAccount:0191e5f7-0000-7000-8000-000000000001';
const tag = '5b7c0e1f9a2d4c6b8e0f1a2b3c4d5e6f';
const price = 23010;

/// A policy shaped the way the platform writes one.
Map<String, dynamic> policyFor(Map<String, String> fields, String currency, int amount) => {
      'op': 'all_of',
      'of': <Map<String, dynamic>>[
        {
          'op': 'outputs_only_to',
          'scripts': ['5120${'ab' * 32}'],
        },
        {'op': 'total_out_max', 'sats': price},
        {'op': 'released_total_max', 'sats': price},
        {'op': 'fee_max', 'sats': 0},
        {
          'op': 'http_get',
          'provider': origin,
          'path': '$api/platform/external-accounts/$account',
          'credentials': 'GRID',
          'expect': <Map<String, dynamic>>[
            for (final f in fields.entries)
              {'is': 'equals', 'at': 'accountInfo.${f.key}', 'value': f.value},
          ],
          'on_unavailable': 'pending',
        },
        {
          'op': 'http_get',
          'provider': origin,
          'path': '$api/transactions/{reference}',
          'credentials': 'GRID',
          'expect': <Map<String, dynamic>>[
            {'is': 'matches_reference', 'at': 'id'},
            {'is': 'equals', 'at': 'type', 'value': 'OUTGOING'},
            {'is': 'equals', 'at': 'description', 'value': tag},
            {'is': 'equals', 'at': 'destination.accountId', 'value': account},
            {'is': 'equals', 'at': 'receivedAmount.currency.code', 'value': currency},
            {'is': 'at_least', 'at': 'receivedAmount.amount', 'value': amount},
            {'is': 'equals', 'at': 'status', 'value': 'COMPLETED'},
          ],
          'on_unavailable': 'pending',
        },
      ],
    };

ExpectedPayout expecting(Map<String, String> fields, String currency, int amount) =>
    ExpectedPayout(
      gridOrigin: origin,
      gridApiPath: api,
      accountId: account,
      payeeFields: fields,
      currency: currency,
      amountMinor: amount,
      dealTag: tag,
      priceSats: price,
    );

const bank = {'accountNumber': '0123456789', 'bankName': 'OPay'};
const mpesa = {'phoneNumber': '+254712345678', 'provider': 'M-PESA'};

List<Map<String, dynamic>> terms(Map<String, dynamic> p) =>
    (p['of'] as List).cast<Map<String, dynamic>>();
Map<String, dynamic> fetch(Map<String, dynamic> p, String pathPart) =>
    terms(p).firstWhere((t) => t['op'] == 'http_get' && (t['path'] as String).contains(pathPart));
List<Map<String, dynamic>> expects(Map<String, dynamic> f) =>
    (f['expect'] as List).cast<Map<String, dynamic>>();

void refused(Map<String, dynamic> policy, Map<String, String> fields, String why) {
  expect(
    () => checkPayoutPolicy(policy, expecting(fields, 'NGN', 3000000)),
    throwsA(isA<PolicyRefused>().having((e) => e.reason, 'reason', contains(why))),
  );
}

void main() {
  test('a naira bank payout the platform wrote honestly passes', () {
    checkPayoutPolicy(policyFor(bank, 'NGN', 3000000), expecting(bank, 'NGN', 3000000));
  });

  test('so does an M-PESA payout, held to the phone and the provider', () {
    checkPayoutPolicy(policyFor(mpesa, 'KES', 150000), expecting(mpesa, 'KES', 150000));
  });

  test('a policy that is not a list of conditions is refused', () {
    refused({'op': 'always'}, bank, 'not a list');
  });

  test('a condition the app cannot read is refused — an any_of could widen everything', () {
    final p = policyFor(bank, 'NGN', 3000000);
    terms(p).add({'op': 'any_of', 'of': []});
    refused(p, bank, 'cannot read');
  });

  test('a cap above the price is refused, even beside one at the price', () {
    final p = policyFor(bank, 'NGN', 3000000);
    terms(p).add({'op': 'released_total_max', 'sats': price * 10});
    refused(p, bank, 'together may take more');
  });

  test('a second destination is refused', () {
    final p = policyFor(bank, 'NGN', 3000000);
    (terms(p).first['scripts'] as List).add('5120${'cd' * 32}');
    refused(p, bank, 'besides the platform');
  });

  test('evidence from anybody but the pinned Grid is refused', () {
    final p = policyFor(bank, 'NGN', 3000000);
    fetch(p, '/transactions/')['provider'] = 'https://platform.example';
    refused(p, bank, 'other than Grid');
  });

  test('a payee held to another account number is refused', () {
    final p = policyFor({...bank, 'accountNumber': '9999999999'}, 'NGN', 3000000);
    refused(p, bank, 'accountNumber');
  });

  test('a payee check that forgets the bank is refused', () {
    final p = policyFor({'accountNumber': '0123456789'}, 'NGN', 3000000);
    refused(p, bank, 'bankName');
  });

  test('a payout in another currency, or for less, is refused', () {
    refused(policyFor(bank, 'GHS', 3000000), bank, 'NGN');
    refused(policyFor(bank, 'NGN', 2999999), bank, 'less than');
  });

  test('a payout for another deal is refused', () {
    final p = policyFor(bank, 'NGN', 3000000);
    expects(fetch(p, '/transactions/'))
        .firstWhere((e) => e['at'] == 'description')['value'] = 'someone-elses-deal';
    refused(p, bank, 'this deal');
  });

  test('a payout that need not have completed is refused', () {
    final p = policyFor(bank, 'NGN', 3000000);
    expects(fetch(p, '/transactions/')).removeWhere((e) => e['at'] == 'status');
    refused(p, bank, 'completed');
  });
}
