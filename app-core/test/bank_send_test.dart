import 'package:app_core/platform/bank_send.dart';
import 'package:test/test.dart';

void main() {
  test('the owner is told how many approvals a send will take', () {
    // One stream sets the payout's escrow up and funds it, on one approval.
    expect(BankSend.approvals, 1);
  });

  test('a deal tag is 16 random bytes, and never the same twice', () {
    final a = BankSend.newDealTag(), b = BankSend.newDealTag();
    expect(a, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(a, isNot(b));
  });
}
