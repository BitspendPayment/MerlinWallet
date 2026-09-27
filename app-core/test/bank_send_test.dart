import 'package:app_core/asp/ark_info.dart';
import 'package:app_core/platform/bank_send.dart';
import 'package:test/test.dart';

IndexerVtxo vtxo(int sats, {bool spent = false}) => IndexerVtxo(
      txid: '11' * 32,
      vout: 0,
      amountSats: sats,
      script: '',
      isSpent: spent,
      createdAt: 0,
      expiresAt: 0,
    );

void main() {
  test('an empty escrow is topped up by the whole price', () {
    expect(BankSend.shortfall(23010, const []), 23010);
  });

  test('what the escrow already holds counts toward the price, and spent coins do not', () {
    expect(BankSend.shortfall(23010, [vtxo(20000)]), 3010);
    expect(BankSend.shortfall(23010, [vtxo(20000), vtxo(5000, spent: true)]), 3010);
    expect(BankSend.shortfall(23010, [vtxo(30000)]), 0);
  });

  test('a top-up is never smaller than the ASP accepts', () {
    expect(BankSend.shortfall(23010, [vtxo(23000)], dust: 330), 330);
  });

  test('the owner is told how many approvals a send will take', () {
    expect(BankSend.approvalsNeeded(hasEscrow: false, shortfall: 23010), 5);
    expect(BankSend.approvalsNeeded(hasEscrow: true, shortfall: 23010), 2);
    expect(BankSend.approvalsNeeded(hasEscrow: true, shortfall: 0), 1);
  });

  test('a deal tag is 16 random bytes, and never the same twice', () {
    final a = BankSend.newDealTag(), b = BankSend.newDealTag();
    expect(a, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(a, isNot(b));
  });
}
