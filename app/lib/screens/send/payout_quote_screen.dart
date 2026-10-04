import 'package:app_core/platform/bank_send.dart' show BankSend;
import 'package:app_core/platform/platform_client.dart' show PayoutQuote;
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../../services/mpc_service.dart';
import '../../services/payout_service.dart';
import 'send_widgets.dart';

/// The platform's price for a payout, and what to check before agreeing to it.
///
/// Getting a price sets nothing up and costs no approval: the payout's escrow is minted when the
/// owner confirms.
class PayoutQuoteScreen extends StatefulWidget {
  const PayoutQuoteScreen({super.key, required this.draft});
  final PayoutDraft draft;

  @override
  State<PayoutQuoteScreen> createState() => _PayoutQuoteScreenState();
}

class _PayoutQuoteScreenState extends State<PayoutQuoteScreen> {
  bool _loading = true;
  PayoutQuote? _quote;
  Object? _error;
  bool _understood = false;
  bool _sending = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final payouts = context.read<PayoutService>();
    try {
      await payouts.ready;
      final quote = await payouts.quote(widget.draft);
      if (!mounted) return;
      setState(() {
        _quote = quote;
        _understood = false;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e;
        _loading = false;
      });
    }
  }

  /// Again from the start. A new price is a new quote, under a new deal tag.
  void _retry() {
    setState(() {
      _error = null;
      _quote = null;
      _loading = true;
    });
    _load();
  }

  Future<void> _confirm() async {
    final quote = _quote!;
    // Checked on the tap, since the screen does not tick: rebuilt, it shows the price as expired.
    if (DateTime.now().isAfter(quote.expiresAt)) {
      setState(() {});
      return;
    }
    setState(() {
      _sending = true;
      _error = null;
    });
    try {
      final tag = await context.read<PayoutService>().start(widget.draft, quote);
      if (mounted) context.pop(tag);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _sending = false;
        _error = e;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Review', style: GoogleFonts.inter(fontWeight: FontWeight.w600)),
        centerTitle: true,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: _loading
              ? _waiting()
              : _quote == null
                  ? _failed()
                  : _review(),
        ),
      ),
    );
  }

  Widget _waiting() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(
            width: 64,
            height: 64,
            child: CircularProgressIndicator(strokeWidth: 3),
          ),
          const SizedBox(height: 24),
          Text(
            'Getting a price…',
            style:
                GoogleFonts.inter(fontSize: 18, fontWeight: FontWeight.w600, color: Colors.white),
          ),
          const SizedBox(height: 12),
          Text(
            'Asking the payout service what this costs.',
            textAlign: TextAlign.center,
            style: GoogleFonts.inter(color: Colors.white54, fontSize: 14),
          ),
        ],
      ),
    );
  }

  Widget _failed() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SendNotice(
          icon: Icons.error_outline,
          color: Colors.redAccent,
          text: plainError(_error ?? 'No price came back.'),
        ),
        const SizedBox(height: 24),
        ElevatedButton(onPressed: _retry, child: const Text('Try again')),
        const SizedBox(height: 12),
        OutlinedButton(
          onPressed: () => context.pop(),
          style: OutlinedButton.styleFrom(side: const BorderSide(color: Colors.white24)),
          child: const Text('Back'),
        ),
      ],
    );
  }

  Widget _review() {
    final d = widget.draft, q = _quote!;
    final balance = context.watch<MpcService>().arkBalance.toInt();
    final matched = q.nameCheck == 'MATCHED';
    final affordable = q.sats <= balance;
    final expired = DateTime.now().isAfter(q.expiresAt);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Expanded(
          child: ListView(
            children: [
              SendCard(children: [
                Text('You send', style: sendLabelStyle()),
                const SizedBox(height: 4),
                Text(
                  d.amount,
                  style: GoogleFonts.inter(
                      fontSize: 32, fontWeight: FontWeight.bold, color: Colors.white),
                ),
                const SizedBox(height: 4),
                Text(
                  'to ${d.fullName}',
                  style: GoogleFonts.inter(
                      fontSize: 16, fontWeight: FontWeight.w500, color: Colors.white),
                ),
                Text(
                  d.fields.values.join(' · '),
                  style: GoogleFonts.inter(color: Colors.white54, fontSize: 13),
                ),
              ]),
              const SizedBox(height: 12),
              _nameCheck(q),
              const SizedBox(height: 12),
              SendCard(children: [
                DetailRow('Price', '${formatSats(q.sats)} sats'),
                DetailRow('Your balance', '${formatSats(balance)} sats'),
                DetailRow('Price good until', DateFormat.Hm().format(q.expiresAt.toLocal())),
              ]),
              const SizedBox(height: 12),
              Text(
                "You'll approve ${approvalTimes(BankSend.approvals)} with your passkey: that sets "
                'up an escrow for this payment, seals the deal and sends it the price.',
                style: GoogleFonts.inter(color: Colors.white54, fontSize: 13),
              ),
              if (!affordable) ...[
                const SizedBox(height: 12),
                SendNotice(
                  icon: Icons.account_balance_wallet_outlined,
                  color: Colors.redAccent,
                  text: 'Not enough in your wallet: this takes ${formatSats(q.sats)} sats '
                      'from your balance.',
                ),
              ],
              if (expired) ...[
                const SizedBox(height: 12),
                const SendNotice(
                  icon: Icons.timer_off_outlined,
                  color: Colors.amberAccent,
                  text: 'This price has expired. Get a new one to go on.',
                ),
              ],
              if (_error != null) ...[
                const SizedBox(height: 12),
                SendNotice(
                  icon: Icons.error_outline,
                  color: Colors.redAccent,
                  text: plainError(_error!),
                ),
              ],
              if (!matched)
                CheckboxListTile(
                  key: const Key('payoutUnderstoodBox'),
                  value: _understood,
                  onChanged: (v) => setState(() => _understood = v ?? false),
                  controlAffinity: ListTileControlAffinity.leading,
                  contentPadding: EdgeInsets.zero,
                  title: Text('I understand, send anyway',
                      style: GoogleFonts.inter(color: Colors.white, fontSize: 14)),
                ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        if (expired)
          ElevatedButton(onPressed: _retry, child: const Text('Get a new price'))
        else
          ElevatedButton(
            key: const Key('payoutConfirmBtn'),
            onPressed: !_sending && affordable && (matched || _understood) ? _confirm : null,
            child: Text(_sending ? 'Sending…' : 'Confirm and send'),
          ),
      ],
    );
  }

  /// Who the bank says the account is. The platform refuses a clear mismatch itself; anything
  /// short of a match is the owner's to accept.
  Widget _nameCheck(PayoutQuote q) {
    final (badge, color) = switch (q.nameCheck) {
      'MATCHED' => ('Name matches', Colors.greenAccent),
      'PARTIAL_MATCH' => ('Partly matches', Colors.amberAccent),
      final String other => (other.toLowerCase().replaceAll('_', ' '), Colors.amberAccent),
      null => ('Not checked', Colors.amberAccent),
    };
    return SendCard(children: [
      Row(
        children: [
          Expanded(child: Text('Name at the bank', style: sendLabelStyle())),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Text(
              badge,
              style: GoogleFonts.inter(color: color, fontSize: 12, fontWeight: FontWeight.bold),
            ),
          ),
        ],
      ),
      const SizedBox(height: 4),
      Text(
        q.nameAtBank ?? 'Not given',
        style: GoogleFonts.inter(fontSize: 16, fontWeight: FontWeight.w500, color: Colors.white),
      ),
      if (q.nameCheck != 'MATCHED') ...[
        const SizedBox(height: 8),
        Text(
          'Make sure this is who you mean to pay. Money sent to the wrong account usually '
          'cannot be got back.',
          style: GoogleFonts.inter(color: Colors.white54, fontSize: 12),
        ),
      ],
    ]);
  }
}
