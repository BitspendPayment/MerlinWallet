import 'dart:math' show max;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../../services/payout_service.dart';
import 'payout_form_screen.dart' show openPayoutForm;
import 'send_widgets.dart';

/// One payout, step by step as it goes, and its receipt once it is done. The work carries on in
/// PayoutService whether this screen is open or not.
class PayoutProgressScreen extends StatefulWidget {
  const PayoutProgressScreen({super.key, required this.dealTag});
  final String dealTag;

  @override
  State<PayoutProgressScreen> createState() => _PayoutProgressScreenState();
}

enum _StepState { done, active, failed, waiting }

class _PayoutProgressScreenState extends State<PayoutProgressScreen> {
  /// What the escrow still holds, asked for once the payout has failed.
  Future<int>? _left;
  bool _returning = false;

  Future<void> _return(Payout p) async {
    final payouts = context.read<PayoutService>();
    final messenger = ScaffoldMessenger.of(context);
    final until = p.holdUntil;
    if (until != null && until.isAfter(DateTime.now())) {
      messenger.showSnackBar(SnackBar(
          content: Text('The deal holds your escrow until ${DateFormat.Hm().format(until)}. '
              'You can take it back after that.')));
      return;
    }
    setState(() => _returning = true);
    try {
      final back = await payouts.returnLeftover(p);
      messenger.showSnackBar(SnackBar(
          content: Text(back > 0
              ? 'Returned ${formatSats(back)} sats to your balance'
              : 'Nothing was left to return')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text(plainError(e))));
    } finally {
      if (mounted) {
        setState(() {
          _returning = false;
          _left = null;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final payouts = context.watch<PayoutService>();
    final p = payouts.payout(widget.dealTag);
    if (p == null) {
      return Scaffold(
        appBar: AppBar(),
        body: Center(
          child: Text('This payout is no longer on this phone.',
              style: GoogleFonts.inter(color: Colors.white54)),
        ),
      );
    }
    final escrow = p.escrowKey;
    if (p.failed && p.leftoverSats == null && escrow != null) _left ??= payouts.heldSats(escrow);

    return Scaffold(
      appBar: AppBar(
        title: Text(
          p.state == 'repaid'
              ? 'Sent'
              : p.failed
                  ? 'Not sent'
                  : 'Sending',
          style: GoogleFonts.inter(fontWeight: FontWeight.w600),
        ),
        centerTitle: true,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Expanded(
                child: ListView(
                  children: [
                    Text(
                      p.amount,
                      textAlign: TextAlign.center,
                      style: GoogleFonts.inter(
                          fontSize: 32, fontWeight: FontWeight.bold, color: Colors.white),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'to ${p.fullName}',
                      textAlign: TextAlign.center,
                      style: GoogleFonts.inter(fontSize: 16, color: Colors.white),
                    ),
                    Text(
                      p.destination,
                      textAlign: TextAlign.center,
                      style: GoogleFonts.inter(fontSize: 13, color: Colors.white54),
                    ),
                    const SizedBox(height: 24),
                    SendCard(children: _steps(p)),
                    if (p.state == 'repaid') ...[
                      const SizedBox(height: 16),
                      _receipt(p),
                    ],
                    if (p.failed && p.escrowKey != null) ...[
                      const SizedBox(height: 16),
                      _leftover(p),
                    ],
                    if (!p.finished) ...[
                      const SizedBox(height: 16),
                      Text(
                        'You can leave this screen: the payout carries on, and shows under '
                        'Send money.',
                        textAlign: TextAlign.center,
                        style: GoogleFonts.inter(color: Colors.white38, fontSize: 12),
                      ),
                    ],
                  ],
                ),
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  if (p.finished) ...[
                    Expanded(
                      child: OutlinedButton(
                        key: const Key('payoutSendAgainBtn'),
                        onPressed: () => openPayoutForm(context, p, replace: true),
                        style:
                            OutlinedButton.styleFrom(side: const BorderSide(color: Colors.white24)),
                        child: const Text('Send again'),
                      ),
                    ),
                    const SizedBox(width: 12),
                  ],
                  Expanded(
                    child: ElevatedButton(
                      key: const Key('payoutDoneBtn'),
                      onPressed: () => context.go('/'),
                      child: const Text('Done'),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  List<Widget> _steps(Payout p) {
    const steps = payoutSteps;
    final at = p.step == 'done' ? steps.length : max(0, steps.indexOf(p.step));
    return [
      for (final (i, s) in steps.indexed)
        _StepRow(
          title: switch (s) {
            'policy' => "Check the platform's terms",
            'seal' => 'Set up an escrow, seal the deal and send it ${formatSats(p.sats)} sats',
            'fund' => 'The platform pays',
            'pay' => 'Paid out to ${p.fullName}',
            _ => 'The platform is repaid · ${formatSats(p.sats)} sats',
          },
          state: i < at
              ? _StepState.done
              : i > at
                  ? _StepState.waiting
                  : p.failed
                      ? _StepState.failed
                      : _StepState.active,
          detail: i != at
              ? null
              : p.failed
                  ? p.failure ?? 'It did not go through.'
                  : switch (s) {
                      'policy' => 'That it holds the platform to what you agreed',
                      'seal' => 'Approve twice with your passkey',
                      'fund' => p.note ?? 'It checks it will be repaid, then pays',
                      'pay' => p.gridStatus == null
                          ? 'Waiting for the money to arrive'
                          : 'Grid: ${p.gridStatus}',
                      _ => 'Out of your escrow: the agreed price, and no more',
                    },
        ),
    ];
  }

  Widget _receipt(Payout p) {
    final txid = p.arkTxid;
    return SendCard(children: [
      Text('Receipt',
          style: GoogleFonts.inter(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white)),
      const SizedBox(height: 12),
      DetailRow('Amount', p.amount),
      DetailRow('Recipient', p.fullName),
      DetailRow(p.rail == 'mobile_money' ? 'Wallet' : 'Account', p.destination),
      if (p.nameAtBank != null) DetailRow('Name at the bank', p.nameAtBank!),
      DetailRow('Paid from your escrow', '${formatSats(p.sats)} sats'),
      if (p.gridStatus != null) DetailRow('Grid status', p.gridStatus!),
      if (txid != null)
        GestureDetector(
          onTap: () {
            Clipboard.setData(ClipboardData(text: txid));
            ScaffoldMessenger.of(context)
                .showSnackBar(const SnackBar(content: Text('Repayment ID copied')));
          },
          child: DetailRow(
            'Repayment',
            txid.length > 16 ? '${txid.substring(0, 16)}…' : txid,
            trailing: const Icon(Icons.copy, color: Colors.white38, size: 14),
          ),
        ),
      DetailRow('Date', DateFormat('MMM d, HH:mm').format(p.createdAt)),
    ]);
  }

  /// A failed payout leaves what its escrow was sent there, to come back to the balance once its
  /// deal is over.
  Widget _leftover(Payout p) {
    final returned = p.leftoverSats;
    final text = GoogleFonts.inter(color: Colors.white70, fontSize: 13, height: 1.4);
    if (returned != null) {
      return SendCard(children: [
        Text(
          returned > 0
              ? 'Returned ${formatSats(returned)} sats to your balance.'
              : 'Nothing was left in your escrow.',
          style: text,
        ),
      ]);
    }
    return SendCard(children: [
      FutureBuilder<int>(
        future: _left,
        builder: (context, snap) {
          if (snap.hasError) return Text(plainError(snap.error!), style: text);
          final held = snap.data;
          if (held == null) return Text('Checking what your escrow still holds…', style: text);
          if (held == 0) return Text('Nothing of yours was left in the escrow.', style: text);
          final until = p.holdUntil;
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                "This payment's escrow still holds ${formatSats(held)} sats. Take it back into "
                'your balance.',
                style: text,
              ),
              if (until != null && until.isAfter(DateTime.now())) ...[
                const SizedBox(height: 8),
                Text(
                  'The deal holds it until ${DateFormat.Hm().format(until)}.',
                  style: GoogleFonts.inter(color: Colors.amberAccent, fontSize: 12),
                ),
              ],
              const SizedBox(height: 12),
              OutlinedButton(
                key: const Key('payoutReturnLeftoverBtn'),
                onPressed: _returning ? null : () => _return(p),
                style: OutlinedButton.styleFrom(side: const BorderSide(color: Colors.white24)),
                child: Text(_returning ? 'Returning…' : 'Return leftover to balance'),
              ),
            ],
          );
        },
      ),
    ]);
  }
}

class _StepRow extends StatelessWidget {
  const _StepRow({required this.title, required this.state, this.detail});
  final String title;
  final _StepState state;
  final String? detail;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 14),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 20,
            height: 20,
            child: switch (state) {
              _StepState.done =>
                const Icon(Icons.check_circle, color: Colors.greenAccent, size: 20),
              _StepState.active => const Padding(
                  padding: EdgeInsets.all(2),
                  child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                ),
              _StepState.failed => const Icon(Icons.cancel, color: Colors.redAccent, size: 20),
              _StepState.waiting =>
                const Icon(Icons.radio_button_unchecked, color: Colors.white24, size: 20),
            },
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: GoogleFonts.inter(
                    color: state == _StepState.waiting ? Colors.white38 : Colors.white,
                    fontWeight: FontWeight.w500,
                    fontSize: 14,
                  ),
                ),
                if (detail != null)
                  Text(
                    detail!,
                    style: GoogleFonts.inter(
                      color: state == _StepState.failed ? Colors.redAccent : Colors.white54,
                      fontSize: 12,
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
