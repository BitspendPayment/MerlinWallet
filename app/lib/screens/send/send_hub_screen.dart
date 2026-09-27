import 'package:app_core/platform/platform_client.dart' show Corridor, Rail;
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../../services/payout_service.dart';
import 'payout_form_screen.dart';
import 'send_widgets.dart';

/// Where sending money starts: payouts still going, the people paid lately, then every country the
/// platform pays into.
class SendHubScreen extends StatefulWidget {
  const SendHubScreen({super.key});

  @override
  State<SendHubScreen> createState() => _SendHubScreenState();
}

class _SendHubScreenState extends State<SendHubScreen> {
  Future<List<Corridor>>? _corridors;

  @override
  void initState() {
    super.initState();
    final payouts = context.read<PayoutService>();
    if (payouts.available) _corridors = payouts.corridors();
  }

  void _openForm(Corridor c, Rail r) => context.push('/send/payout', extra: PayoutFormArgs(c, r));

  Future<void> _pickRail(Corridor c) async {
    final rails = c.rails;
    if (rails.length == 1) {
      _openForm(c, rails.single);
      return;
    }
    final rail = await showModalBottomSheet<Rail>(
      context: context,
      backgroundColor: const Color(0xFF1E1E1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 20, 24, 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Send to ${c.name} by',
              style:
                  GoogleFonts.inter(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white),
            ),
            const SizedBox(height: 12),
            for (final r in rails)
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: Icon(_railIcon(r.kind), color: Colors.white70),
                title: Text(r.label, style: GoogleFonts.inter(color: Colors.white)),
                trailing: const Icon(Icons.chevron_right, color: Colors.white38),
                onTap: () => Navigator.of(ctx).pop(r),
              ),
          ],
        ),
      ),
    );
    if (rail != null && mounted) _openForm(c, rail);
  }

  @override
  Widget build(BuildContext context) {
    final payouts = context.watch<PayoutService>();
    return Scaffold(
      appBar: AppBar(
        title: Text('Send money', style: GoogleFonts.inter(fontWeight: FontWeight.w600)),
        centerTitle: true,
      ),
      body: SafeArea(
        child: !payouts.available
            ? const _Message(
                icon: Icons.cloud_off,
                title: 'Not available here',
                body: 'Sending to bank accounts and mobile money is not available on this server '
                    'yet.',
              )
            : ListView(
                padding: const EdgeInsets.all(24),
                children: [
                  if (payouts.pending.isNotEmpty) ...[
                    const _Heading('In progress'),
                    for (final p in payouts.pending) _payoutTile(p),
                    const SizedBox(height: 16),
                  ],
                  FutureBuilder<List<Corridor>>(
                    future: _corridors,
                    builder: (context, snap) {
                      if (snap.hasError) {
                        return _Message(
                          icon: Icons.cloud_off,
                          title: 'Could not load where you can send',
                          body: plainError(snap.error!),
                          action: TextButton(
                            onPressed: () => setState(() => _corridors =
                                context.read<PayoutService>().corridors(refresh: true)),
                            child: const Text('Try again'),
                          ),
                        );
                      }
                      final corridors = snap.data;
                      if (corridors == null) {
                        return const Padding(
                          padding: EdgeInsets.all(32),
                          child: Center(child: CircularProgressIndicator(color: Colors.white)),
                        );
                      }
                      return Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          if (payouts.recipients.isNotEmpty) ...[
                            const _Heading('Recent'),
                            for (final p in payouts.recipients)
                              _Tile(
                                leading:
                                    Text(flag(p.country), style: const TextStyle(fontSize: 20)),
                                title: p.fullName,
                                subtitle: p.destination,
                                onTap: () => openPayoutForm(context, p),
                              ),
                            const SizedBox(height: 16),
                          ],
                          const _Heading('Choose a country'),
                          for (final c in corridors)
                            _Tile(
                              key: Key('sendCountry${c.country}'),
                              leading: Text(flag(c.country), style: const TextStyle(fontSize: 20)),
                              title: c.name,
                              subtitle:
                                  '${c.currency} · ${c.rails.map((r) => r.label).join(' or ')}',
                              onTap: () => _pickRail(c),
                            ),
                        ],
                      );
                    },
                  ),
                ],
              ),
      ),
    );
  }

  Widget _payoutTile(Payout p) {
    final (label, icon, color) = switch (p.state) {
      'failed' => ('Did not go through', Icons.error_outline, Colors.redAccent),
      'paid_out' || 'repaying' => ('Paid out', Icons.check_circle_outline, Colors.greenAccent),
      'paying' => ('Paying out…', Icons.schedule, Colors.white54),
      _ => ('Sending…', Icons.schedule, Colors.white54),
    };
    return _Tile(
      leading: Icon(icon, color: color, size: 20),
      title: '${p.amount} to ${p.fullName}',
      subtitle: label,
      onTap: () => context.push('/send/payout/progress', extra: p.dealTag),
    );
  }
}

IconData _railIcon(String kind) =>
    kind == 'mobile_money' ? Icons.phone_android : Icons.account_balance_outlined;

class _Heading extends StatelessWidget {
  const _Heading(this.text);
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Text(
          text,
          style: GoogleFonts.inter(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.white),
        ),
      );
}

/// A row in the style of the wallet's transaction list.
class _Tile extends StatelessWidget {
  const _Tile({
    super.key,
    required this.leading,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  final Widget leading;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Material(
        color: const Color(0xFF1E1E1E),
        borderRadius: BorderRadius.circular(16),
        child: InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Container(
                  width: 40,
                  height: 40,
                  alignment: Alignment.center,
                  decoration: const BoxDecoration(
                    color: Colors.white10,
                    shape: BoxShape.circle,
                  ),
                  child: leading,
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        style: GoogleFonts.inter(fontWeight: FontWeight.w600, color: Colors.white),
                      ),
                      Text(
                        subtitle,
                        style: GoogleFonts.inter(color: Colors.white38, fontSize: 12),
                      ),
                    ],
                  ),
                ),
                const Icon(Icons.chevron_right, color: Colors.white38),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _Message extends StatelessWidget {
  const _Message({required this.icon, required this.title, required this.body, this.action});
  final IconData icon;
  final String title;
  final String body;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32.0),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 64, color: Colors.white24),
            const SizedBox(height: 16),
            Text(
              title,
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(
                  fontSize: 20, fontWeight: FontWeight.bold, color: Colors.white54),
            ),
            const SizedBox(height: 8),
            Text(
              body,
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(color: Colors.white38, fontSize: 14),
            ),
            if (action != null) ...[const SizedBox(height: 16), action!],
          ],
        ),
      ),
    );
  }
}
