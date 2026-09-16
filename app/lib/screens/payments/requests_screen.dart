import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:protocol/protocol.dart';

import '../../services/mpc_service.dart';

/// Payment requests addressed to this wallet, plus the form for asking someone else to pay.
///
/// Approving pays the amount and payee recorded in the request itself — the UI never supplies
/// them. That is deliberate: the cosigner matches the settled send against the stored request to
/// mark it fulfilled, so letting the screen edit either field would silently break that link (and
/// would be the obvious place to slip in a different payee).
class RequestsScreen extends StatefulWidget {
  const RequestsScreen({super.key});

  @override
  State<RequestsScreen> createState() => _RequestsScreenState();
}

class _RequestsScreenState extends State<RequestsScreen> {
  // Shown from the service's local copy at once; reading the cosigner is a passkey approval, so it
  // only happens on pull-to-refresh.
  bool _loading = false;
  String? _error;
  String? _busyId;

  Future<void> _refresh() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      // One read, one approval: contact names come from the local copy.
      await context.read<MpcService>().refreshPaymentRequests();
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _approve(PaymentIntent intent) async {
    final svc = context.read<MpcService>();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Pay this request?'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('${intent.amountSats} sats',
                style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
            if (intent.memo.isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(intent.memo),
            ],
            const SizedBox(height: 12),
            const Text('To', style: TextStyle(fontSize: 12, color: Colors.black54)),
            Text(_short(intent.toArkAddress),
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Pay')),
        ],
      ),
    );
    if (ok != true || !mounted) return;

    setState(() => _busyId = intent.id);
    try {
      final txid = await svc.approvePaymentRequest(intent);
      if (mounted) _snack('Paid — ${_short(txid)}');
    } catch (e) {
      if (mounted) _snack('Payment failed: $e');
    } finally {
      if (mounted) setState(() => _busyId = null);
    }
  }

  Future<void> _decline(PaymentIntent intent) async {
    setState(() => _busyId = intent.id);
    try {
      await context.read<MpcService>().declinePaymentRequest(intent.id);
      if (mounted) _snack('Declined');
    } catch (e) {
      if (mounted) _snack('Could not decline: $e');
    } finally {
      if (mounted) setState(() => _busyId = null);
    }
  }

  Future<void> _askDialog() async {
    final svc = context.read<MpcService>();
    if (svc.contacts.isEmpty) {
      _snack('Add a contact first — you can only request from wallets you know.');
      return;
    }
    final amountCtrl = TextEditingController();
    final memoCtrl = TextEditingController();
    String target = _hex(svc.contacts.first.verifyingKey);

    final send = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          title: const Text('Request a payment'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              DropdownButtonFormField<String>(
                initialValue: target,
                decoration: const InputDecoration(labelText: 'From'),
                items: svc.contacts
                    .map((c) => DropdownMenuItem(
                          value: _hex(c.verifyingKey),
                          child: Text(c.label.isEmpty ? _short(_hex(c.verifyingKey)) : c.label),
                        ))
                    .toList(),
                onChanged: (v) => setLocal(() => target = v ?? target),
              ),
              TextField(
                controller: amountCtrl,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(labelText: 'Amount (sats)'),
              ),
              TextField(
                controller: memoCtrl,
                decoration: const InputDecoration(labelText: 'What for?'),
              ),
              const SizedBox(height: 12),
              const Text(
                'They must have allowed you to bill them, and they choose whether to pay.',
                style: TextStyle(fontSize: 12, color: Colors.black54),
              ),
            ],
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Request')),
          ],
        ),
      ),
    );
    if (send != true || !mounted) return;

    final sats = int.tryParse(amountCtrl.text.trim()) ?? 0;
    if (sats <= 0) {
      _snack('Enter an amount');
      return;
    }
    try {
      await svc.requestPayment(target, sats, memo: memoCtrl.text.trim());
      if (mounted) _snack('Requested $sats sats');
    } catch (e) {
      if (mounted) _snack('Request failed: $e');
    }
  }

  void _snack(String msg) =>
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));

  @override
  Widget build(BuildContext context) {
    final svc = context.watch<MpcService>();
    // Only actionable requests. Once one is paid, declined or expired there is nothing left to
    // do with it, so it clears from the inbox — the cosigner keeps the record briefly for audit,
    // and a completed payment shows up in the Ark transaction history.
    final intents = svc.pendingPaymentRequests;

    return Scaffold(
      appBar: AppBar(title: const Text('Requests')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _askDialog,
        icon: const Icon(Icons.call_received),
        label: const Text('Ask'),
      ),
      body: RefreshIndicator(
        onRefresh: _refresh,
        child: _error != null
            ? ListView(children: [Padding(padding: const EdgeInsets.all(16), child: Text(_error!))])
            : _loading
                ? const Center(child: CircularProgressIndicator())
                : intents.isEmpty
                    ? ListView(children: const [
                        Padding(
                          padding: EdgeInsets.all(32),
                          child: Text('No payment requests.', textAlign: TextAlign.center),
                        )
                      ])
                    : ListView.separated(
                        itemCount: intents.length,
                        separatorBuilder: (_, __) => const Divider(height: 1),
                        itemBuilder: (_, i) => _IntentTile(
                          intent: intents[i],
                          contacts: svc.contacts,
                          busy: _busyId == intents[i].id,
                          onApprove: () => _approve(intents[i]),
                          onDecline: () => _decline(intents[i]),
                        ),
                      ),
      ),
    );
  }
}

class _IntentTile extends StatelessWidget {
  const _IntentTile({
    required this.intent,
    required this.contacts,
    required this.busy,
    required this.onApprove,
    required this.onDecline,
  });

  final PaymentIntent intent;
  final List<Contact> contacts;
  final bool busy;
  final VoidCallback onApprove;
  final VoidCallback onDecline;

  @override
  Widget build(BuildContext context) {
    final fromHex = _hex(intent.fromVerifyingKey);
    final label = contacts
        .where((c) => _hex(c.verifyingKey) == fromHex)
        .map((c) => c.label)
        .firstWhere((l) => l.isNotEmpty, orElse: () => _short(fromHex));
    final pending = intent.status == 'pending';

    return ListTile(
      isThreeLine: true,
      title: Text('$label asked for ${intent.amountSats} sats'),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (intent.memo.isNotEmpty) Text(intent.memo),
          Text(
            pending ? 'Awaiting your decision' : intent.status,
            style: TextStyle(
              fontSize: 12,
              color: pending ? Colors.orange.shade800 : Colors.black54,
            ),
          ),
        ],
      ),
      trailing: busy
          ? const SizedBox(width: 24, height: 24, child: CircularProgressIndicator(strokeWidth: 2))
          : pending
              ? Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    IconButton(
                      tooltip: 'Decline',
                      icon: const Icon(Icons.close),
                      onPressed: onDecline,
                    ),
                    FilledButton(onPressed: onApprove, child: const Text('Pay')),
                  ],
                )
              : null,
    );
  }
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

String _short(String s) =>
    s.length <= 20 ? s : '${s.substring(0, 10)}…${s.substring(s.length - 8)}';
