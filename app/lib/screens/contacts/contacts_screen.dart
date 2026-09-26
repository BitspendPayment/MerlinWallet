import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../services/mpc_service.dart';

/// Who may bill this wallet.
///
/// Adding is ONE-WAY and deliberately so: you alone decide who can request money from you, and
/// the contact is never asked or notified. A contact is identified by their GROUP key — the
/// wallet's single public identity — which is also what your cosigner derives their payee address
/// from, so there is nothing else to exchange.
class ContactsScreen extends StatefulWidget {
  const ContactsScreen({super.key});

  @override
  State<ContactsScreen> createState() => _ContactsScreenState();
}

class _ContactsScreenState extends State<ContactsScreen> {
  // Shown from the service's local copy at once; reading the cosigner is a passkey approval, so it
  // only happens on pull-to-refresh.
  bool _loading = false;
  String? _error;

  Future<void> _refresh() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      await context.read<MpcService>().refreshContacts();
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _addDialog() async {
    final keyCtrl = TextEditingController();
    final labelCtrl = TextEditingController();
    final added = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Allow someone to bill you'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: keyCtrl,
              decoration: const InputDecoration(
                labelText: 'Their wallet key',
                hintText: '02… (66 hex characters)',
              ),
              maxLines: 2,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: labelCtrl,
              decoration: const InputDecoration(labelText: 'Name'),
            ),
            const SizedBox(height: 12),
            const Text(
              'They will be able to send you payment requests. You still approve every payment.',
              style: TextStyle(fontSize: 12, color: Colors.black54),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Allow')),
        ],
      ),
    );
    if (added != true || !mounted) return;
    try {
      await context.read<MpcService>().addContact(keyCtrl.text, labelCtrl.text);
      if (mounted) _snack('${labelCtrl.text} can now request payments from you');
    } catch (e) {
      if (mounted) _snack('Could not add: $e');
    }
  }

  Future<void> _remove(String vkHex, String label) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Revoke $label?'),
        content: const Text(
          'They will no longer be able to request payments, and any requests they have already '
          'sent you are discarded.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Revoke')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    try {
      await context.read<MpcService>().removeContact(vkHex);
      if (mounted) _snack('$label revoked');
    } catch (e) {
      if (mounted) _snack('Could not revoke: $e');
    }
  }

  void _snack(String msg) =>
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));

  @override
  Widget build(BuildContext context) {
    final svc = context.watch<MpcService>();
    final myKey = svc.myGroupKey;

    return Scaffold(
      appBar: AppBar(title: const Text('Contacts')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _addDialog,
        icon: const Icon(Icons.person_add),
        label: const Text('Allow'),
      ),
      body: RefreshIndicator(
        onRefresh: _refresh,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            if (myKey != null) _MyKeyCard(groupKey: myKey),
            const SizedBox(height: 16),
            Text('Allowed to bill you', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            if (_error != null)
              Text(_error!, style: const TextStyle(color: Colors.red))
            else if (_loading)
              const Center(child: Padding(padding: EdgeInsets.all(24), child: CircularProgressIndicator()))
            else if (svc.contacts.isEmpty)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 24),
                child: Text('Nobody can request money from you yet.'),
              )
            else
              ...svc.contacts.map((c) {
                final vk = _hex(c.verifyingKey);
                return ListTile(
                  leading: const CircleAvatar(child: Icon(Icons.person)),
                  title: Text(c.label.isEmpty ? 'Unnamed' : c.label),
                  subtitle: Text(_short(vk), style: const TextStyle(fontFamily: 'monospace')),
                  trailing: IconButton(
                    icon: const Icon(Icons.remove_circle_outline),
                    onPressed: () => _remove(vk, c.label),
                  ),
                );
              }),
          ],
        ),
      ),
    );
  }
}

/// Your own identity — the one thing you hand out so others can allowlist you.
class _MyKeyCard extends StatelessWidget {
  const _MyKeyCard({required this.groupKey});
  final String groupKey;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Your wallet key', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 4),
            const Text(
              'Share this so others can allow you to request money from them.',
              style: TextStyle(fontSize: 12, color: Colors.black54),
            ),
            const SizedBox(height: 8),
            SelectableText(groupKey, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton.icon(
                icon: const Icon(Icons.copy, size: 18),
                label: const Text('Copy'),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: groupKey));
                  ScaffoldMessenger.of(context)
                      .showSnackBar(const SnackBar(content: Text('Wallet key copied')));
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

String _short(String hex) =>
    hex.length <= 20 ? hex : '${hex.substring(0, 10)}…${hex.substring(hex.length - 8)}';
