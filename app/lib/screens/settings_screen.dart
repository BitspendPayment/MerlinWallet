import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:app/services/mpc_service.dart';
import 'package:app/widgets/app_bottom_nav.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final mpc = context.watch<MpcService>();

    return Scaffold(
      appBar: AppBar(
        title: Text('Settings',
            style: GoogleFonts.inter(fontWeight: FontWeight.w600)),
        centerTitle: true,
      ),
      body: SafeArea(
        child: ListView(
          children: [
            const SizedBox(height: 8),
            ListTile(
              leading: Icon(Icons.exit_to_app,
                  color: mpc.hasExitAddress ? Colors.tealAccent : Colors.orangeAccent),
              title: Text('Exit address',
                  style: GoogleFonts.inter(
                      fontWeight: FontWeight.w600, color: Colors.white)),
              subtitle: Text(
                mpc.exitAddress ??
                    'Not set — without one, nothing can be pre-signed for you to broadcast',
                style: GoogleFonts.robotoMono(color: Colors.white54, fontSize: 11),
              ),
              trailing: const Icon(Icons.edit, size: 18),
              onTap: () => _editExitAddress(context, mpc),
            ),
            const Divider(height: 1, color: Colors.white12),
            ListTile(
              leading: Icon(
                mpc.arkAvailable ? Icons.check_circle : Icons.cloud_off,
                color: mpc.arkAvailable ? Colors.greenAccent : Colors.amberAccent,
              ),
              title: Text('Ark server',
                  style: GoogleFonts.inter(color: Colors.white)),
              trailing: Text(
                mpc.arkAvailable ? 'Available' : 'Unavailable',
                style: GoogleFonts.inter(
                  color: mpc.arkAvailable ? Colors.greenAccent : Colors.white54,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
        ),
      ),
      bottomNavigationBar: const AppBottomNav(current: '/settings'),
    );
  }

  /// Changing the address does not move anything and does not invalidate the exits already signed —
  /// those still pay the old address, and still work. It decides where the next ones pay, which is
  /// the next time anything is sealed.
  Future<void> _editExitAddress(BuildContext context, MpcService mpc) async {
    final controller = TextEditingController(text: mpc.exitAddress ?? '');
    final messenger = ScaffoldMessenger.of(context);
    final address = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        title: Text('Exit address', style: GoogleFonts.inter(color: Colors.white)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'An address in another wallet. Your signed exits pay here if this service ever '
              'stops answering.',
              style: GoogleFonts.inter(color: Colors.white54, fontSize: 12),
            ),
            const SizedBox(height: 16),
            TextField(
              key: const Key('settingsExitAddressField'),
              controller: controller,
              autocorrect: false,
              enableSuggestions: false,
              style: GoogleFonts.robotoMono(color: Colors.white, fontSize: 12),
              decoration: const InputDecoration(border: OutlineInputBorder()),
            ),
            const SizedBox(height: 8),
            Text(
              'Exits already signed keep paying the old address. New ones start from the next '
              'send, settle or renewal.',
              style: GoogleFonts.inter(color: Colors.white38, fontSize: 11),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Cancel')),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(controller.text.trim()),
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (address == null || address.isEmpty) return;
    try {
      await mpc.setExitAddress(address);
      messenger.showSnackBar(const SnackBar(content: Text('Exit address saved')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('$e')));
    }
  }
}
