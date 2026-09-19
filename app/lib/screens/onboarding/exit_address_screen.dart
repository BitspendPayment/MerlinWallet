/// Where the money goes if this service disappears.
///
/// Asked once, right after the wallet's key exists and before the wallet opens, because it is what
/// every later signature is made out to: at the end of every send, settle and renewal the cosigner
/// co-signs a spend of each VTXO to this address, and the phone keeps it. Without an address there
/// is nothing to pre-sign to, and the wallet would depend on the cosigner answering forever.
///
/// It must be an address in some *other* wallet — one this app has no key for. A hardware wallet, an
/// exchange, another phone. It is checked here against the network the ASP reports, so a mainnet
/// address on a signet wallet is caught now rather than on the day it is needed.
library;

import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import 'package:app/services/mpc_service.dart';

class ExitAddressScreen extends StatefulWidget {
  const ExitAddressScreen({super.key});

  @override
  State<ExitAddressScreen> createState() => _ExitAddressScreenState();
}

class _ExitAddressScreenState extends State<ExitAddressScreen> {
  final _controller = TextEditingController();
  String? _error;
  bool _saving = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final service = context.read<MpcService>();
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      await service.setExitAddress(_controller.text);
      if (mounted) context.push('/onboarding/ready');
    } catch (e) {
      setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Your way out')),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.exit_to_app, size: 48, color: Colors.tealAccent.withOpacity(0.9)),
              const SizedBox(height: 24),
              Text(
                'Where should your money go\nif this service disappears?',
                style: GoogleFonts.inter(
                  fontSize: 22,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                  height: 1.3,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'Give a Bitcoin address in another wallet — a hardware wallet, an exchange, '
                'anything this app does not control.\n\n'
                'Every time you send or renew, your wallet is handed a signed transaction that '
                'pays your balance to this address. You keep those. If this service ever stops '
                'answering, they are how you get your money out without it.',
                style: GoogleFonts.inter(color: Colors.white60, fontSize: 14, height: 1.5),
              ),
              const SizedBox(height: 28),
              TextField(
                key: const Key('exitAddressField'),
                controller: _controller,
                autocorrect: false,
                enableSuggestions: false,
                style: GoogleFonts.robotoMono(color: Colors.white, fontSize: 13),
                decoration: InputDecoration(
                  labelText: 'Bitcoin address',
                  errorText: _error,
                  errorMaxLines: 3,
                  border: const OutlineInputBorder(),
                ),
                // The button reads this field, so the screen has to rebuild as it is typed into —
                // without this it stays disabled however valid the address is.
                onChanged: (_) => setState(() => _error = null),
                onSubmitted: (_) => _saving ? null : _save(),
              ),
              const SizedBox(height: 24),
              SizedBox(
                width: double.infinity,
                child: FilledButton(
                  key: const Key('exitAddressSaveBtn'),
                  onPressed: _saving || _controller.text.trim().isEmpty ? null : _save,
                  style: FilledButton.styleFrom(padding: const EdgeInsets.symmetric(vertical: 16)),
                  child: _saving
                      ? const SizedBox(
                          height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Continue'),
                ),
              ),
              const SizedBox(height: 12),
              Text(
                'You can change it later in Settings. Changing it does not move anything — it '
                'decides where the next signed exits pay.',
                style: GoogleFonts.inter(color: Colors.white38, fontSize: 12),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
