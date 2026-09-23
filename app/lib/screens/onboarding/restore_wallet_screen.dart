/// Getting a wallet back on a phone that has never held it.
///
/// There is no seed phrase to type and no file to import, because there is nothing this screen
/// could ask for that the passkey does not already answer. The wallet's key is derived from the
/// passkey's PRF — the same passkey, wherever it syncs, derives the same half of the key — and the
/// other half is the one the cosigner dealt at the original ceremony and has held ever since.
///
/// So the whole flow is: pick the passkey, ask the cosigner, check the two halves add up to the key
/// this wallet signs with. See [MpcService.restoreWallet]; a wallet that does not check out is
/// refused rather than opened.
library;

import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../../services/mpc_service.dart';

class RestoreWalletScreen extends StatefulWidget {
  const RestoreWalletScreen({super.key});

  @override
  State<RestoreWalletScreen> createState() => _RestoreWalletScreenState();
}

class _RestoreWalletScreenState extends State<RestoreWalletScreen> {
  bool _busy = false;
  String? _error;

  Future<void> _restore() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await context.read<MpcService>().restoreWallet();
      // The exits are this device's copies of transactions signed for the old one, so they do not
      // come back with everything else. The address is asked for again and the next seal reissues
      // them — which is why restore ends where onboarding does.
      if (mounted) context.push('/onboarding/exit-address');
    } catch (e) {
      setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Spacer(),
              const Center(
                  child: Icon(Icons.restore, size: 80, color: Colors.white)),
              const SizedBox(height: 32),
              Text(
                'Use your passkey',
                style: GoogleFonts.inter(
                    fontSize: 32, fontWeight: FontWeight.bold),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              Text(
                'Your wallet is not a file on your old phone — it is derived from the passkey '
                'you made it with. Pick that passkey and this device works out its half of the '
                'key again, then asks the co-signing enclave for the other half.\n\n'
                'Your balance is loaded when Ark is available. After restoring, pull down on the '
                'Contacts and Requests screens to load your contacts and pending payments.',
                style: GoogleFonts.inter(
                    color: Colors.white70, fontSize: 16, height: 1.5),
                textAlign: TextAlign.center,
              ),
              if (_error != null) ...[
                const SizedBox(height: 24),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.red.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Text(
                    'Could not restore: $_error',
                    style: GoogleFonts.inter(
                        color: Colors.redAccent, fontSize: 13),
                  ),
                ),
              ],
              if (_busy) ...[
                const SizedBox(height: 24),
                Text(
                  'Putting your key back together…',
                  style: GoogleFonts.inter(color: Colors.white70, fontSize: 14),
                  textAlign: TextAlign.center,
                ),
              ],
              const Spacer(),
              ElevatedButton(
                key: const Key('restoreWalletBtn'),
                onPressed: _busy ? null : _restore,
                child: _busy
                    ? const SizedBox(
                        height: 20,
                        width: 20,
                        child: CircularProgressIndicator(strokeWidth: 2))
                    : Text(_error == null ? 'Restore my wallet' : 'Try again'),
              ),
              const SizedBox(height: 12),
              Text(
                'Only works on a device your passkey has synced to. If it was never backed up, '
                'the wallet cannot be recovered here.',
                style: GoogleFonts.inter(color: Colors.white38, fontSize: 12),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
