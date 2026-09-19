import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../../services/mpc_service.dart';

/// Onboarding step between choosing a server and DKG: create the wallet's passkey.
///
/// Not skippable, and before DKG rather than after: the enclave approves every request to the
/// cosigner with a passkey assertion, so without one there is no cosigner to generate a key with.
/// The same passkey's PRF output is what the wallet's half of its key is derived from — at DKG, and
/// again for every payment, since no share is kept — so every payment needs a gesture. [MpcService.enablePasskey] keeps an already-registered passkey, so retrying is
/// safe.
class PasskeySetupScreen extends StatefulWidget {
  const PasskeySetupScreen({super.key});

  @override
  State<PasskeySetupScreen> createState() => _PasskeySetupScreenState();
}

class _PasskeySetupScreenState extends State<PasskeySetupScreen> {
  bool _busy = false;
  String? _error;

  Future<void> _createPasskey() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await context.read<MpcService>().enablePasskey();
      if (mounted) context.push('/onboarding/dkg');
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
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Spacer(),
              const Center(
                child: Icon(Icons.fingerprint, size: 80, color: Colors.white),
              ),
              const SizedBox(height: 32),
              Text(
                'Secure your wallet',
                style:
                    GoogleFonts.inter(fontSize: 32, fontWeight: FontWeight.bold),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              Text(
                'Create a passkey. It is how the secure enclave holding the other '
                'half of your key knows it is you, and it locks your half too: '
                'every payment asks for your fingerprint, face, or screen lock — '
                'nothing to remember, nothing that can be guessed.',
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
                    'Passkey setup failed: $_error',
                    style: GoogleFonts.inter(
                        color: Colors.redAccent, fontSize: 13),
                  ),
                ),
              ],
              if (_busy) ...[
                const SizedBox(height: 24),
                Text(
                  'Creating your passkey… one moment.',
                  style: GoogleFonts.inter(color: Colors.white70, fontSize: 14),
                  textAlign: TextAlign.center,
                ),
              ],
              const Spacer(),
              ElevatedButton(
                key: const Key('passkeyCreateBtn'),
                onPressed: _busy ? null : _createPasskey,
                child: _busy
                    ? const SizedBox(
                        height: 20,
                        width: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : Text(_error == null ? 'Create passkey' : 'Try again'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
