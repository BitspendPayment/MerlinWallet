import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';

class WelcomeScreen extends StatelessWidget {
  const WelcomeScreen({super.key});

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
              Center(
                child: Container(
                  width: 80,
                  height: 80,
                  decoration: BoxDecoration(
                    color: Colors.white,
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(
                    Icons.account_balance_wallet_outlined,
                    color: Colors.black,
                    size: 40,
                  ),
                ),
              ),
              const SizedBox(height: 32),
              Text(
                'Merlin Wallet',
                style: GoogleFonts.inter(
                  fontSize: 32,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              Text(
                'Secure 2-of-2 Multi-Party Computation Bitcoin Wallet.\n\nYou hold one key share on this device.\nThe co-signing server holds the other.\nNeither can move your funds alone.',
                style: GoogleFonts.inter(
                  fontSize: 16,
                  color: Colors.white70,
                  height: 1.5,
                ),
                textAlign: TextAlign.center,
              ),
              const Spacer(),
              ElevatedButton(
                key: const Key('welcomeCreateBtn'),
                onPressed: () {
                  // Software signer is the only path (hardware signer dropped).
                  // Spending is gated by a passkey (created after DKG), not a PIN.
                  context.push('/onboarding/server', extra: {
                    'isRestore': false,
                  });
                },
                child: const Text('Create MPC Wallet'),
              ),
              const SizedBox(height: 12),
              TextButton(
                key: const Key('welcomeRestoreBtn'),
                onPressed: () {
                  // Same passkey, new phone: the wallet is derived from it, so there is nothing
                  // else to bring across. See `RestoreWalletScreen`.
                  context.push('/onboarding/server', extra: {
                    'isRestore': true,
                  });
                },
                child: const Text('I already have a wallet'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
