import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import 'package:app/services/mpc_service.dart';

class WalletReadyScreen extends StatelessWidget {
  const WalletReadyScreen({super.key});

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
                child: Icon(Icons.check_circle_outline,
                    size: 80, color: Colors.greenAccent),
              ),
              const SizedBox(height: 32),
              Text(
                'Wallet Ready!',
                style: GoogleFonts.inter(
                    fontSize: 32, fontWeight: FontWeight.bold),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              Text(
                'Your MPC Bitcoin Wallet has been created.\nYour key share is secured by a passkey on this device.',
                style: GoogleFonts.inter(color: Colors.white70, fontSize: 16),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 48),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.grey[900],
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Column(
                  children: [
                    Text('Holds',
                        style: GoogleFonts.inter(
                            color: Colors.white54, fontSize: 12)),
                    const SizedBox(height: 4),
                    Text('Bitcoin, in Ark',
                        style: GoogleFonts.inter(fontWeight: FontWeight.bold)),
                    const Divider(height: 24, color: Colors.white24),
                    Text('Key Protection',
                        style: GoogleFonts.inter(
                            color: Colors.white54, fontSize: 12)),
                    const SizedBox(height: 4),
                    Text('Passkey',
                        style: GoogleFonts.inter(fontWeight: FontWeight.bold)),
                    const Divider(height: 24, color: Colors.white24),
                    Text('Your way out',
                        style: GoogleFonts.inter(
                            color: Colors.white54, fontSize: 12)),
                    const SizedBox(height: 4),
                    Text(
                      context.watch<MpcService>().exitAddress ?? 'not set',
                      textAlign: TextAlign.center,
                      style: GoogleFonts.robotoMono(
                          fontWeight: FontWeight.bold, fontSize: 11),
                    ),
                  ],
                ),
              ),
              const Spacer(),
              ElevatedButton(
                key: const Key('walletReadyBtn'),
                onPressed: () {
                  context.go('/');
                },
                child: const Text('Go to Wallet'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
