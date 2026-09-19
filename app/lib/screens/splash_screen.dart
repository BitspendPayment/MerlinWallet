import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:app_core/persistence/wallet_store.dart' show IncompatibleWalletStateException;
import '../services/mpc_service.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  /// Set when this install holds wallet state from before shares were rebuilt per operation. It is
  /// neither read nor quietly replaced: the owner is told, and resets it.
  IncompatibleWalletStateException? _incompatible;
  bool _resetting = false;

  @override
  void initState() {
    super.initState();
    _checkWalletState();
  }

  Future<void> _checkWalletState() async {
    final mpcService = context.read<MpcService>();

    // Wait for init() to finish loading persisted config from Hive
    await mpcService.initFuture;

    if (!mounted) return;

    if (mpcService.dkgComplete) {
      // Keys exist — restore session and go to home
      try {
        await mpcService.restoreSession();
      } on IncompatibleWalletStateException catch (e) {
        if (mounted) setState(() => _incompatible = e);
        return;
      } catch (e) {
        // Session restore failed — will start in disconnected state
        print("Session restore failed: $e — falling back to onboarding");
      }
      if (mounted) context.go('/');
    } else {
      // No keys — start onboarding
      if (mounted) context.go('/onboarding/welcome');
    }
  }

  Future<void> _reset() async {
    setState(() => _resetting = true);
    try {
      await context.read<MpcService>().resetLocalWallet();
      if (mounted) context.go('/onboarding/welcome');
    } catch (e) {
      if (!mounted) return;
      setState(() => _resetting = false);
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Reset failed: $e')));
    }
  }

  Widget _incompatibleState(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'This wallet data is from an older development build',
                style: GoogleFonts.inter(fontSize: 22, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 16),
              Text(
                'Older builds kept part of the wallet\'s key on this phone. This build keeps none '
                'of it — the key is rebuilt from your passkey each time you sign — and it cannot '
                'use the old data. There is no migration.\n\n'
                'Resetting deletes the old data from this phone. Your wallet is not deleted: '
                'afterwards choose "Restore wallet" and it is rebuilt from your passkey. You will '
                'be asked for your exit address again.',
                style: GoogleFonts.inter(fontSize: 15, height: 1.4),
              ),
              const SizedBox(height: 28),
              FilledButton(
                onPressed: _resetting ? null : _reset,
                child: Text(_resetting ? 'Resetting…' : 'Reset wallet data on this phone'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_incompatible != null) return _incompatibleState(context);
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            SvgPicture.asset(
              'assets/logo/mark-a-hat.svg',
              width: 96,
              height: 96,
            ),
            const SizedBox(height: 24),
            Text(
              'Merlin Wallet',
              style: GoogleFonts.inter(
                fontSize: 24,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 32),
            const CircularProgressIndicator(color: Colors.white),
          ],
        ),
      ),
    );
  }
}
