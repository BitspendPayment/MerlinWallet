import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../services/mpc_service.dart';
import '../services/payout_service.dart' show plainError;

/// The wallet behind its passkey: on a cold start, and on every return to the app, until the owner
/// gives it.
///
/// The gesture is more than a door. Its approval re-arms the renewal the cosigner runs on its own
/// ([MpcService.unlock]), so the lock asks for it straight away rather than waiting for a tap, and
/// keeps a button only to ask again.
class LockScreen extends StatefulWidget {
  const LockScreen({super.key});

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  late final AppLifecycleListener _lifecycle;
  bool _asked = false;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    // A passkey prompt needs the app in front to show over: asked once it is, and once only — after
    // a cancel the owner decides when to try again.
    _lifecycle = AppLifecycleListener(onResume: _askOnce);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (WidgetsBinding.instance.lifecycleState == AppLifecycleState.resumed) _askOnce();
    });
  }

  @override
  void dispose() {
    _lifecycle.dispose();
    super.dispose();
  }

  void _askOnce() {
    if (_asked) return;
    _asked = true;
    _unlock();
  }

  Future<void> _unlock() async {
    if (_busy || !mounted) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await context.read<MpcService>().unlock();
    } catch (e) {
      if (mounted) setState(() => _error = plainError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                SvgPicture.asset('assets/logo/mark-a-hat.svg', width: 96, height: 96),
                const SizedBox(height: 24),
                Text(
                  'Merlin Wallet',
                  style: GoogleFonts.inter(fontSize: 24, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 12),
                Text(
                  'Unlock with your passkey. It also keeps your funds renewing while you are '
                  'away.',
                  textAlign: TextAlign.center,
                  style: GoogleFonts.inter(color: Colors.white60, fontSize: 14, height: 1.4),
                ),
                if (_error != null) ...[
                  const SizedBox(height: 20),
                  Text(
                    _error!,
                    textAlign: TextAlign.center,
                    style: GoogleFonts.inter(color: Colors.redAccent, fontSize: 13),
                  ),
                ],
                const SizedBox(height: 32),
                FilledButton(
                  key: const Key('unlockBtn'),
                  onPressed: _busy ? null : _unlock,
                  child: Text(_busy ? 'Waiting for your passkey…' : 'Unlock'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
