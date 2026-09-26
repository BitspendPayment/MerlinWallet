import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../widgets/stepper_widget.dart';
import 'package:provider/provider.dart';
import '../../services/mpc_service.dart';

class SigningScreen extends StatefulWidget {
  final Map<String, dynamic> extras;
  const SigningScreen({super.key, this.extras = const {}});

  @override
  State<SigningScreen> createState() => _SigningScreenState();
}

class _SigningScreenState extends State<SigningScreen> {
  int _currentStep = 0;
  late final List<String> _steps;
  String _statusText = '';

  @override
  void initState() {
    super.initState();
    _steps = ['Build', 'Sign', 'Submit'];
    _statusText = 'Building transaction...';
    _startArkSend();
  }

  Future<void> _startArkSend() async {
    final mpcService = context.read<MpcService>();

    if (!mpcService.arkAvailable) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Ark wallet not initialized!')),
        );
        context.pop();
      }
      return;
    }

    final destination = widget.extras['address'] as String?;
    final amountStr = widget.extras['amount'] as String?;

    if (destination == null || amountStr == null) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Invalid transaction details!')),
        );
        context.pop();
      }
      return;
    }

    final amount = int.tryParse(amountStr);
    if (amount == null || amount <= 0) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Invalid amount!')),
        );
        context.pop();
      }
      return;
    }

    try {
      // Step 0: Build transaction
      setState(() {
        _currentStep = 0;
        _statusText = 'Building transaction...';
      });

      // One call where there were three. `MpcArkWallet` built the transaction,
      // had it co-signed and submitted it as separate steps this screen could
      // narrate; the cosigner builds it now and the wallet answers with FROST
      // signatures and talks to the ASP, all inside one session. The steps
      // still happen — they are just no longer three awaits to sit between.
      setState(() {
        _currentStep = 1;
        _statusText = 'Signing with your Key Share...';
      });

      final arkTxid = await mpcService.sendArk(destination, amount);

      // Gone mid-send: the payment went through, and there is no screen to say so on. Calling
      // setState here would throw into the catch below and log a send that succeeded as failed.
      if (!mounted) return;
      setState(() {
        _currentStep = 2;
        _statusText = 'Submitted to Ark...';
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Ark send complete! TX: ${arkTxid.substring(0, 16)}...'),
            backgroundColor: Colors.green,
          ),
        );
        context.go('/ark');
      }
    } catch (e, st) {
      debugPrint('=== ARK SEND FAILED ===');
      debugPrint('Error: $e');
      debugPrint('Stack: $st');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
              content: Text('Ark Send Failed: $e'),
              backgroundColor: Colors.red),
        );
        context.pop();
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Sending')),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          children: [
            DkgStepper(currentStep: _currentStep, steps: _steps),
            const Spacer(),
            Text(_statusText,
                style: GoogleFonts.inter(fontSize: 14, color: Colors.white70)),
            const SizedBox(height: 32),
            const CircularProgressIndicator(color: Colors.white),
            const Spacer(),
          ],
        ),
      ),
    );
  }
}
