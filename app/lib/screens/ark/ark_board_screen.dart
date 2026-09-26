import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:app/services/mpc_service.dart';

class ArkBoardScreen extends StatefulWidget {
  const ArkBoardScreen({super.key});

  @override
  State<ArkBoardScreen> createState() => _ArkBoardScreenState();
}

class _ArkBoardScreenState extends State<ArkBoardScreen> {
  _BoardState _state = _BoardState.ready;
  String? _commitmentTxid;
  int _boardedSats = 0;
  String? _error;
  Timer? _pollTimer;

  @override
  void initState() {
    super.initState();
    // Initial check + poll every 5 seconds
    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<MpcService>().refreshBoardingBalance();
    });
    _pollTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      if (mounted && _state == _BoardState.ready) {
        context.read<MpcService>().refreshBoardingBalance();
      }
    });
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    super.dispose();
  }

  Future<void> _startBoarding() async {
    final mpcService = context.read<MpcService>();

    // Each confirmed deposit is settled with a passkey-approved operation.
    setState(() {
      _state = _BoardState.settling;
      _error = null;
      // What is being settled, read before it moves — afterwards the boarding
      // balance is zero and there is nothing left to name.
      _boardedSats = mpcService.boardingBalance;
    });

    try {
      final txid = await mpcService.boardFunds();
      if (!mounted) return;
      setState(() {
        _state = _BoardState.done;
        _commitmentTxid = txid;
      });
    } catch (e, st) {
      debugPrint('BOARDING FAILED: $e');
      debugPrint('$st');
      if (!mounted) return;
      setState(() {
        _state = _BoardState.error;
        _error = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final mpcService = context.watch<MpcService>();
    final boardingAddress = mpcService.boardingAddress;

    return Scaffold(
      appBar: AppBar(
        title: Text(
          'Receive',
          style: GoogleFonts.inter(fontWeight: FontWeight.w600),
        ),
        centerTitle: true,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: _buildBody(context, boardingAddress),
        ),
      ),
    );
  }

  Widget _buildBody(BuildContext context, String? boardingAddress) {
    switch (_state) {
      case _BoardState.ready:
        return _buildReadyState(context, boardingAddress);
      case _BoardState.settling:
        return _buildSettlingState();
      case _BoardState.done:
        return _buildDoneState(context);
      case _BoardState.error:
        return _buildErrorState(context);
    }
  }

  Widget _buildReadyState(BuildContext context, String? boardingAddress) {
    final mpcService = context.watch<MpcService>();
    final balance = mpcService.boardingBalance;
    final hasFunds = balance > 0;
    final pending = mpcService.boardingPendingBalance;
    final hasPending = pending > 0;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Expanded(
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(
                    color: const Color(0xFF1E1E1E),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(Icons.info_outline,
                              color: Colors.blueAccent, size: 20),
                          const SizedBox(width: 8),
                          Text(
                            'How Receiving Works',
                            style: GoogleFonts.inter(
                              fontWeight: FontWeight.w600,
                              color: Colors.white,
                              fontSize: 16,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      _buildStep('1', 'Send BTC to the address below'),
                      const SizedBox(height: 8),
                      _buildStep('2', 'Wait for on-chain confirmation'),
                      const SizedBox(height: 8),
                      _buildStep(
                          '3', 'Tap "Board Now" to settle into Ark VTXOs'),
                    ],
                  ),
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: hasFunds
                        ? Colors.green.withOpacity(0.1)
                        : const Color(0xFF1E1E1E),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: hasFunds
                          ? Colors.greenAccent.withOpacity(0.3)
                          : Colors.white10,
                    ),
                  ),
                  child: Row(
                    children: [
                      Icon(
                        hasFunds ? Icons.check_circle : Icons.hourglass_empty,
                        color: hasFunds ? Colors.greenAccent : Colors.white38,
                        size: 24,
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              hasFunds
                                  ? 'Funds detected: ${NumberFormat("#,##0").format(balance)} sats'
                                  : hasPending
                                      ? 'Waiting for confirmation'
                                      : 'No funds detected yet',
                              style: GoogleFonts.inter(
                                color: hasFunds
                                    ? Colors.greenAccent
                                    : hasPending
                                        ? Colors.orangeAccent
                                        : Colors.white54,
                                fontWeight: FontWeight.w600,
                                fontSize: 14,
                              ),
                            ),
                            // A mempool deposit cannot be boarded — the ASP
                            // rejects the intent if any input is unconfirmed —
                            // so say so rather than showing "no funds".
                            if (hasPending)
                              Text(
                                '${NumberFormat("#,##0").format(pending)} sats seen, not yet mined',
                                style: GoogleFonts.inter(
                                  color: Colors.orangeAccent
                                      .withValues(alpha: 0.7),
                                  fontSize: 11,
                                ),
                              ),
                            if (!hasFunds && !hasPending)
                              Text(
                                'Checking every 5 seconds...',
                                style: GoogleFonts.inter(
                                  color: Colors.white24,
                                  fontSize: 11,
                                ),
                              ),
                            Text(
                              'Already in Ark: '
                              '${NumberFormat("#,##0").format(mpcService.arkBalance.toInt())} sats',
                              style: GoogleFonts.inter(
                                color: Colors.white38,
                                fontSize: 11,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),
                if (boardingAddress != null) ...[
                  Center(
                    child: Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: QrImageView(
                        data: boardingAddress,
                        version: QrVersions.auto,
                        size: 200.0,
                        backgroundColor: Colors.white,
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'Your Boarding Address',
                    style: GoogleFonts.inter(
                      color: Colors.white54,
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 8),
                  GestureDetector(
                    onTap: () {
                      Clipboard.setData(ClipboardData(text: boardingAddress));
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(
                          content: Text('Boarding address copied'),
                          duration: Duration(seconds: 2),
                        ),
                      );
                    },
                    child: Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: const Color(0xFF1E1E1E),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: Colors.white10),
                      ),
                      child: Row(
                        children: [
                          Expanded(
                            child: Text(
                              boardingAddress,
                              style: GoogleFonts.inter(
                                fontSize: 12,
                                color: Colors.white70,
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          const Icon(Icons.copy,
                              color: Colors.white38, size: 18),
                        ],
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        ElevatedButton(
          key: const Key('arkBoardNowBtn'),
          onPressed: hasFunds ? _startBoarding : null,
          child: Text(hasFunds ? 'Board Now' : 'Waiting for funds...'),
        ),
        const SizedBox(height: 8),
        Text(
          hasFunds
              ? 'Tap to settle your on-chain funds into Ark VTXOs'
              : 'Send BTC to the address above, then board',
          textAlign: TextAlign.center,
          style: GoogleFonts.inter(color: Colors.white38, fontSize: 11),
        ),
      ],
    );
  }

  Widget _buildStep(String number, String text) {
    return Row(
      children: [
        Container(
          width: 24,
          height: 24,
          decoration: BoxDecoration(
            color: Colors.white10,
            shape: BoxShape.circle,
          ),
          child: Center(
            child: Text(
              number,
              style: GoogleFonts.inter(
                color: Colors.white54,
                fontSize: 12,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Text(
            text,
            style: GoogleFonts.inter(color: Colors.white70, fontSize: 14),
          ),
        ),
      ],
    );
  }

  Widget _buildSettlingState() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(
            width: 64,
            height: 64,
            child: CircularProgressIndicator(strokeWidth: 3),
          ),
          const SizedBox(height: 24),
          Text(
            'Boarding in progress...',
            style: GoogleFonts.inter(
              fontSize: 18,
              fontWeight: FontWeight.w600,
              color: Colors.white,
            ),
          ),
          const SizedBox(height: 12),
          Text(
            'Signing intent proofs and settling with ASP.\nThis may take a moment.',
            textAlign: TextAlign.center,
            style: GoogleFonts.inter(color: Colors.white54, fontSize: 14),
          ),
          const SizedBox(height: 32),
          // A batch round is minutes, and only the owner can tell a slow one from an ASP that has
          // gone. Stopping fails the boarding where it stands: the deposit stays at its boarding
          // address to be boarded again, and the key rebuilt for this is let go.
          TextButton(
            onPressed: () => context.read<MpcService>().cancelOperation(),
            child: Text(
              'Stop waiting',
              style: GoogleFonts.inter(color: Colors.white54, fontSize: 14),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDoneState(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 80,
            height: 80,
            decoration: BoxDecoration(
              color: Colors.green.withOpacity(0.1),
              shape: BoxShape.circle,
            ),
            child: const Icon(
              Icons.check_circle,
              color: Colors.greenAccent,
              size: 48,
            ),
          ),
          const SizedBox(height: 24),
          Text(
            'Boarding Complete!',
            style: GoogleFonts.inter(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
          const SizedBox(height: 12),
          Text(
            _boardedSats > 0
                ? '${NumberFormat("#,##0").format(_boardedSats)} sats settled into Ark VTXOs.'
                : 'Your funds have been settled into Ark VTXOs.',
            textAlign: TextAlign.center,
            style: GoogleFonts.inter(color: Colors.white54, fontSize: 14),
          ),
          Text(
            'Now in Ark: '
            '${NumberFormat("#,##0").format(context.watch<MpcService>().arkBalance.toInt())} sats',
            textAlign: TextAlign.center,
            style: GoogleFonts.inter(color: Colors.white38, fontSize: 12),
          ),
          if (_commitmentTxid != null) ...[
            const SizedBox(height: 16),
            GestureDetector(
              onTap: () {
                Clipboard.setData(ClipboardData(text: _commitmentTxid!));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Transaction ID copied')),
                );
              },
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFF1E1E1E),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      'TX: ${_commitmentTxid!.substring(0, 16)}...',
                      style: GoogleFonts.inter(
                        color: Colors.white54,
                        fontSize: 12,
                      ),
                    ),
                    const SizedBox(width: 8),
                    const Icon(Icons.copy, color: Colors.white38, size: 14),
                  ],
                ),
              ),
            ),
          ],
          const SizedBox(height: 32),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              key: const Key('arkBoardDoneBtn'),
              onPressed: () => context.go('/ark'),
              child: const Text('Back to Ark'),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorState(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.symmetric(vertical: 24),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 80,
            height: 80,
            decoration: BoxDecoration(
              color: Colors.red.withOpacity(0.1),
              shape: BoxShape.circle,
            ),
            child: const Icon(
              Icons.error_outline,
              color: Colors.redAccent,
              size: 48,
            ),
          ),
          const SizedBox(height: 24),
          Text(
            'Boarding Failed',
            style: GoogleFonts.inter(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            margin: const EdgeInsets.symmetric(horizontal: 16),
            decoration: BoxDecoration(
              color: Colors.red.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              _error ?? 'Unknown error',
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(color: Colors.redAccent, fontSize: 13),
            ),
          ),
          const SizedBox(height: 32),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              ElevatedButton(
                onPressed: _startBoarding,
                child: const Text('Retry'),
              ),
              const SizedBox(width: 16),
              OutlinedButton(
                onPressed: () => context.pop(),
                style: OutlinedButton.styleFrom(
                  side: const BorderSide(color: Colors.white24),
                ),
                child: Text(
                  'Cancel',
                  style: GoogleFonts.inter(color: Colors.white),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

enum _BoardState { ready, settling, done, error }
