import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:app/services/mpc_service.dart';

class SendScreen extends StatefulWidget {
  const SendScreen({super.key});

  @override
  State<SendScreen> createState() => _SendScreenState();
}

class _SendScreenState extends State<SendScreen> {
  final TextEditingController _addressController = TextEditingController();
  final TextEditingController _amountController = TextEditingController();
  bool _isBtc = true;

  /// The only kind of address this wallet can pay. On-chain sends went with the on-chain wallet;
  /// money leaves here either to another Ark address or, if everything else fails, through the
  /// pre-signed exits on the Exit tab.
  bool _isArkAddress(String address) =>
      address.startsWith('tark1') || address.startsWith('ark1');

  @override
  Widget build(BuildContext context) {
    final mpcService = context.watch<MpcService>();
    final formattedArk = NumberFormat('#,###').format(mpcService.arkBalance.toInt());

    final address = _addressController.text.trim();
    final isArk = _isArkAddress(address);

    return Scaffold(
      appBar: AppBar(title: const Text('Send')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Expanded(
                child: SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      TextField(
                        key: const Key('sendAddressField'),
                        controller: _addressController,
                        onChanged: (_) => setState(() {}),
                        decoration: InputDecoration(
                          labelText: 'Recipient Address',
                          hintText: 'tark1...',
                          suffixIcon: IconButton(
                            icon: const Icon(Icons.qr_code_scanner),
                            onPressed: () {},
                          ),
                        ),
                        style: GoogleFonts.inter(),
                      ),
                      if (address.isNotEmpty) ...[
                        const SizedBox(height: 8),
                        Builder(builder: (_) {
                          final color = isArk ? Colors.blueAccent : Colors.amberAccent;
                          return Row(
                            children: [
                              Icon(isArk ? Icons.account_tree : Icons.error_outline,
                                  size: 14, color: color),
                              const SizedBox(width: 6),
                              Text(
                                isArk ? 'Ark (off-chain)' : 'Not an Ark address',
                                style: GoogleFonts.inter(fontSize: 12, color: color),
                              ),
                            ],
                          );
                        }),
                      ],
                      const SizedBox(height: 24),
                      Row(
                        children: [
                          Expanded(
                            child: TextField(
                              key: const Key('sendAmountField'),
                              controller: _amountController,
                              keyboardType: const TextInputType.numberWithOptions(
                                  decimal: true),
                              decoration: InputDecoration(
                                labelText: 'Amount',
                                suffixText: _isBtc ? 'Sats' : 'USD',
                              ),
                              style: GoogleFonts.inter(fontSize: 24),
                            ),
                          ),
                          const SizedBox(width: 16),
                          IconButton(
                            onPressed: () {
                              setState(() {
                                _isBtc = !_isBtc;
                              });
                            },
                            icon: const Icon(Icons.swap_vert),
                          ),
                        ],
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'Balance: $formattedArk Sats',
                        style: GoogleFonts.inter(
                            color: Colors.white54, fontSize: 12),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              ElevatedButton(
                key: const Key('sendReviewBtn'),
                onPressed: _onReview,
                child: const Text('Review Transaction'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _onReview() {
    final address = _addressController.text.trim();
    final amountText = _amountController.text.trim();

    if (address.isEmpty || amountText.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Please fill all fields')));
      return;
    }

    if (!_isArkAddress(address)) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('That is not an Ark address — it starts with tark1 or ark1')));
      return;
    }

    if (!_isBtc) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('USD mode not supported yet')));
      return;
    }

    try {
      final amountDouble = double.parse(amountText);
      if (amountDouble <= 0) throw Exception();
      if (amountDouble % 1 != 0) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
            content: Text('Sats must be an integer')));
        return;
      }

      context.push('/spending/review', extra: {
        'address': address,
        'amount': amountDouble.toInt().toString(),
        'isBtc': true,
        'isArk': true,
      });
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Invalid amount')));
    }
  }
}
