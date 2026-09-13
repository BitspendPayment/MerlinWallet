import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:app/services/mpc_service.dart';
import 'package:app/widgets/app_bottom_nav.dart';
import 'package:app/widgets/offline_banner.dart';
import 'package:intl/intl.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final mpcService = context.watch<MpcService>();
    final balance = mpcService.balance;
    final transactions = mpcService.transactions;

    final balanceBtc = balance.toDouble() / 100000000;
    final balanceUsd = balanceBtc * 65000; // Mock exchange rate for now

    return Scaffold(
      appBar: AppBar(
        title: Text(
          'Merlin Wallet',
          style: GoogleFonts.inter(fontWeight: FontWeight.w600),
        ),
        centerTitle: true,
        actions: [
          _buildConnectionIndicator(context, mpcService),
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () {
              mpcService.refreshHistory();
            },
          ),
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            onPressed: () => context.push('/settings'),
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            // On-chain-only banner (shown only in offline mode).
            const OfflineBanner(),
            const SizedBox(height: 24),
            // Balance Card
            _buildBalanceCard(context, balance, balanceUsd),
            const SizedBox(height: 32),
            // Recent Transactions Title
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24.0),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Recent Transactions',
                    style: GoogleFonts.inter(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                  TextButton(
                    onPressed: () {},
                    child: Text(
                      'View All',
                      style: GoogleFonts.inter(
                          color: Colors.white54, fontSize: 12),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            // Transactions List
            Expanded(
              child: transactions.isEmpty
                  ? Center(
                      child: Text(
                        "No transactions yet",
                        style: GoogleFonts.inter(color: Colors.white38),
                      ),
                    )
                  : ListView.builder(
                      padding: const EdgeInsets.symmetric(horizontal: 16),
                      itemCount: transactions.length,
                      itemBuilder: (context, index) {
                        final tx = transactions[index];
                        final isIncoming = tx.amountSats >= 0;
                        final amount = tx.amountSats.toInt().abs();
                        // Format date
                        final date = DateTime.fromMillisecondsSinceEpoch(
                            tx.timestamp.toInt() * 1000);
                        final dateStr =
                            DateFormat.yMMMd().add_jm().format(date);

                        return _buildTransactionItem(
                          title: isIncoming ? 'Received' : 'Sent',
                          amount: '${isIncoming ? '+' : '-'}$amount Sats',
                          date: dateStr,
                          isIncoming: isIncoming,
                          isPending: tx.isPending,
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
      bottomNavigationBar: const AppBottomNav(current: '/'),
    );
  }

  Widget _buildConnectionIndicator(BuildContext context, MpcService mpcService) {
    final isConnected = mpcService.isConnected;
    final color = isConnected ? Colors.greenAccent : Colors.redAccent;

    return GestureDetector(
      onTap: isConnected
          ? null
          : () {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Reconnecting...')),
              );
              mpcService.reconnect();
            },
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8.0),
        child: Tooltip(
          message: isConnected ? 'Connected' : 'Disconnected — tap to reconnect',
          child: Container(
            width: 12,
            height: 12,
            decoration: BoxDecoration(
              color: color,
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: color.withOpacity(0.4),
                  blurRadius: 6,
                  spreadRadius: 1,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildBalanceCard(
      BuildContext context, BigInt balance, double usdValue) {
    final balanceFormatter = NumberFormat("#,##0", "en_US");
    final usdFormatter = NumberFormat.currency(symbol: "\$");

    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 24),
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(24),
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Colors.grey[800]!,
            Colors.grey[900]!,
          ],
        ),
        border: Border.all(color: Colors.white10),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.3),
            blurRadius: 15,
            offset: const Offset(0, 5),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'Total Balance',
                style: GoogleFonts.inter(
                  color: Colors.white54,
                  fontSize: 14,
                  fontWeight: FontWeight.w500,
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: Colors.green.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  '+2.4%', // Mock percentage
                  style: GoogleFonts.inter(
                    color: Colors.greenAccent,
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            '${balanceFormatter.format(balance.toInt())} Sats',
            style: GoogleFonts.inter(
              fontSize: 32,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            usdFormatter.format(usdValue),
            style: GoogleFonts.inter(
              fontSize: 16,
              color: Colors.white38,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 24),
          Row(
            children: [
              Expanded(
                child: _buildActionButton(
                  context,
                  widgetKey: const Key('homeSendBtn'),
                  icon: Icons.arrow_upward,
                  label: 'Send',
                  onTap: () => context.push('/spending/send'),
                  isPrimary: true,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildActionButton(
                  context,
                  widgetKey: const Key('homeReceiveBtn'),
                  icon: Icons.arrow_downward,
                  label: 'Receive',
                  onTap: () => context.push('/receive'),
                  isPrimary: false,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildActionButton(
    BuildContext context, {
    Key? widgetKey,
    required IconData icon,
    required String label,
    required VoidCallback onTap,
    required bool isPrimary,
  }) {
    return GestureDetector(
      key: widgetKey,
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 12),
        decoration: BoxDecoration(
          color: isPrimary ? Colors.white : Colors.white10,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              icon,
              size: 20,
              color: isPrimary ? Colors.black : Colors.white,
            ),
            const SizedBox(width: 8),
            Text(
              label,
              style: GoogleFonts.inter(
                color: isPrimary ? Colors.black : Colors.white,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTransactionItem({
    required String title,
    required String amount,
    required String date,
    required bool isIncoming,
    bool isPending = false,
  }) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1E1E1E),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color:
                  isIncoming ? Colors.green.withOpacity(0.1) : Colors.white10,
              shape: BoxShape.circle,
            ),
            child: Icon(
              isIncoming ? Icons.arrow_downward : Icons.arrow_upward,
              color: isIncoming ? Colors.greenAccent : Colors.white,
              size: 20,
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      title,
                      style: GoogleFonts.inter(
                        fontWeight: FontWeight.w600,
                        color: Colors.white,
                      ),
                    ),
                    if (isPending)
                      Padding(
                        padding: const EdgeInsets.only(left: 8.0),
                        child: Text(
                          "(Pending)",
                          style: GoogleFonts.inter(
                              color: Colors.orangeAccent, fontSize: 10),
                        ),
                      ),
                  ],
                ),
                Text(
                  date,
                  style: GoogleFonts.inter(
                    color: Colors.white38,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          Text(
            amount,
            style: GoogleFonts.inter(
              fontWeight: FontWeight.bold,
              color: isIncoming ? Colors.greenAccent : Colors.white,
            ),
          ),
        ],
      ),
    );
  }
}
