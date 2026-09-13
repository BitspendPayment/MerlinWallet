import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:intl/intl.dart';
import 'package:app/services/mpc_service.dart';
import 'package:app/widgets/app_bottom_nav.dart';
import 'package:protocol/protocol.dart';

class ArkScreen extends StatelessWidget {
  const ArkScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final mpcService = context.watch<MpcService>();
    final arkBalance = mpcService.arkBalance;
    // No history to show. The cosigner kept an Ark transaction log and served it over
    // `ListArkTransactions`; it is called rather than running now, so it never sees a receive and
    // could only ever log what it performed itself — a wallet that appears never to have been
    // paid. Rebuilding this from the ASP indexer's own history is its own piece of work.
    const arkTxs = <ArkTransactionSummary>[];
    final arkAvailable = mpcService.arkAvailable;

    final balanceBtc = arkBalance.toDouble() / 100000000;
    final balanceUsd = balanceBtc * 65000;

    return Scaffold(
      appBar: AppBar(
        title: Text(
          'Ark',
          style: GoogleFonts.inter(fontWeight: FontWeight.w600),
        ),
        centerTitle: true,
        actions: [
          // Request-to-pay lives with the Ark balance it spends from. The badge counts
          // requests still awaiting a decision.
          Stack(
            alignment: Alignment.center,
            children: [
              IconButton(
                key: const Key('arkRequestsBtn'),
                icon: const Icon(Icons.call_received),
                tooltip: 'Payment requests',
                onPressed: () => context.push('/requests'),
              ),
              if (mpcService.pendingPaymentRequests.isNotEmpty)
                Positioned(
                  right: 8,
                  top: 8,
                  child: Container(
                    padding: const EdgeInsets.all(4),
                    decoration: const BoxDecoration(
                        color: Colors.red, shape: BoxShape.circle),
                    child: Text(
                      '${mpcService.pendingPaymentRequests.length}',
                      style: const TextStyle(color: Colors.white, fontSize: 10),
                    ),
                  ),
                ),
            ],
          ),
          IconButton(
            key: const Key('arkContactsBtn'),
            icon: const Icon(Icons.people_outline),
            tooltip: 'Contacts',
            onPressed: () => context.push('/contacts'),
          ),
          IconButton(
            key: const Key('arkRefreshBtn'),
            icon: const Icon(Icons.refresh),
            onPressed: () => mpcService.refreshVtxos(),
          ),
        ],
      ),
      body: SafeArea(
        child: !arkAvailable
            ? _buildUnavailable(context)
            : Column(
                children: [
                  const SizedBox(height: 24),
                  _buildArkBalanceCard(
                      context, mpcService, arkBalance, balanceUsd),
                  const SizedBox(height: 32),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 24.0),
                    child: Align(
                      alignment: Alignment.centerLeft,
                      child: Text(
                        'Transactions',
                        style: GoogleFonts.inter(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                          color: Colors.white,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),
                  Expanded(
                    child: arkTxs.isEmpty
                        ? Center(
                            child: Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(Icons.receipt_long_outlined,
                                    size: 48, color: Colors.white24),
                                const SizedBox(height: 12),
                                Text(
                                  'History unavailable',
                                  style:
                                      GoogleFonts.inter(color: Colors.white38),
                                ),
                                const SizedBox(height: 4),
                                Text(
                                  'Your balance above is current',
                                  style: GoogleFonts.inter(
                                      color: Colors.white24, fontSize: 12),
                                ),
                              ],
                            ),
                          )
                        : ListView.builder(
                            padding: const EdgeInsets.symmetric(horizontal: 16),
                            itemCount: arkTxs.length,
                            itemBuilder: (context, index) {
                              final tx = arkTxs[arkTxs.length - 1 - index];
                              return _buildTransactionItem(context, tx);
                            },
                          ),
                  ),
                ],
              ),
      ),
      bottomNavigationBar: _buildBottomNav(context),
    );
  }

  Widget _buildUnavailable(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32.0),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.cloud_off, size: 64, color: Colors.white24),
            const SizedBox(height: 16),
            Text(
              'Ark Not Available',
              style: GoogleFonts.inter(
                fontSize: 20,
                fontWeight: FontWeight.bold,
                color: Colors.white54,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'The server is not connected to an ASP.\nArk features require an ASP connection.',
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(color: Colors.white38, fontSize: 14),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildArkBalanceCard(BuildContext context, MpcService mpcService,
      BigInt balance, double usdValue) {
    final balanceFormatter = NumberFormat("#,##0", "en_US");
    final usdFormatter = NumberFormat.currency(symbol: "\$");

    // Wallet-wide auto-renew state. Auto-settle consolidates every VTXO into one
    // renewed VTXO, so the soonest-expiring VTXO is the whole wallet's next
    // renewal deadline (min expiresAt, skipping not-yet-backfilled 0s).
    final hasFunds = balance > BigInt.zero;
    final delegated = mpcService.hasActiveDelegate;
    int? soonestExp;
    VtxoInfo? soonest;
    for (final v in mpcService.vtxos) {
      final e = v.expiresAt.toInt();
      if (e <= 0) continue;
      if (soonestExp == null || e < soonestExp) {
        soonestExp = e;
        soonest = v;
      }
    }

    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 24),
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(24),
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            const Color(0xFF1A237E),
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
                'Ark Balance',
                style: GoogleFonts.inter(
                  color: Colors.white54,
                  fontSize: 14,
                  fontWeight: FontWeight.w500,
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: Colors.blue.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  'Off-chain',
                  style: GoogleFonts.inter(
                    color: Colors.blueAccent,
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
          if (hasFunds) ...[
            const SizedBox(height: 12),
            delegated
                ? _buildRenewalLine(context, mpcService, soonest)
                : _buildEnableAutoRenew(context, mpcService),
          ],
          const SizedBox(height: 24),
          Row(
            children: [
              Expanded(
                child: _buildActionButton(
                  context,
                  widgetKey: const Key('arkSendBtn'),
                  icon: Icons.arrow_upward,
                  label: 'Send',
                  onTap: () => context.push('/ark/send'),
                  isPrimary: true,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _buildActionButton(
                  context,
                  widgetKey: const Key('arkReceiveBtn'),
                  icon: Icons.arrow_downward,
                  label: 'Receive',
                  onTap: () => context.push('/ark/receive'),
                  isPrimary: false,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _buildActionButton(
                  context,
                  widgetKey: const Key('arkBoardBtn'),
                  icon: Icons.login,
                  label: 'Board',
                  onTap: () => context.push('/ark/board'),
                  isPrimary: false,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  /// Wallet-wide auto-renew status line inside the balance card. When an expiry
  /// is known it shows a countdown and taps through to the refresh/expiry sheet;
  /// while the fresh expiry is still being backfilled it just reads "active".
  Widget _buildRenewalLine(
      BuildContext context, MpcService mpcService, VtxoInfo? soonest) {
    String label;
    VoidCallback? onTap;
    if (soonest == null) {
      label = 'Auto-renew active';
    } else {
      final s = soonest;
      final serverMargin =
          mpcService.arkInfo?.autoSettleSafetyMarginSecs.toInt() ?? 0;
      final nowSecs = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final secsUntil = (s.expiresAt.toInt() - serverMargin) - nowSecs;
      label = secsUntil <= 0
          ? 'Auto-renews soon'
          : 'Auto-renews in ${_formatTimeUntil(secsUntil)}';
      onTap = () => _showDelegateInfo(context, s, mpcService);
    }
    return InkWell(
      onTap: onTap,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.autorenew,
              size: 14, color: Colors.tealAccent.withOpacity(0.8)),
          const SizedBox(width: 6),
          Text(
            label,
            style: GoogleFonts.inter(
              color: Colors.white54,
              fontSize: 13,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

  /// Shown when the balance isn't auto-renewing — never delegated, or a
  /// receive/send invalidated the delegate and it needs the user's signature.
  /// The tap delegates now (pops the passkey), covering every un-delegated case.
  Widget _buildEnableAutoRenew(BuildContext context, MpcService mpcService) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          "Your funds aren't auto-renewing yet",
          style: GoogleFonts.inter(color: Colors.white38, fontSize: 12),
        ),
        const SizedBox(height: 8),
        SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            key: const Key('arkEnableAutoRenewBtn'),
            onPressed: () async {
              final messenger = ScaffoldMessenger.of(context);
              try {
                await mpcService.delegateNow();
                messenger.showSnackBar(const SnackBar(
                    content: Text('Auto-settle protection active')));
              } catch (e) {
                messenger.showSnackBar(
                    SnackBar(content: Text('Delegate failed: $e')));
              }
            },
            icon: Icon(Icons.shield_outlined,
                size: 18, color: Colors.tealAccent.withOpacity(0.9)),
            label: Text(
              'Enable auto-renew',
              style: GoogleFonts.inter(
                color: Colors.tealAccent.withOpacity(0.9),
                fontWeight: FontWeight.w600,
              ),
            ),
            style: OutlinedButton.styleFrom(
              side: BorderSide(color: Colors.tealAccent.withOpacity(0.5)),
              padding: const EdgeInsets.symmetric(vertical: 12),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
          ),
        ),
      ],
    );
  }

  /// Coarse "time until" label for the auto-renew countdown: days, else hours,
  /// else minutes, else "soon". Recomputed on rebuild (10s VTXO poll), so no
  /// live timer is needed.
  String _formatTimeUntil(int seconds) {
    if (seconds >= 86400) return '~${seconds ~/ 86400}d';
    if (seconds >= 3600) return '~${seconds ~/ 3600}h';
    if (seconds >= 60) return '~${seconds ~/ 60}m';
    return 'soon';
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
              size: 18,
              color: isPrimary ? Colors.black : Colors.white,
            ),
            const SizedBox(width: 6),
            Text(
              label,
              style: GoogleFonts.inter(
                color: isPrimary ? Colors.black : Colors.white,
                fontWeight: FontWeight.w600,
                fontSize: 13,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTransactionItem(BuildContext context, ArkTransactionSummary tx) {
    final amount = tx.amountSats.toInt();
    final isIncoming = amount >= 0;
    final absAmount = amount.abs();
    final formatter = NumberFormat("#,##0", "en_US");

    String title;
    switch (tx.txType) {
      case 'board':
        title = 'Boarded (UTXO → VTXO)';
        break;
      case 'send':
        title = 'Sent';
        break;
      case 'receive':
        title = 'Received';
        break;
      case 'settle':
        title = 'Refreshed (VTXO)';
        break;
      default:
        title = tx.txType;
    }

    final date = tx.timestamp > 0
        ? DateFormat.yMMMd().add_jm().format(
            DateTime.fromMillisecondsSinceEpoch(tx.timestamp.toInt() * 1000))
        : '';

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
                Text(
                  title,
                  overflow: TextOverflow.ellipsis,
                  style: GoogleFonts.inter(
                    fontWeight: FontWeight.w600,
                    color: Colors.white,
                    fontSize: 14,
                  ),
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
            '${isIncoming ? '+' : '-'}${formatter.format(absAmount)} Sats',
            style: GoogleFonts.inter(
              fontWeight: FontWeight.bold,
              color: isIncoming ? Colors.greenAccent : Colors.white,
            ),
          ),
        ],
      ),
    );
  }

  /// Bottom sheet shown when tapping a delegated received VTXO: explains the
  /// auto-refresh and shows the estimated refresh + expiry times.
  void _showDelegateInfo(
      BuildContext context, VtxoInfo vtxo, MpcService mpcService) {
    // The server auto-settles when now >= expires_at - safety_margin (see
    // auto_settle.rs), so that threshold is the real refresh time. The margin
    // comes from GetArkInfo. When the threshold is already in the past the
    // next 60s auto-settle tick refreshes it, so show it as imminent rather
    // than a stale timestamp.
    final serverMargin =
        mpcService.arkInfo?.autoSettleSafetyMarginSecs.toInt() ?? 0;
    final expiresAt = vtxo.expiresAt.toInt();
    final hasExpiry = expiresAt > 0;
    final fmt = DateFormat.yMMMd().add_jm();
    final expiryStr = hasExpiry
        ? fmt.format(DateTime.fromMillisecondsSinceEpoch(expiresAt * 1000))
        : null;
    final refreshAt = expiresAt - serverMargin;
    final nowSecs = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final hasRefreshEstimate = hasExpiry && serverMargin > 0;
    // Threshold already passed: the next auto-settle tick refreshes it.
    final refreshImminent = hasRefreshEstimate && refreshAt <= nowSecs;
    final refreshTimeStr = (hasRefreshEstimate && !refreshImminent)
        ? fmt.format(DateTime.fromMillisecondsSinceEpoch(refreshAt * 1000))
        : null;

    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E1E1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 20, 24, 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.autorenew,
                    size: 20, color: Colors.tealAccent.withOpacity(0.9)),
                const SizedBox(width: 8),
                Text(
                  'Auto-refresh enabled',
                  style: GoogleFonts.inter(
                    fontWeight: FontWeight.w600,
                    color: Colors.white,
                    fontSize: 16,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              'Your Ark balance is delegated to the server, which automatically '
              'refreshes all your funds together into a single VTXO before they '
              'expire — no action needed.',
              style: GoogleFonts.inter(
                color: Colors.white60,
                fontSize: 13,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 20),
            if (refreshImminent)
              _infoRow('Refreshes', 'any moment now')
            else if (refreshTimeStr != null)
              _infoRow('Refreshes around', refreshTimeStr)
            else
              _infoRow('Refreshes', 'shortly before expiry'),
            if (expiryStr != null) _infoRow('Expires', expiryStr),
          ],
        ),
      ),
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label,
              style: GoogleFonts.inter(color: Colors.white38, fontSize: 13)),
          Flexible(
            child: Text(
              value,
              textAlign: TextAlign.right,
              style: GoogleFonts.inter(
                color: Colors.white,
                fontSize: 13,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBottomNav(BuildContext context) {
    return const AppBottomNav(current: '/ark');
  }
}
