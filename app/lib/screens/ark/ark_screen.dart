import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:intl/intl.dart';
import 'package:app_core/asp/asp_client.dart' show IndexerVtxo;
import 'package:app/services/mpc_service.dart';
import 'package:app/widgets/app_bottom_nav.dart';

class ArkScreen extends StatelessWidget {
  const ArkScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final mpcService = context.watch<MpcService>();
    final arkBalance = mpcService.arkBalance;
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
                  // No history to show. The cosigner kept an Ark transaction log and served it
                  // over `ListArkTransactions`; it is called rather than running now, so it never
                  // sees a receive and could only ever log what it performed itself — a wallet
                  // that appears never to have been paid. Rebuilding this from the ASP indexer's
                  // `GetVirtualTxs` is its own piece of work.
                  Expanded(
                    child: Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.receipt_long_outlined,
                              size: 48, color: Colors.white24),
                          const SizedBox(height: 12),
                          Text(
                            'History unavailable',
                            style: GoogleFonts.inter(color: Colors.white38),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            'Your balance above is current',
                            style: GoogleFonts.inter(
                                color: Colors.white24, fontSize: 12),
                          ),
                        ],
                      ),
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
    final delegated = !mpcService.needsDelegateAction;
    int? soonestExp;
    IndexerVtxo? soonest;
    for (final v in mpcService.vtxos) {
      final e = v.expiresAt;
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
      BuildContext context, MpcService mpcService, IndexerVtxo? soonest) {
    String label;
    VoidCallback? onTap;
    if (soonest == null) {
      label = 'Auto-renew active';
    } else {
      // Counted to expiry, not to a refresh time. The refresh threshold was
      // `expires_at - GetArkInfo.auto_settle_safety_margin_secs`, a cosigner
      // setting it published so the app could show when it would settle on our
      // behalf. It does not settle on our behalf any more, and there is no RPC
      // for that margin — so the honest number is the one the ASP told us.
      final s = soonest;
      final nowSecs = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final secsUntil = s.expiresAt - nowSecs;
      label = secsUntil <= 0
          ? 'Renew now'
          : 'Renew within ${_formatTimeUntil(secsUntil)}';
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

  /// Shown when the user has to do something: refresh funds that are due, or be reminded about funds
  /// that arrived since the watch was armed. Each is one passkey prompt, and only on this tap —
  /// nothing here happens unasked.
  Widget _buildEnableAutoRenew(BuildContext context, MpcService mpcService) {
    final due = mpcService.refreshDue;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          due
              ? 'Some of your funds need refreshing now'
              : "New funds aren't set to renew themselves yet",
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
                if (due) {
                  await mpcService.delegateNow();
                  messenger.showSnackBar(
                      const SnackBar(content: Text('Funds refreshed')));
                } else {
                  await mpcService.protectFunds();
                  messenger.showSnackBar(const SnackBar(
                      content: Text('These funds will renew themselves before they expire')));
                }
              } catch (e) {
                messenger.showSnackBar(SnackBar(
                    content: Text(due ? 'Refresh failed: $e' : 'Could not protect these funds: $e')));
              }
            },
            icon: Icon(Icons.shield_outlined,
                size: 18, color: Colors.tealAccent.withOpacity(0.9)),
            label: Text(
              due ? 'Refresh funds' : 'Renew automatically',
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

  /// Bottom sheet shown when tapping a VTXO: explains what keeps it alive and
  /// when it stops being spendable off-chain.
  void _showDelegateInfo(
      BuildContext context, IndexerVtxo vtxo, MpcService mpcService) {
    final expiresAt = vtxo.expiresAt;
    final hasExpiry = expiresAt > 0;
    final fmt = DateFormat.yMMMd().add_jm();
    final expiryStr = hasExpiry
        ? fmt.format(DateTime.fromMillisecondsSinceEpoch(expiresAt * 1000))
        : null;
    final nowSecs = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final overdue = hasExpiry && expiresAt <= nowSecs;
    final delegated = mpcService.fundsProtected;

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
                  delegated ? 'Renews automatically' : 'Not set to renew',
                  style: GoogleFonts.inter(
                    fontWeight: FontWeight.w600,
                    color: Colors.white,
                    fontSize: 16,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            // This used to read "delegated to the server, which automatically
            // refreshes your funds — no action needed". That is no longer true,
            // and it is the kind of untrue that costs someone their VTXOs: the
            // cosigner runs as a sandboxed guest with no network access at all,
            // so it can reach neither the ASP nor anything else and cannot
            // settle on our behalf. What it does is hold the signed renewal and
            // watch the clock, waking this device when the deadline nears.
            Text(
              delegated
                  ? 'You signed a renewal for these funds, and the secure enclave '
                      'holding the other half of your key will submit it before they '
                      'expire — nothing for you to do, even with your phone off.'
                  : 'No signed renewal covers these funds yet. Tap "Renew '
                      'automatically" on the Ark tab — or send or refresh, which '
                      'sets it up on the way.',
              style: GoogleFonts.inter(
                color: Colors.white60,
                fontSize: 13,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 20),
            if (overdue)
              _infoRow('Refresh', 'now — this VTXO has expired')
            else if (expiryStr != null)
              _infoRow('Refresh before', expiryStr),
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
