/// The way out: the transactions that spend this wallet's money without anyone's permission.
///
/// A VTXO can be spent two ways. The cooperative way needs the ASP, and the unilateral way needs
/// only its owner — except that the owner here is a 2-of-2 with the cosigner, so the signature has
/// to be collected while the cosigner is still answering. That is what every delegate renewal does
/// — at the end of a send, a refresh, and every entry to the app — handing back one signed exit per
/// VTXO, paying an address in a wallet this app does not control. They are kept on this phone.
///
/// This screen is the honest account of that: what is covered, what is not, when each becomes
/// spendable, and what still has to happen for a full exit — because a pre-signed spend is the last
/// hop, not the whole journey.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'package:app_core/asp/exit_chain.dart';
import 'package:app_core/sessions/exit_plan.dart' show ExitTx;
import 'package:app/services/mpc_service.dart';
import 'package:app/widgets/app_bottom_nav.dart';

class ExitScreen extends StatelessWidget {
  const ExitScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final service = context.watch<MpcService>();
    final exits = service.exits;
    final uncovered = service.vtxosWithoutExit;
    final coveredSats = exits.fold<int>(0, (s, e) => s + e.amountSats);
    final uncoveredSats = uncovered.fold<int>(0, (s, v) => s + v.amountSats);

    return Scaffold(
      appBar: AppBar(
        title:
            Text('Exit', style: GoogleFonts.inter(fontWeight: FontWeight.w600)),
        centerTitle: true,
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
          children: [
            _explainer(),
            const SizedBox(height: 20),
            _addressCard(context, service),
            const SizedBox(height: 20),
            if (exits.isEmpty && uncovered.isEmpty)
              _empty()
            else ...[
              _coverage(coveredSats, uncoveredSats),
              if (uncovered.isNotEmpty) ...[
                const SizedBox(height: 12),
                _uncoveredNote(service),
              ],
              const SizedBox(height: 20),
              Text('Signed and yours',
                  style: GoogleFonts.inter(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: Colors.white)),
              const SizedBox(height: 8),
              for (final exit in exits) _exitTile(context, exit),
            ],
            const SizedBox(height: 20),
            _whatIsMissing(),
          ],
        ),
      ),
      bottomNavigationBar: const AppBottomNav(current: '/exit'),
    );
  }

  Widget _explainer() => Text(
        'If this service stops answering, these transactions are how you get your money out. '
        'Each one pays the funds it covers to its exit address after a waiting period, and needs nobody '
        'else to sign it.',
        style:
            GoogleFonts.inter(color: Colors.white60, fontSize: 13, height: 1.5),
      );

  Widget _addressCard(BuildContext context, MpcService service) {
    final address = service.exitAddress;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1E1E1E),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        children: [
          Icon(Icons.north_east,
              size: 20, color: Colors.tealAccent.withOpacity(0.9)),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Your exit address',
                    style:
                        GoogleFonts.inter(color: Colors.white54, fontSize: 12)),
                const SizedBox(height: 4),
                Text(
                  address ?? 'Not set — nothing can be pre-signed',
                  style: GoogleFonts.robotoMono(
                      color:
                          address == null ? Colors.orangeAccent : Colors.white,
                      fontSize: 12),
                ),
              ],
            ),
          ),
          TextButton(
            key: const Key('exitChangeAddressBtn'),
            onPressed: () => context.push('/settings'),
            child: const Text('Change'),
          ),
        ],
      ),
    );
  }

  Widget _empty() => Padding(
        padding: const EdgeInsets.symmetric(vertical: 32),
        child: Column(
          children: [
            Icon(Icons.inbox_outlined, size: 48, color: Colors.white24),
            const SizedBox(height: 12),
            Text('No funds to exit yet',
                style: GoogleFonts.inter(color: Colors.white38)),
          ],
        ),
      );

  Widget _coverage(int coveredSats, int uncoveredSats) {
    final format = NumberFormat('#,##0', 'en_US');
    return Row(
      children: [
        Expanded(
          child: _stat('Covered', '${format.format(coveredSats)} sats',
              Colors.tealAccent),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _stat(
            'Not covered',
            '${format.format(uncoveredSats)} sats',
            uncoveredSats == 0 ? Colors.white38 : Colors.orangeAccent,
          ),
        ),
      ],
    );
  }

  Widget _stat(String label, String value, Color colour) => Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: const Color(0xFF1E1E1E),
          borderRadius: BorderRadius.circular(16),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label,
                style: GoogleFonts.inter(color: Colors.white54, fontSize: 12)),
            const SizedBox(height: 6),
            Text(value,
                style: GoogleFonts.inter(
                    color: colour, fontSize: 16, fontWeight: FontWeight.bold)),
          ],
        ),
      );

  /// Money no exit covers yet: what the cosigner made by renewing on its own, or an escrow's leftover
  /// taken back. Nothing to press — the next entry to the app signs an exit for everything held
  /// (`MpcService.unlock`), as long as there is an address to pay.
  Widget _uncoveredNote(MpcService service) => Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: Colors.orange.withOpacity(0.08),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: Colors.orangeAccent.withOpacity(0.3)),
        ),
        child: Text(
          service.hasExitAddress
              ? 'Some of your money has no exit yet. A renewal, or a leftover coming back, makes '
                  'a new output, and only you can sign its exit. It is signed the next time you '
                  'open the app.'
              : 'Some of your money has no exit yet. Exits are signed once an exit address is '
                  'set.',
          style: GoogleFonts.inter(color: Colors.white70, fontSize: 13, height: 1.4),
        ),
      );

  Widget _exitTile(BuildContext context, ExitTx exit) {
    final format = NumberFormat('#,##0', 'en_US');
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1E1E1E),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text('${format.format(exit.amountSats)} sats',
                    style: GoogleFonts.inter(
                        color: Colors.white,
                        fontSize: 16,
                        fontWeight: FontWeight.bold)),
              ),
              IconButton(
                key: const Key('exitCopyBtn'),
                tooltip: 'Copy transaction',
                icon: const Icon(Icons.copy, size: 18),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: exit.rawTx));
                  ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Exit transaction copied')));
                },
              ),
              IconButton(
                tooltip: 'Show as QR',
                icon: const Icon(Icons.qr_code, size: 18),
                onPressed: () => _showQr(context, exit),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text('from ${_short(exit.outpoint)}',
              style:
                  GoogleFonts.robotoMono(color: Colors.white38, fontSize: 11)),
          const SizedBox(height: 8),
          Row(
            children: [
              Icon(Icons.schedule, size: 14, color: Colors.white38),
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  'Spendable ${describeDelay(exit.sequence)} after the transaction holding these '
                  'funds is confirmed on-chain',
                  style: GoogleFonts.inter(color: Colors.white38, fontSize: 11),
                ),
              ),
            ],
          ),
          _ExitPath(exit: exit),
        ],
      ),
    );
  }

  void _showQr(BuildContext context, ExitTx exit) {
    showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        title: Text('Exit transaction',
            style: GoogleFonts.inter(color: Colors.white)),
        content: SizedBox(
          width: 280,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                color: Colors.white,
                padding: const EdgeInsets.all(8),
                child: QrImageView(data: exit.rawTx, size: 240),
              ),
              const SizedBox(height: 12),
              Text(
                'Scanning this gives the whole signed transaction. Broadcast it from anywhere.',
                style: GoogleFonts.inter(color: Colors.white54, fontSize: 12),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Close')),
        ],
      ),
    );
  }

  /// The parts of an exit this wallet cannot do for you yet, said plainly rather than implied.
  Widget _whatIsMissing() => Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: const Color(0xFF161616),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: Colors.white10),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('What these do not do yet',
                style: GoogleFonts.inter(
                    color: Colors.white70,
                    fontSize: 13,
                    fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            Text(
              'Your money lives off-chain, so before an exit can be mined, the transactions that '
              'put it there have to be published on-chain first. This app cannot do that step yet; '
              'a later version will.\n\n'
              'An exit also pays no fee — it carries a tiny output anyone can spend to pay for it. '
              'Whoever broadcasts it attaches that fee, which is why it never becomes too cheap to '
              'confirm, however long it sits here.',
              style: GoogleFonts.inter(
                  color: Colors.white38, fontSize: 12, height: 1.5),
            ),
          ],
        ),
      );

  static String _short(String outpoint) {
    final parts = outpoint.split(':');
    final txid = parts.first;
    if (txid.length <= 16) return outpoint;
    return '${txid.substring(0, 8)}…${txid.substring(txid.length - 6)}:${parts.last}';
  }
}

/// A BIP-68 nSequence, in words: bit 22 set means units of 512 seconds, otherwise blocks.
String describeDelay(int sequence) {
  final value = sequence & 0xFFFF;
  if (sequence & (1 << 22) != 0) {
    final duration = Duration(seconds: value * 512);
    if (duration.inDays > 0) {
      return '${duration.inDays} day${duration.inDays == 1 ? '' : 's'}';
    }
    if (duration.inHours > 0) {
      return '${duration.inHours} hour${duration.inHours == 1 ? '' : 's'}';
    }
    return '${duration.inMinutes} minutes';
  }
  return '$value block${value == 1 ? '' : 's'}';
}

/// The whole path this exit has to take, fetched when the user asks for it.
///
/// An exit alone spends nothing: the transaction that made its VTXO was never published, nor the
/// one before that, back to a commitment transaction the ASP put on-chain when it ran the batch.
/// This shows that line of descent in the order it must be broadcast, with the exit at the end, so
/// what is actually required is visible rather than implied.
class _ExitPath extends StatefulWidget {
  const _ExitPath({required this.exit});

  final ExitTx exit;

  @override
  State<_ExitPath> createState() => _ExitPathState();
}

class _ExitPathState extends State<_ExitPath> {
  Future<ExitChain>? _chain;

  @override
  Widget build(BuildContext context) {
    return Theme(
      data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
      child: ExpansionTile(
        key: const Key('exitPathTile'),
        tilePadding: EdgeInsets.zero,
        childrenPadding: const EdgeInsets.only(bottom: 8),
        title: Text('The full path on-chain',
            style: GoogleFonts.inter(color: Colors.white70, fontSize: 12)),
        // Asked for only when opened: it is a call to the ASP's indexer, and most of the time
        // nobody needs it.
        onExpansionChanged: (open) {
          if (open && _chain == null) {
            setState(() =>
                _chain = context.read<MpcService>().exitChain(widget.exit));
          }
        },
        children: [
          FutureBuilder<ExitChain>(
            future: _chain,
            builder: (context, snapshot) {
              if (snapshot.connectionState != ConnectionState.done) {
                return const Padding(
                  padding: EdgeInsets.all(12),
                  child: SizedBox(
                      height: 18,
                      width: 18,
                      child: CircularProgressIndicator(strokeWidth: 2)),
                );
              }
              if (snapshot.hasError) {
                return Text('Could not read the path: ${snapshot.error}',
                    style: GoogleFonts.inter(
                        color: Colors.orangeAccent, fontSize: 11));
              }
              return _path(context, snapshot.data!);
            },
          ),
        ],
      ),
    );
  }

  Widget _path(BuildContext context, ExitChain chain) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final hop in chain.hops)
          _hop(hop, chain.hops.indexOf(hop) == chain.hops.length - 1),
        if (chain.missing.isNotEmpty) ...[
          const SizedBox(height: 8),
          Text(
            'The server did not return ${chain.missing.length} transaction'
            '${chain.missing.length == 1 ? '' : 's'} this path needs. Without them the exit cannot '
            'be published — try again later, or while the server is reachable.',
            style: GoogleFonts.inter(
                color: Colors.orangeAccent, fontSize: 11, height: 1.4),
          ),
        ],
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: Text(
                '${chain.toPublish.length} transaction'
                '${chain.toPublish.length == 1 ? '' : 's'} to broadcast, in this order. The first '
                'is already on-chain.',
                style: GoogleFonts.inter(color: Colors.white38, fontSize: 11),
              ),
            ),
            TextButton.icon(
              key: const Key('exitCopyPathBtn'),
              onPressed: chain.isComplete
                  ? () {
                      final all = [
                        for (final hop in chain.toPublish)
                          if (hop.rawTx != null) hop.rawTx!,
                      ].join('\n');
                      Clipboard.setData(ClipboardData(text: all));
                      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                          content: Text('Whole path copied, in order')));
                    }
                  : null,
              icon: const Icon(Icons.copy_all, size: 16),
              label: const Text('Copy path'),
            ),
          ],
        ),
      ],
    );
  }

  Widget _hop(ExitHop hop, bool last) {
    final (label, colour) = switch (hop.kind) {
      ChainKind.commitment => ('On-chain already', Colors.greenAccent),
      ChainKind.tree => ('Batch tree', Colors.white54),
      ChainKind.checkpoint => ('Checkpoint', Colors.white54),
      ChainKind.ark => ('The payment', Colors.white54),
      ChainKind.exit => ('Your exit', Colors.tealAccent),
      ChainKind.unknown => ('Unknown', Colors.orangeAccent),
    };
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Column(
            children: [
              Icon(
                hop.kind == ChainKind.commitment
                    ? Icons.check_circle
                    : (hop.kind == ChainKind.exit
                        ? Icons.exit_to_app
                        : Icons.arrow_downward),
                size: 14,
                color: colour,
              ),
              if (!last) Container(width: 1, height: 18, color: Colors.white12),
            ],
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label,
                    style: GoogleFonts.inter(color: colour, fontSize: 12)),
                Text(
                  hop.txid.isEmpty ? '(txid unknown)' : _shortTxid(hop.txid),
                  style: GoogleFonts.robotoMono(
                      color: Colors.white38, fontSize: 10),
                ),
              ],
            ),
          ),
          if (hop.kind != ChainKind.commitment && hop.rawTx == null)
            Text('missing',
                style: GoogleFonts.inter(
                    color: Colors.orangeAccent, fontSize: 10)),
        ],
      ),
    );
  }

  static String _shortTxid(String txid) => txid.length <= 20
      ? txid
      : '${txid.substring(0, 10)}…${txid.substring(txid.length - 8)}';
}
