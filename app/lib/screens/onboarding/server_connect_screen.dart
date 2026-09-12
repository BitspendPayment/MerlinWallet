import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import '../../services/mpc_service.dart';

const String _regtestHost = '10.0.2.2';
// Physical phone reaches the host over `adb reverse` at 127.0.0.1 (10.0.2.2 is emulator-only).
const String _regtestPhoneHost = '127.0.0.1';
const String _mutinyHost = 'mutiny.vtxos.network';

class ServerConnectionScreen extends StatefulWidget {
  const ServerConnectionScreen({super.key});

  @override
  State<ServerConnectionScreen> createState() => _ServerConnectionScreenState();
}

class _ServerConnectionScreenState extends State<ServerConnectionScreen> {
  String? _selecting;

  Future<void> _pick(String host) async {
    if (_selecting != null) return;
    final extras =
        GoRouterState.of(context).extra as Map<String, dynamic>? ?? {};
    setState(() => _selecting = host);
    try {
      await context.read<MpcService>().setHost(host);
      if (!mounted) return;
      context.push('/onboarding/dkg', extra: extras);
    } catch (e) {
      if (!mounted) return;
      setState(() => _selecting = null);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Connection failed: $e')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Choose a Server')),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Co-signing Server',
              style:
                  GoogleFonts.inter(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            Text(
              'Pick where the MPC co-signing server is running.',
              style: GoogleFonts.inter(color: Colors.white70),
            ),
            const SizedBox(height: 24),
            _PresetCard(
              keyName: 'serverPresetMutiny',
              icon: Icons.shield_outlined,
              title: 'Mutiny',
              subtitle: 'Mutinynet (signet) at mutiny.vtxos.network — test coins, '
                  'not enclave-attested',
              busy: _selecting == _mutinyHost,
              disabled: _selecting != null && _selecting != _mutinyHost,
              onTap: () => _pick(_mutinyHost),
            ),
            if (kDebugMode) ...[
              const SizedBox(height: 16),
              _PresetCard(
                keyName: 'serverPresetRegtest',
                icon: Icons.developer_board,
                title: 'Regtest (local)',
                subtitle:
                    'Local cosigner on $_regtestHost — emulator',
                busy: _selecting == _regtestHost,
                disabled: _selecting != null && _selecting != _regtestHost,
                onTap: () => _pick(_regtestHost),
              ),
              const SizedBox(height: 16),
              _PresetCard(
                keyName: 'serverPresetRegtestPhone',
                icon: Icons.phone_android,
                title: 'Regtest (phone)',
                subtitle:
                    'Local cosigner on $_regtestPhoneHost — physical phone via adb reverse',
                busy: _selecting == _regtestPhoneHost,
                disabled:
                    _selecting != null && _selecting != _regtestPhoneHost,
                onTap: () => _pick(_regtestPhoneHost),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _PresetCard extends StatelessWidget {
  const _PresetCard({
    required this.keyName,
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.busy,
    required this.disabled,
    required this.onTap,
  });

  final String keyName;
  final IconData icon;
  final String title;
  final String subtitle;
  final bool busy;
  final bool disabled;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Card(
      key: Key(keyName),
      child: InkWell(
        onTap: disabled ? null : onTap,
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Row(
            children: [
              Icon(icon, size: 32),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: GoogleFonts.inter(
                          fontSize: 16, fontWeight: FontWeight.w600),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      subtitle,
                      style: GoogleFonts.inter(
                          fontSize: 13, color: Colors.white70),
                    ),
                  ],
                ),
              ),
              if (busy)
                const SizedBox(
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              else
                const Icon(Icons.chevron_right),
            ],
          ),
        ),
      ),
    );
  }
}
