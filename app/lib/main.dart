import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'theme/app_theme.dart';
import 'screens/onboarding/welcome_screen.dart';
import 'screens/onboarding/server_connect_screen.dart';
import 'screens/onboarding/dkg_progress_screen.dart';
import 'screens/onboarding/passkey_setup_screen.dart';
import 'screens/onboarding/restore_wallet_screen.dart';
import 'screens/onboarding/wallet_ready_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/exit/exit_screen.dart';
import 'screens/onboarding/exit_address_screen.dart';
import 'screens/splash_screen.dart';
import 'screens/ark/ark_screen.dart';
import 'screens/ark/ark_board_screen.dart';
import 'screens/send/send_hub_screen.dart';
import 'screens/send/payout_form_screen.dart';
import 'screens/send/payout_quote_screen.dart';
import 'screens/send/payout_progress_screen.dart';

import 'package:provider/provider.dart';
import 'services/mpc_service.dart';
import 'services/payout_service.dart';
import 'services/push_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Best-effort push init. No-ops gracefully when Firebase config is missing
  // (e.g. CI builds without google-services.json).
  await PushService.initialize();
  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) {
          final svc = MpcService();
          svc.initFuture = svc.init();
          // Offered now, before onboarding, so the DKG carries the token and
          // no enrolment call — no second fingerprint — follows it.
          PushService.offerToken(svc);
          // Wakes are acted on once a wallet is open: DKG or session restore
          // is what populates client.userId.
          late final VoidCallback loginListener;
          loginListener = () {
            if (svc.client?.userId != null) {
              svc.removeListener(loginListener);
              PushService.onLoggedIn(svc);
            }
          };
          svc.addListener(loginListener);
          return svc;
        }),
        // Not lazy: it picks up payouts still in flight as soon as the wallet opens.
        ChangeNotifierProvider(
          lazy: false,
          create: (context) => PayoutService(context.read<MpcService>()),
        ),
      ],
      child: const MerlinWalletApp(),
    ),
  );
}

class MerlinWalletApp extends StatefulWidget {
  const MerlinWalletApp({super.key});

  @override
  State<MerlinWalletApp> createState() => _MerlinWalletAppState();
}

class _MerlinWalletAppState extends State<MerlinWalletApp> {
  GoRouter? _router;

  @override
  Widget build(BuildContext context) {
    // Keep one router instance across app rebuilds.
    _router ??= _buildRouter();
    return MaterialApp.router(
      title: 'Merlin Wallet',
      theme: AppTheme.darkTheme,
      routerConfig: _router!,
      debugShowCheckedModeBanner: false,
    );
  }
}

// No `refreshListenable`: nothing here redirects, and a refresh rebuilds every pushed page from the
// route alone — dropping an object passed as `extra`, which the send screens are opened with.
GoRouter _buildRouter() => GoRouter(
      initialLocation: '/splash',
      routes: [
        GoRoute(
          path: '/splash',
          builder: (context, state) => const SplashScreen(),
        ),
        // The wallet is the Ark wallet now; there is no other.
        GoRoute(
          path: '/',
          builder: (context, state) => const ArkScreen(),
        ),
        GoRoute(
          path: '/exit',
          builder: (context, state) => const ExitScreen(),
        ),
        GoRoute(
          path: '/onboarding/welcome',
          builder: (context, state) => const WelcomeScreen(),
        ),
        GoRoute(
          path: '/onboarding/server',
          builder: (context, state) => const ServerConnectionScreen(),
        ),
        GoRoute(
          path: '/onboarding/dkg',
          builder: (context, state) => const DkgProgressScreen(),
        ),
        GoRoute(
          path: '/onboarding/passkey',
          builder: (context, state) => const PasskeySetupScreen(),
        ),
        GoRoute(
          path: '/onboarding/restore',
          builder: (context, state) => const RestoreWalletScreen(),
        ),
        GoRoute(
          path: '/onboarding/ready',
          builder: (context, state) => const WalletReadyScreen(),
        ),
        GoRoute(
          path: '/onboarding/exit-address',
          builder: (context, state) => const ExitAddressScreen(),
        ),
        GoRoute(
          path: '/ark',
          builder: (context, state) => const ArkScreen(),
        ),
        GoRoute(
          path: '/ark/receive',
          builder: (context, state) => const ArkBoardScreen(),
        ),
        // Sending to bank accounts and mobile money, through the payout platform.
        GoRoute(
          path: '/send',
          builder: (context, state) => const SendHubScreen(),
        ),
        GoRoute(
          path: '/send/payout',
          builder: (context, state) =>
              PayoutFormScreen(args: state.extra! as PayoutFormArgs),
        ),
        GoRoute(
          path: '/send/payout/quote',
          builder: (context, state) =>
              PayoutQuoteScreen(draft: state.extra! as PayoutDraft),
        ),
        GoRoute(
          path: '/send/payout/progress',
          builder: (context, state) =>
              PayoutProgressScreen(dealTag: state.extra! as String),
        ),
        GoRoute(
          path: '/settings',
          builder: (context, state) => const SettingsScreen(),
        ),
      ],
    );
