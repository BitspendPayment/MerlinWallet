import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'theme/app_theme.dart';
import 'screens/home_screen.dart';
import 'screens/onboarding/welcome_screen.dart';
import 'screens/onboarding/server_connect_screen.dart';
import 'screens/onboarding/dkg_progress_screen.dart';
import 'screens/onboarding/passkey_setup_screen.dart';
import 'screens/onboarding/wallet_ready_screen.dart';
import 'screens/spending/send_screen.dart';
import 'screens/spending/review_screen.dart';
import 'screens/spending/signing_screen.dart';
import 'screens/receive_screen.dart';
import 'screens/contacts/contacts_screen.dart';
import 'screens/payments/requests_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/splash_screen.dart';
import 'screens/ark/ark_screen.dart';
import 'screens/ark/ark_receive_screen.dart';
import 'screens/ark/ark_send_screen.dart';
import 'screens/ark/ark_board_screen.dart';

import 'package:provider/provider.dart';
import 'services/mpc_service.dart';
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
          // The FCM token can only be registered once the wallet is
          // authenticated — DKG or session restore is what populates
          // client.userId. init() alone doesn't log in, so register on the
          // first change where a user id exists. Idempotent; PushService also
          // re-registers on token rotation.
          late final VoidCallback tokenListener;
          tokenListener = () {
            if (svc.client?.userId != null) {
              svc.removeListener(tokenListener);
              PushService.registerCurrentToken(svc);
            }
          };
          svc.addListener(tokenListener);
          return svc;
        }),
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
    // Build once, wiring the router to MpcService so the offline-mode guard can
    // re-evaluate (refreshListenable) and redirect off Ark routes.
    _router ??= _buildRouter(context.read<MpcService>());
    return MaterialApp.router(
      title: 'Merlin Wallet',
      theme: AppTheme.darkTheme,
      routerConfig: _router!,
      debugShowCheckedModeBanner: false,
    );
  }
}

GoRouter _buildRouter(MpcService mpc) => GoRouter(
  initialLocation: '/splash',
  refreshListenable: mpc,
  // In offline mode the Ark + Services routes are unreachable — bounce to Home.
  redirect: (context, state) {
    final path = state.uri.path;
    final isArkRoute =
        path == '/ark' || path.startsWith('/ark/') || path == '/services';
    if (isArkRoute && mpc.offlineMode) return '/';
    return null;
  },
  routes: [
    GoRoute(
      path: '/splash',
      builder: (context, state) => const SplashScreen(),
    ),
    GoRoute(
      path: '/',
      builder: (context, state) => const HomeScreen(),
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
      path: '/onboarding/ready',
      builder: (context, state) => const WalletReadyScreen(),
    ),
    GoRoute(
      path: '/spending/send',
      builder: (context, state) => const SendScreen(),
    ),
    GoRoute(
      path: '/receive',
      builder: (context, state) => const ReceiveScreen(),
    ),
    GoRoute(
      path: '/contacts',
      builder: (context, state) => const ContactsScreen(),
    ),
    GoRoute(
      path: '/requests',
      builder: (context, state) => const RequestsScreen(),
    ),
    GoRoute(
      path: '/spending/review',
      builder: (context, state) {
        final extras = state.extra as Map<String, dynamic>? ?? {};
        return ReviewScreen(extras: extras);
      },
    ),
    GoRoute(
      path: '/spending/signing',
      builder: (context, state) {
        final extras = state.extra as Map<String, dynamic>? ?? {};
        return SigningScreen(extras: extras);
      },
    ),
    GoRoute(
      path: '/ark',
      builder: (context, state) => const ArkScreen(),
    ),
    GoRoute(
      path: '/ark/receive',
      builder: (context, state) => const ArkReceiveScreen(),
    ),
    GoRoute(
      path: '/ark/send',
      builder: (context, state) => const ArkSendScreen(),
    ),
    GoRoute(
      path: '/ark/board',
      builder: (context, state) => const ArkBoardScreen(),
    ),
    GoRoute(
      path: '/settings',
      builder: (context, state) => const SettingsScreen(),
    ),
  ],
);
