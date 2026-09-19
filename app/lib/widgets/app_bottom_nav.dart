import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

/// Bottom navigation, built by route so indices are derived rather than hardcoded.
///
/// Three destinations, because this wallet does three things: hold money in Ark, get it out
/// without anyone's help, and be configured. The Home tab was the on-chain wallet's, Services was
/// a tab with nothing behind it, and Send lives on the Ark screen with Receive and Board.
class AppBottomNav extends StatelessWidget {
  /// Route of the current screen, e.g. '/' or '/ark'.
  final String current;
  const AppBottomNav({super.key, required this.current});

  @override
  Widget build(BuildContext context) {
    const items = <_NavItem>[
      _NavItem('/', Icons.account_balance_wallet_outlined,
          Icons.account_balance_wallet, 'Wallet'),
      _NavItem('/exit', Icons.exit_to_app_outlined, Icons.exit_to_app, 'Exit'),
      _NavItem('/settings', Icons.settings_outlined, Icons.settings, 'Settings'),
    ];

    int currentIndex = items.indexWhere((i) => i.route == current);
    if (currentIndex < 0) currentIndex = 0;

    return BottomNavigationBar(
      backgroundColor: const Color(0xFF1E1E1E),
      selectedItemColor: Colors.white,
      unselectedItemColor: Colors.white38,
      showSelectedLabels: true,
      showUnselectedLabels: true,
      type: BottomNavigationBarType.fixed,
      currentIndex: currentIndex,
      onTap: (index) {
        final route = items[index].route;
        if (route != current) context.go(route);
      },
      items: [
        for (final i in items)
          BottomNavigationBarItem(
            icon: Icon(i.icon),
            activeIcon: Icon(i.activeIcon),
            label: i.label,
          ),
      ],
    );
  }
}

class _NavItem {
  final String route;
  final IconData icon;
  final IconData activeIcon;
  final String label;
  const _NavItem(this.route, this.icon, this.activeIcon, this.label);
}
