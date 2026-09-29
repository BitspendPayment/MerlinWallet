/// Sending money to a bank account or a mobile-money wallet, through the payout platform, paid for
/// out of an escrow.
///
/// The steps are app-core's `BankSend`. This keeps what the app has to remember between them —
/// each payout, and the key of the escrow they are paid from — in the `payouts` box, and follows the
/// payouts in flight, again after a restart. Following asks the platform, never the cosigner, so it
/// costs no approval.
library;

import 'dart:async';
import 'dart:io' show SocketException;
import 'dart:math' show pow;

import 'package:app_core/asp/ark_info.dart' show IndexerVtxo;
import 'package:app_core/client.dart';
import 'package:app_core/passkey/operation_secrets.dart' show OperationCancelled;
import 'package:app_core/platform/bank_send.dart';
import 'package:app_core/platform/platform_client.dart';
import 'package:app_core/platform/policy_check.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart' as services show PlatformException;
import 'package:grpc/grpc.dart' show GrpcError;
import 'package:hive/hive.dart';
import 'package:intl/intl.dart';

import '../passkey/passkey_channel.dart';
import 'mpc_service.dart';
import 'server_host.dart' as server_host;

/// Also cleared by name in `MpcService.resetLocalWallet`.
const _boxName = 'payouts';

/// Kept in the box beside the payouts, which are maps under their deal tags.
const _escrowKeyKey = 'escrowKey';

/// A payout's steps, in order. [Payout.step] is the one it has got to; `done` is past them all.
const payoutSteps = ['policy', 'seal', 'fund', 'pay', 'repay'];

/// One payout as this device remembers it: a JSON map in the `payouts` box, under its deal tag.
class Payout {
  Payout(Map json) : json = Map<String, dynamic>.from(json);
  final Map<String, dynamic> json;

  String get dealTag => json['deal_tag'] as String;
  String get country => json['country'] as String;

  /// `bank` or `mobile_money`.
  String get rail => json['rail'] as String;
  Map<String, String> get fields => Map<String, String>.from(json['fields'] as Map);
  String get fullName => json['full_name'] as String;
  String? get nameAtBank => json['name_at_bank'] as String?;
  int get amountMinor => json['amount_minor'] as int;
  String get currency => json['currency'] as String;
  int get decimals => json['decimals'] as int;

  /// The agreed price.
  int get sats => json['sats'] as int;
  String get escrowKey => json['escrow_key'] as String;

  /// This send set the escrow up first.
  bool get setUp => json['set_up'] as bool? ?? false;

  /// What was, or is being, sent to the escrow to bring it up to the price.
  int get topUpSats => json['top_up_sats'] as int? ?? 0;

  /// The platform's word — quoted, funding, paying, paid_out, repaying, repaid, failed — or
  /// `committing` while this device seals it.
  String get state => json['state'] as String;

  /// One of [payoutSteps], or `done`.
  String get step => json['step'] as String;
  String? get failure => json['failure'] as String?;

  /// Said while the platform's answer is awaited, when there is something to say.
  String? get note => json['note'] as String?;
  String? get gridStatus => json['grid_status'] as String?;

  /// The platform's repayment, out of the escrow.
  String? get arkTxid => json['ark_txid'] as String?;

  /// What was taken back from the escrow after a failure, once it has been.
  int? get leftoverSats => json['leftover_sats'] as int?;
  DateTime get createdAt => DateTime.fromMillisecondsSinceEpoch(json['created_at'] as int);

  /// Until when its deal holds the escrow: nothing else can be sealed over it, and nothing taken
  /// back from it, before then. Null when no deal does.
  DateTime? get holdUntil {
    final at = json['hold_until'] as int?;
    return at == null ? null : DateTime.fromMillisecondsSinceEpoch(at);
  }

  bool get failed => state == 'failed';
  bool get finished => state == 'repaid' || failed;
  bool get paidOut => const {'paid_out', 'repaying', 'repaid'}.contains(state);

  String get amount => formatMinor(amountMinor, currency, decimals);

  /// The account and the bank, or the phone and the network, on one line.
  String get destination => fields.values.join(' · ');
}

/// What the owner filled in: whom to pay, where, and how much.
class PayoutDraft {
  const PayoutDraft({
    required this.corridor,
    required this.rail,
    required this.fields,
    required this.fullName,
    required this.amountMinor,
  });

  final Corridor corridor;
  final Rail rail;

  /// By Grid's names for them, which the platform and the sealed policy use too.
  final Map<String, String> fields;
  final String fullName;
  final int amountMinor;

  String get amount => formatMinor(amountMinor, corridor.currency, corridor.decimals);
}

/// [text], in the currency's major units, as minor units — `1,500.5` at 2 decimals is 150050 — or
/// null if it is not an amount with at most [decimals] places.
///
/// Commas only where thousands are grouped: `1500,50` is refused rather than read as a hundred
/// times too much.
int? toMinor(String text, int decimals) {
  final m = RegExp(r'^(\d{1,3}(?:,\d{3})+|\d*)(?:\.(\d*))?$').firstMatch(text.trim());
  if (m == null) return null;
  final whole = m[1]!.replaceAll(',', ''), fraction = m[2] ?? '';
  if ((whole.isEmpty && fraction.isEmpty) || fraction.length > decimals || whole.length > 15) {
    return null;
  }
  var minor = whole.isEmpty ? 0 : int.parse(whole);
  for (var i = 0; i < decimals; i++) {
    minor *= 10;
  }
  return minor + (fraction.isEmpty ? 0 : int.parse(fraction.padRight(decimals, '0')));
}

/// [minor] as it would be typed: 150050 at 2 decimals is `1500.50`.
String plainAmount(int minor, int decimals) {
  if (decimals == 0) return '$minor';
  final s = '$minor'.padLeft(decimals + 1, '0');
  return '${s.substring(0, s.length - decimals)}.${s.substring(s.length - decimals)}';
}

/// [minor] as its currency writes it: 150050 NGN is ₦1,500.50.
String formatMinor(int minor, String currency, int decimals) =>
    NumberFormat.simpleCurrency(locale: 'en_US', name: currency, decimalDigits: decimals)
        .format(minor / pow(10, decimals));

String formatSats(int sats) => NumberFormat('#,##0', 'en_US').format(sats);

/// How many passkey approvals, in words: "once", "twice", "3 times".
String approvalTimes(int n) => switch (n) { 1 => 'once', 2 => 'twice', _ => '$n times' };

/// [e] in words the owner can act on.
String plainError(Object e) {
  if (e is PolicyRefused) {
    return "The platform asked for terms the app won't sign: ${e.reason}.";
  }
  if (e is PlatformException) {
    if (e.refused) return 'The payout service turned this down: ${e.message}';
    return e.status == null
        ? 'The payout service could not be reached. Check your connection and try again.'
        : 'The payout service had a problem: ${e.message}. Try again in a moment.';
  }
  if (e is OperationCancelled ||
      (e is services.PlatformException && e.code == PasskeyChannel.cancelled)) {
    return 'The passkey prompt was cancelled.';
  }
  if (e is SocketException || e is TimeoutException) {
    return 'Could not connect. Check your connection and try again.';
  }
  if (e is StateError) return e.message;
  final message = e is GrpcError ? e.message ?? '$e' : '$e';
  if (message.contains('already committed to a deal')) {
    return 'Your last payout still holds your escrow. You can send again once it has finished.';
  }
  return message;
}

int _sum(Iterable<IndexerVtxo> vtxos) =>
    vtxos.where((v) => !v.isSpent).fold<int>(0, (a, v) => a + v.amountSats);

class PayoutService extends ChangeNotifier {
  PayoutService(this._mpc) {
    _mpc.addListener(_onWallet);
    _onWallet();
  }

  final MpcService _mpc;
  Box? _box;

  /// The wallet [_bank] was built over. A reconnect makes a new one.
  MpcClient? _client;
  BankSend? _bank;
  PlatformClient? _platform;
  List<Corridor>? _corridors;

  /// Payouts being followed, and the ones this run is still sealing.
  final Map<String, StreamSubscription<PayoutStatus>> _following = {};
  final Set<String> _sending = {};

  /// Whether this server has a payout platform. MutinyNet has none yet.
  bool get available => server_host.platformBase(_mpc.host) != null;

  /// The box, open. Anything that decides from it awaits this first; until then the getters below
  /// read as empty.
  Future<void> get ready => _open();

  Future<Box> _open() async => _box ??= await Hive.openBox(_boxName);

  void _onWallet() {
    // Reset, or not set up yet: nothing to follow, and nothing of the last wallet's to follow it with.
    if (!_mpc.dkgComplete) {
      _stop();
      return;
    }
    final client = _mpc.client;
    if (client == null || identical(client, _client) || !available) return;
    _need();
    unawaited(_resume());
  }

  /// Follow what was still in flight when the app last stopped — and what failed while its deal
  /// still held the escrow, to hear when the platform ends it.
  Future<void> _resume() async {
    await _open();
    final now = DateTime.now();
    for (final p in payouts) {
      final held = p.failed && (p.holdUntil?.isAfter(now) ?? false);
      if ((!p.finished || held) && !_sending.contains(p.dealTag)) _follow(p.dealTag);
    }
    notifyListeners();
  }

  void _stop() {
    for (final s in _following.values) {
      s.cancel();
    }
    _following.clear();
    _client = null;
    _bank = null;
    _corridors = null;
  }

  PlatformClient _platformClient() {
    final base = server_host.platformBase(_mpc.host);
    if (base == null) throw StateError('Sending money is not available on this server yet.');
    if (_platform?.base != base) _platform = PlatformClient(base);
    return _platform!;
  }

  /// The steps, over the wallet as it is connected now.
  BankSend _need() {
    final client = _mpc.client;
    if (client == null) {
      throw StateError('Your wallet is not connected yet. Try again in a moment.');
    }
    if (!identical(client, _client) || _bank == null) {
      final host = _mpc.host;
      _client = client;
      _bank = BankSend(
        wallet: client,
        platform: _platformClient(),
        platformId: server_host.platformIdentifier,
        gridOrigin: server_host.gridOriginForPolicy(host),
        delivery: server_host.platformDelivery(host),
      );
    }
    return _bank!;
  }

  // --- What is remembered ------------------------------------------------------------------------

  /// Every payout this device remembers, newest first.
  List<Payout> get payouts {
    final box = _box;
    if (box == null) return const [];
    return [
      for (final v in box.values)
        if (v is Map) Payout(v),
    ]..sort((a, b) => b.createdAt.compareTo(a.createdAt));
  }

  Payout? payout(String dealTag) {
    final v = _box?.get(dealTag);
    return v is Map ? Payout(v) : null;
  }

  /// The escrow payouts are paid from, once one is set up.
  String? get escrowKey => _box?.get(_escrowKeyKey) as String?;

  /// Whether that escrow is set up, and this wallet still holds it.
  bool get hasEscrow {
    final key = escrowKey?.toLowerCase();
    return key != null &&
        (_mpc.client?.escrows.any((e) => e.escrowKeyHex.toLowerCase() == key) ?? false);
  }

  /// Who was paid lately, newest first and once each — the ones the money reached.
  List<Payout> get recipients {
    final seen = <(String, String, String, String)>{};
    return [
      for (final p in payouts)
        if (p.paidOut && seen.add((p.country, p.rail, p.fullName, p.destination))) p,
    ].take(5).toList();
  }

  /// Payouts still to be dealt with: in flight, or failed with their escrow still this wallet's
  /// and nothing paid from it since — whatever it holds may be theirs to take back.
  List<Payout> get pending {
    final all = payouts;
    return [
      for (final (i, p) in all.indexed)
        if (!p.finished ||
            (p.failed &&
                p.leftoverSats == null &&
                p.escrowKey == escrowKey &&
                !all.take(i).any((q) => q.escrowKey == p.escrowKey)))
          p,
    ];
  }

  /// The payout whose deal still holds the escrow, if one does. Another can't be sealed over it
  /// until that one is repaid or its deadline passes: the cosigner would refuse.
  Payout? get holding {
    final key = escrowKey, now = DateTime.now();
    for (final p in payouts) {
      final until = p.holdUntil;
      if (p.escrowKey == key && p.state != 'repaid' && until != null && until.isAfter(now)) {
        return p;
      }
    }
    return null;
  }

  // --- The platform ------------------------------------------------------------------------------

  /// Where the platform pays out. Kept once fetched.
  Future<List<Corridor>> corridors({bool refresh = false}) async {
    if (refresh || _corridors == null) _corridors = await _platformClient().corridors();
    return _corridors!;
  }

  Future<List<String>> banks(String country) => _platformClient().banks(country);

  /// Mint the escrow payouts are paid from, and pair the platform into it. One approval, once.
  Future<void> setUp() async {
    await _open();
    final key = await _need().ensureEscrow(known: escrowKey);
    await _box!.put(_escrowKeyKey, key);
    notifyListeners();
  }

  /// The platform's price for [d], and the policy it asks to have sealed. Commits nothing.
  Future<PayoutQuote> quote(PayoutDraft d) async {
    final key = escrowKey;
    if (key == null) throw StateError('Set up sending first.');
    return _need().quote(
      escrowKeyHex: key,
      country: d.corridor.country,
      rail: d.rail.kind,
      fields: d.fields,
      fullName: d.fullName,
      amountMinor: d.amountMinor,
    );
  }

  /// What the escrow holds, and what has to be sent to it from the balance for it to hold [q]'s
  /// price.
  Future<({int held, int topUp})> funding(PayoutQuote q) async {
    final bank = _need();
    final held = await bank.held(escrowKey!);
    final info = await bank.wallet.getArkInfo();
    return (held: _sum(held), topUp: BankSend.shortfall(q.sats, held, dust: info.dust));
  }

  Future<int> heldSats(String escrowKeyHex) async => _sum(await _need().held(escrowKeyHex));

  // --- Sending -----------------------------------------------------------------------------------

  /// Go ahead with [q]: remember it, then seal it and have the platform pay, in the background.
  /// Returns its deal tag at once; [payout] says how it is going.
  ///
  /// [topUp] is what the quote screen worked out the escrow is short by.
  Future<String> start(PayoutDraft d, PayoutQuote q,
      {required bool setUp, required int topUp}) async {
    final box = await _open();
    final now = DateTime.now().millisecondsSinceEpoch;
    await box.put(q.dealTag, <String, dynamic>{
      'deal_tag': q.dealTag,
      'request_id': q.requestId,
      'country': d.corridor.country,
      'rail': d.rail.kind,
      'fields': d.fields,
      'full_name': d.fullName,
      'name_at_bank': q.nameAtBank,
      'amount_minor': q.amountMinor,
      'currency': q.currency,
      'decimals': d.corridor.decimals,
      'sats': q.sats,
      'escrow_key': escrowKey,
      'set_up': setUp,
      'top_up_sats': topUp,
      'state': 'committing',
      'step': 'policy',
      // Until the seal says exactly when: the deal it is about to seal lasts this long.
      'hold_until': now + q.dealSeconds * 1000,
      'created_at': now,
      'updated_at': now,
    });
    notifyListeners();
    unawaited(_send(q, d.fields));
    return q.dealTag;
  }

  Future<void> _send(PayoutQuote q, Map<String, String> fields) async {
    final tag = q.dealTag;
    _sending.add(tag);
    try {
      final BankSend bank;
      final Commitment sealed;
      try {
        bank = _need();
        sealed = await bank.commit(
          q,
          escrowKeyHex: payout(tag)!.escrowKey,
          fields: fields,
          onStep: (step) => unawaited(_update(
              tag,
              (p) => p['step'] = switch (step) {
                    CommitStep.policy => 'policy',
                    CommitStep.seal => 'seal',
                  })),
        );
      } catch (e) {
        // Not sealed, so no deal holds the escrow. What a top-up sent stays in it, and counts toward
        // the next send.
        await _update(tag, (p) {
          p['state'] = 'failed';
          p['failure'] = plainError(e);
          p.remove('hold_until');
          if (e is PolicyRefused) p['step'] = 'policy';
        });
        return;
      }
      unawaited(_mpc.refreshVtxos());
      await _update(tag, (p) {
        p['state'] = 'funding';
        p['step'] = 'fund';
        p['top_up_sats'] = sealed.topUpSats;
        p['hold_until'] = sealed.deadline.millisecondsSinceEpoch;
      });

      try {
        await bank.fund(q);
        await _update(tag, (p) => p['step'] = 'pay');
      } on PlatformException catch (e) {
        if (e.refused) {
          // Not paid. Still followed: the platform ends the deal once it gives the payout up,
          // and that frees the escrow — and a refusal can be "funded already".
          await _update(
              tag,
              (p) => p
                ..['state'] = 'failed'
                ..['failure'] = plainError(e));
        } else {
          await _unclear(tag, e);
        }
      } catch (e) {
        await _unclear(tag, e);
      }
      _follow(tag);
    } finally {
      _sending.remove(tag);
    }
  }

  /// It may have paid all the same: the platform's own word, followed from here, decides.
  Future<void> _unclear(String tag, Object e) => _update(tag,
      (p) => p['note'] = 'No clear answer from the payout service (${plainError(e)}). Checking…');

  void _follow(String tag) {
    if (_following.containsKey(tag)) return;
    final BankSend bank;
    try {
      bank = _need();
    } catch (_) {
      return; // No wallet yet: followed once one opens — see _onWallet.
    }
    _following[tag] = bank.follow(tag).listen(
          (status) => _update(tag, (p) => _apply(p, status)),
          onError: (Object e) {
            _following.remove(tag);
            if (e is PlatformException && e.refused) {
              // The platform does not know it, or will not say: there is nothing left to follow.
              _update(
                  tag,
                  (p) => p
                    ..['state'] = 'failed'
                    ..['failure'] = plainError(e));
              return;
            }
            debugPrint('Following payout $tag: $e');
            // ponytail: a fixed pause between attempts; back off if the platform minds being asked.
            Timer(const Duration(seconds: 15), () {
              if (payout(tag)?.finished == false) _follow(tag);
            });
          },
          onDone: () => _following.remove(tag),
          cancelOnError: true,
        );
  }

  static void _apply(Map<String, dynamic> p, PayoutStatus s) {
    // Given up, and the deal ended: the escrow is the owner's again.
    if (s.dealEnded) p.remove('hold_until');
    // A refusal seen here stands until the platform shows the payout moving after all.
    if (p['state'] == 'failed' && (s.state == 'quoted' || s.state == 'funding')) return;
    p['state'] = s.state;
    p['failure'] = s.failure ?? (s.state == 'failed' ? p['failure'] : null);
    if (s.gridStatus != null) p['grid_status'] = s.gridStatus;
    if (s.arkTxid != null) p['ark_txid'] = s.arkTxid;
    p['step'] = switch (s.state) {
      'quoted' || 'funding' => 'fund',
      'paying' => 'pay',
      'paid_out' || 'repaying' => 'repay',
      'repaid' => 'done',
      _ => p['step'], // Failed: it stays where it stopped.
    };
    if (p['step'] != 'fund') p.remove('note');
  }

  Future<void> _update(String tag, void Function(Map<String, dynamic> p) change) async {
    final box = _box, stored = box?.get(tag);
    if (box == null || stored is! Map) return; // Forgotten: the wallet was reset.
    final p = Map<String, dynamic>.from(stored);
    change(p);
    p['updated_at'] = DateTime.now().millisecondsSinceEpoch;
    await box.put(tag, p);
    notifyListeners();
  }

  /// Take back what [p]'s escrow still holds, into the wallet. One approval, refused while a deal
  /// holds the escrow — and it retires the escrow for good, so the next send sets up a new one.
  Future<int> returnLeftover(Payout p) async {
    final bank = _need();
    final held = (await bank.held(p.escrowKey)).where((v) => !v.isSpent).toList();
    var back = 0;
    if (held.isNotEmpty) {
      back = (await bank.wallet.reclaimEscrow(escrowKeyHex: p.escrowKey, vtxos: held)).amountSats;
      if (escrowKey == p.escrowKey) await _box!.delete(_escrowKeyKey);
      unawaited(_mpc.refreshVtxos());
    }
    await _update(p.dealTag, (json) => json['leftover_sats'] = back);
    return back;
  }

  @override
  void dispose() {
    _mpc.removeListener(_onWallet);
    _stop();
    super.dispose();
  }
}
