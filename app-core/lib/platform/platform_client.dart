/// A payout platform's API, as a wallet calls it: which countries it pays into and how, a quote for
/// one payout, the go-ahead to fund it, and how it is going.
///
/// Nothing the platform says here is trusted with money. Its quote carries the policy the escrow
/// will be committed to, and that is checked by [checkPayoutPolicy] before anything is sealed; the
/// cosigner then fetches the payout's proof from Grid itself. What this client gets wrong can cost
/// a failed send, never a release the owner did not agree to.
library;

import 'dart:convert';

import 'package:http/http.dart' as http;

/// One country the platform pays into, and the ways it can.
class Corridor {
  Corridor(this.json);
  final Map<String, dynamic> json;

  String get country => json['country'] as String;
  String get name => json['name'] as String? ?? country;
  String get currency => json['currency'] as String;
  int get decimals => json['decimals'] as int? ?? 2;
  List<Rail> get rails => [
        for (final r in (json['rails'] as List? ?? const []).cast<Map<String, dynamic>>())
          Rail(r),
      ];
}

/// One way of paying into a country: a bank account, or a mobile-money wallet.
class Rail {
  Rail(this.json);
  final Map<String, dynamic> json;

  /// `bank` or `mobile_money`.
  String get kind => json['rail'] as String? ?? json['kind'] as String;
  String get label => json['label'] as String? ?? (kind == 'bank' ? 'Bank account' : 'Mobile money');
  int get minMinor => json['min_minor'] as int? ?? 1;
  int get maxMinor => json['max_minor'] as int? ?? 1 << 53;
  List<RailField> get fields => [
        for (final f in (json['fields'] as List? ?? const []).cast<Map<String, dynamic>>())
          RailField(f),
      ];
}

/// One thing the sender has to fill in, by the name Grid gives it.
class RailField {
  RailField(this.json);
  final Map<String, dynamic> json;

  /// Grid's name for it: `accountNumber`, `bankName`, `phoneNumber`, `provider`.
  String get key => json['key'] as String;
  String get label => json['label'] as String? ?? key;

  /// Choices, when there is a fixed set — a mobile-money operator, say.
  List<String> get options => (json['options'] as List? ?? const []).cast<String>();

  /// The choices are the country's bank list, fetched with [PlatformClient.banks].
  bool get fromBankList => json['from_bank_list'] as bool? ?? false;

  /// A digits-only field's allowed lengths, when there are rules to pre-check.
  int? get minDigits => (json['digits'] as Map<String, dynamic>?)?['min'] as int?;
  int? get maxDigits => (json['digits'] as Map<String, dynamic>?)?['max'] as int?;

  /// A phone number's required prefix, e.g. `+254`.
  String? get prefix => json['prefix'] as String?;
}

/// What the platform will do for one payout, and what it asks for it.
class PayoutQuote {
  PayoutQuote(this.json);
  final Map<String, dynamic> json;

  String get requestId => json['request_id'] as String;
  String get dealTag => json['deal_tag'] as String;
  String get accountId => json['external_account_id'] as String;
  String get currency => json['currency'] as String;
  int get amountMinor => json['amount_minor'] as int;

  /// The agreed price, in sats — what the escrow will release to the platform, and no more.
  int get sats => json['sats'] as int;
  DateTime get expiresAt => DateTime.parse(json['expires_at'] as String);

  /// How long the platform needs the deal to run.
  int get dealSeconds => json['deal_seconds'] as int? ?? 1800;
  Map<String, dynamic> get policy => json['policy'] as Map<String, dynamic>;
  Map<String, dynamic> get payee => json['payee'] as Map<String, dynamic>? ?? const {};

  /// The name the bank or operator holds for the account, when the corridor checks one.
  String? get nameAtBank => payee['name_at_bank'] as String?;

  /// `MATCHED`, `PARTIAL_MATCH`, … — or null where there is no name check.
  String? get nameCheck => payee['name_check'] as String?;
}

/// Where a payout has got to, as the platform tells it.
class PayoutStatus {
  PayoutStatus(this.json);
  final Map<String, dynamic> json;

  /// `quoted`, `funding`, `paying`, `paid_out`, `repaying`, `repaid` or `failed`.
  String get state => json['state'] as String;
  String? get gridStatus => json['grid_status'] as String?;
  String? get failure => json['failure'] as String?;
  String? get arkTxid => json['ark_txid'] as String?;
  bool get dealEnded => json['deal_ended'] as bool? ?? false;
  bool get finished => state == 'repaid' || state == 'failed';
}

/// The platform refused, or could not be reached.
class PlatformException implements Exception {
  PlatformException(this.message, {this.status});
  final String message;
  final int? status;

  /// A refusal the sender can act on — a bad account number, a payee the bank does not know —
  /// rather than a platform that is down.
  bool get refused => status != null && status! >= 400 && status! < 500;

  @override
  String toString() => message;
}

class PlatformClient {
  PlatformClient(this.base, {http.Client? client}) : _http = client ?? http.Client();

  /// `http://127.0.0.1:7200` on a dev stack.
  final Uri base;
  final http.Client _http;

  Future<List<Corridor>> corridors() async {
    final body = await _get('/corridors');
    final list = body is Map ? body['countries'] as List : body as List;
    return [for (final c in list.cast<Map<String, dynamic>>()) Corridor(c)];
  }

  /// The banks a country's bank rail pays into, spelled exactly as Grid names them — which is what
  /// a policy pins, so it is what the sender chooses from.
  Future<List<String>> banks(String country) async {
    final body = await _get('/corridors/$country/banks');
    final list = body is Map ? body['banks'] as List : body as List;
    return [for (final b in list) b is Map ? b['bank_name'] as String : b as String];
  }

  Future<PayoutQuote> quote({
    required String escrowKeyHex,
    required String country,
    required String rail,
    required Map<String, String> fields,
    required String fullName,
    required int amountMinor,
    required String dealTag,
  }) async =>
      PayoutQuote(await _post('/payouts', {
        'escrow_key': escrowKeyHex,
        'country': country,
        'rail': rail,
        'fields': fields,
        'full_name': fullName,
        'amount_minor': amountMinor,
        'deal_tag': dealTag,
      }) as Map<String, dynamic>);

  /// The go-ahead: the escrow is committed, so the platform may pay. It checks that for itself —
  /// asking the cosigner before it spends anything — so this is a request, not a promise.
  Future<void> fund(String requestId) =>
      _send(() => _http.post(base.resolve('/payouts/$requestId/fund')), 'POST /fund');

  Future<PayoutStatus> status(String dealTag) async =>
      PayoutStatus(await _get('/payouts/$dealTag') as Map<String, dynamic>);

  Future<Object?> _get(String path) =>
      _send(() => _http.get(base.resolve(path)), 'GET $path');

  Future<Object?> _post(String path, Object body) => _send(
      () => _http.post(base.resolve(path),
          headers: const {'content-type': 'application/json'}, body: jsonEncode(body)),
      'POST $path');

  Future<Object?> _send(Future<http.Response> Function() call, String what) async {
    final http.Response response;
    try {
      response = await call().timeout(const Duration(seconds: 60));
    } catch (e) {
      throw PlatformException('the platform could not be reached ($what): $e');
    }
    final text = response.body;
    final decoded = text.isEmpty ? null : jsonDecode(text);
    if (response.statusCode >= 200 && response.statusCode < 300) return decoded;
    final message = decoded is Map && decoded['error'] != null ? decoded['error'] : text;
    throw PlatformException('$message', status: response.statusCode);
  }
}
