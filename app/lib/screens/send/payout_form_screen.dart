import 'package:app_core/platform/platform_client.dart' show Corridor, Rail, RailField;
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../../services/payout_service.dart';
import 'send_widgets.dart';

/// Where the form sends to, and whom to fill in.
class PayoutFormArgs {
  const PayoutFormArgs(this.corridor, this.rail, {this.prefill});
  final Corridor corridor;
  final Rail rail;
  final Payout? prefill;
}

/// What [typed] sends for [f]. A number loses its spaces and dashes and gains [RailField.prefix]
/// — typed or not, and in place of a local number's leading 0. Anything else, a bank's name say,
/// is sent as it was picked.
String fieldValue(RailField f, String typed) {
  final prefix = f.prefix ?? '';
  if (prefix.isEmpty && f.minDigits == null && f.maxDigits == null) return typed.trim();
  var v = typed.replaceAll(RegExp(r'[\s\-()]'), '');
  if (prefix.isEmpty) return v;
  if (v.startsWith(prefix)) {
    v = v.substring(prefix.length);
  } else if (v.startsWith('0')) {
    v = v.substring(1);
  }
  return '$prefix$v';
}

/// Why [value], as [fieldValue] made it, won't do for [f] — or null. The platform checks again;
/// this is to say so before a quote is asked for.
String? fieldError(RailField f, String value) {
  final prefix = f.prefix ?? '';
  final rest = value.startsWith(prefix) ? value.substring(prefix.length) : value;
  if (rest.isEmpty) return 'Required';
  final min = f.minDigits, max = f.maxDigits;
  if (min == null && max == null) return null;
  final after = prefix.isEmpty ? '' : ' after $prefix';
  if (!RegExp(r'^\d+$').hasMatch(rest)) return 'Digits only$after';
  if ((min != null && rest.length < min) || (max != null && rest.length > max)) {
    final want = min == max
        ? '$min digits'
        : min == null
            ? 'up to $max digits'
            : max == null
                ? 'at least $min digits'
                : '$min to $max digits';
    return 'Must be $want$after';
  }
  return null;
}

/// Why [text] won't do as an amount on [rail], or null.
String? amountError(String text, Corridor corridor, Rail rail) {
  final minor = toMinor(text, corridor.decimals);
  String money(int m) => formatMinor(m, corridor.currency, corridor.decimals);
  if (minor == null || minor == 0) {
    return 'Enter an amount, like ${plainAmount(rail.minMinor, corridor.decimals)}';
  }
  if (minor < rail.minMinor) return 'At least ${money(rail.minMinor)}';
  if (minor > rail.maxMinor) return 'At most ${money(rail.maxMinor)}';
  return null;
}

/// Grid's limit on a beneficiary's name.
String? nameError(String text) {
  final name = text.trim();
  if (name.isEmpty) return 'Required';
  if (name.length > 250) return 'At most 250 characters';
  return null;
}

/// Open the form for [p]'s recipient, filled in as [p] was. The corridor is looked up again: what
/// a rail asks for is the platform's to say, and may have changed.
Future<void> openPayoutForm(BuildContext context, Payout p, {bool replace = false}) async {
  final messenger = ScaffoldMessenger.of(context);
  try {
    final corridors = await context.read<PayoutService>().corridors();
    final corridor = corridors.where((c) => c.country == p.country).firstOrNull;
    final rail = corridor?.rails.where((r) => r.kind == p.rail).firstOrNull;
    if (!context.mounted) return;
    if (corridor == null || rail == null) {
      messenger
          .showSnackBar(const SnackBar(content: Text('The platform no longer pays out there.')));
      return;
    }
    final args = PayoutFormArgs(corridor, rail, prefill: p);
    if (replace) {
      context.pushReplacement('/send/payout', extra: args);
    } else {
      context.push('/send/payout', extra: args);
    }
  } catch (e) {
    messenger.showSnackBar(SnackBar(content: Text(plainError(e))));
  }
}

/// Whom to pay, on one rail of one country, and how much. The fields are the rail's own, as the
/// platform describes them.
class PayoutFormScreen extends StatefulWidget {
  const PayoutFormScreen({super.key, required this.args});
  final PayoutFormArgs args;

  @override
  State<PayoutFormScreen> createState() => _PayoutFormScreenState();
}

class _PayoutFormScreenState extends State<PayoutFormScreen> {
  final _form = GlobalKey<FormState>();

  /// Typed fields and bank-list fields, by key. Fields with options are in [_chosen].
  final Map<String, TextEditingController> _text = {};
  final Map<String, String?> _chosen = {};
  late final TextEditingController _name;
  late final TextEditingController _amount;

  Corridor get _corridor => widget.args.corridor;
  Rail get _rail => widget.args.rail;

  @override
  void initState() {
    super.initState();
    final prefill = widget.args.prefill;
    for (final f in _rail.fields) {
      final was = prefill?.fields[f.key];
      if (f.options.isNotEmpty) {
        _chosen[f.key] = f.options.contains(was)
            ? was
            : f.options.length == 1
                ? f.options.single
                : null;
      } else {
        final prefix = f.prefix ?? '';
        final typed = was != null && prefix.isNotEmpty && was.startsWith(prefix)
            ? was.substring(prefix.length)
            : was;
        _text[f.key] = TextEditingController(text: typed ?? '');
      }
    }
    _name = TextEditingController(text: prefill?.fullName ?? '');
    _amount = TextEditingController(
        text: prefill == null ? '' : plainAmount(prefill.amountMinor, _corridor.decimals));
  }

  @override
  void dispose() {
    for (final c in _text.values) {
      c.dispose();
    }
    _name.dispose();
    _amount.dispose();
    super.dispose();
  }

  Future<void> _continue() async {
    if (!_form.currentState!.validate()) return;
    final draft = PayoutDraft(
      corridor: _corridor,
      rail: _rail,
      fields: {
        for (final f in _rail.fields)
          f.key: f.options.isNotEmpty ? _chosen[f.key]! : fieldValue(f, _text[f.key]!.text),
      },
      fullName: _name.text.trim(),
      amountMinor: toMinor(_amount.text, _corridor.decimals)!,
    );
    // The quote screen hands back the payout's tag once it has been sent on its way.
    final tag = await context.push<String>('/send/payout/quote', extra: draft);
    if (tag != null && mounted) context.pushReplacement('/send/payout/progress', extra: tag);
  }

  Future<void> _pickBank(RailField f) async {
    final picked = await showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1E1E1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => _BankPicker(
        title: f.label,
        load: () => context.read<PayoutService>().banks(_corridor.country),
      ),
    );
    if (picked != null) _text[f.key]!.text = picked;
  }

  @override
  Widget build(BuildContext context) {
    final payouts = context.watch<PayoutService>();
    final holding = payouts.holding;
    String money(int m) => formatMinor(m, _corridor.currency, _corridor.decimals);

    return Scaffold(
      appBar: AppBar(
        title: Text(
          '${flag(_corridor.country)}  ${_corridor.name}',
          style: GoogleFonts.inter(fontWeight: FontWeight.w600),
        ),
        centerTitle: true,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Form(
            key: _form,
            autovalidateMode: AutovalidateMode.onUserInteraction,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Expanded(
                  // A Column, not a ListView: Form.validate() checks only fields that are built.
                  child: SingleChildScrollView(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Text(
                          _rail.label,
                          style: GoogleFonts.inter(
                              fontSize: 18, fontWeight: FontWeight.bold, color: Colors.white),
                        ),
                        const SizedBox(height: 16),
                        for (final f in _rail.fields) ...[
                          _field(f),
                          const SizedBox(height: 16),
                        ],
                        TextFormField(
                          key: const Key('payoutNameField'),
                          controller: _name,
                          textCapitalization: TextCapitalization.words,
                          decoration: const InputDecoration(
                            labelText: "Recipient's full name",
                            helperText: 'As their bank or network has it',
                          ),
                          validator: (t) => nameError(t ?? ''),
                          style: GoogleFonts.inter(),
                        ),
                        const SizedBox(height: 16),
                        TextFormField(
                          key: const Key('payoutAmountField'),
                          controller: _amount,
                          keyboardType:
                              TextInputType.numberWithOptions(decimal: _corridor.decimals > 0),
                          decoration: InputDecoration(
                            labelText: 'Amount',
                            suffixText: _corridor.currency,
                            helperText: 'From ${money(_rail.minMinor)} to ${money(_rail.maxMinor)}',
                          ),
                          validator: (t) => amountError(t ?? '', _corridor, _rail),
                          style: GoogleFonts.inter(fontSize: 24),
                        ),
                        if (holding != null) ...[
                          const SizedBox(height: 16),
                          SendNotice(
                            icon: Icons.hourglass_top,
                            color: Colors.amberAccent,
                            text: 'Your payout to ${holding.fullName} is still going through. '
                                'You can send again once it has finished.',
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                ElevatedButton(
                  key: const Key('payoutContinueBtn'),
                  onPressed: holding == null ? _continue : null,
                  child: const Text('Continue'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _field(RailField f) {
    if (f.options.isNotEmpty) {
      return DropdownButtonFormField<String>(
        initialValue: _chosen[f.key],
        decoration: InputDecoration(labelText: f.label),
        dropdownColor: const Color(0xFF1E1E1E),
        items: [for (final o in f.options) DropdownMenuItem(value: o, child: Text(o))],
        onChanged: (v) => setState(() => _chosen[f.key] = v),
        validator: (v) => v == null ? 'Choose one' : null,
      );
    }
    if (f.fromBankList) {
      return TextFormField(
        controller: _text[f.key],
        readOnly: true,
        decoration: InputDecoration(labelText: f.label, suffixIcon: const Icon(Icons.search)),
        onTap: () => _pickBank(f),
        validator: (t) => (t ?? '').isEmpty ? 'Choose one' : null,
        style: GoogleFonts.inter(),
      );
    }
    final prefix = f.prefix;
    final digits = f.minDigits != null || f.maxDigits != null;
    return TextFormField(
      controller: _text[f.key],
      keyboardType: prefix != null
          ? TextInputType.phone
          : digits
              ? TextInputType.number
              : TextInputType.text,
      decoration: InputDecoration(
        labelText: f.label,
        prefixText: prefix == null ? null : '$prefix ',
      ),
      validator: (t) => fieldError(f, fieldValue(f, t ?? '')),
      style: GoogleFonts.inter(),
    );
  }
}

/// A country's banks, searched by name.
class _BankPicker extends StatefulWidget {
  const _BankPicker({required this.title, required this.load});
  final String title;
  final Future<List<String>> Function() load;

  @override
  State<_BankPicker> createState() => _BankPickerState();
}

class _BankPickerState extends State<_BankPicker> {
  late Future<List<String>> _banks = widget.load();
  String _query = '';

  @override
  Widget build(BuildContext context) {
    final media = MediaQuery.of(context);
    return Padding(
      padding: EdgeInsets.fromLTRB(24, 20, 24, 24 + media.viewInsets.bottom),
      child: SizedBox(
        height: media.size.height * 0.7,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              widget.title,
              style:
                  GoogleFonts.inter(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white),
            ),
            const SizedBox(height: 12),
            TextField(
              autofocus: true,
              decoration: const InputDecoration(
                hintText: 'Search',
                prefixIcon: Icon(Icons.search),
              ),
              onChanged: (q) => setState(() => _query = q.trim().toLowerCase()),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: FutureBuilder<List<String>>(
                future: _banks,
                builder: (context, snap) {
                  if (snap.hasError) {
                    return Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          plainError(snap.error!),
                          textAlign: TextAlign.center,
                          style: GoogleFonts.inter(color: Colors.white54),
                        ),
                        TextButton(
                          onPressed: () => setState(() => _banks = widget.load()),
                          child: const Text('Try again'),
                        ),
                      ],
                    );
                  }
                  final banks = snap.data;
                  if (banks == null) {
                    return const Center(child: CircularProgressIndicator(color: Colors.white));
                  }
                  final shown = [
                    for (final b in banks)
                      if (b.toLowerCase().contains(_query)) b,
                  ];
                  if (shown.isEmpty) {
                    return Center(
                      child:
                          Text('Nothing matches', style: GoogleFonts.inter(color: Colors.white38)),
                    );
                  }
                  return ListView.builder(
                    itemCount: shown.length,
                    itemBuilder: (context, i) => ListTile(
                      title: Text(shown[i], style: GoogleFonts.inter(color: Colors.white)),
                      onTap: () => Navigator.of(context).pop(shown[i]),
                    ),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}
