/// What a device keeps about an escrow key: all of it public.
///
/// The same rule as the wallet's own key — nothing secret is stored, so what is kept is what a
/// rebuilt share is *checked against*. An escrow share is rebuilt per operation from the passkey's
/// delta and one scalar the cosigner sealed, and checked against the verifying share here.
///
/// The derivation context is kept too, and it is the one field that is not merely a checkable: it
/// is what the passkey's delta was derived under, so without it a new device could not reproduce
/// that delta at all. It is not a secret — the cosigner holds it, and it is meaningless without
/// the PRF — but it is load-bearing, and a device that lost it would have an escrow it could see
/// and not spend from. `Recover` hands it back with the rest — see [MpcClient.recover] and
/// [EscrowPublicState.fromSummary].
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:protocol/cosigner_v1.dart' as cs;

import 'package:app_core/passkey/wallet_public_state.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;

class EscrowPublicState {
  const EscrowPublicState({
    required this.escrowKeyHex,
    required this.wallet,
    required this.contextHex,
  });

  /// `V'`, compressed hex. The escrow's identity, and the owner key of the Ark address it holds.
  final String escrowKeyHex;

  /// This wallet's place in the escrow: its identifier, its verifying share, and the package both
  /// are checked against. The same shape the wallet's own key is described by, because an escrow is
  /// the same kind of thing — a 2-of-2 this wallet is half of.
  final WalletPublicState wallet;

  /// The context the passkey's delta was derived under, hex. See the library note.
  final String contextHex;

  Map<String, dynamic> toJson() => {
        'escrowKey': escrowKeyHex,
        'wallet': wallet.toJson(),
        'context': contextHex,
      };

  /// What a new device keeps of an escrow the cosigner lists — on `Recover`, or `EscrowList`.
  ///
  /// Null for an escrow this device cannot rebuild: one minted before its context was recorded,
  /// whose delta no passkey can re-derive. Throws if the summary is not about [walletIdentifier]
  /// — the wallet this device just recovered — since an escrow it is not a member of is not its.
  static EscrowPublicState? fromSummary(
    cs.EscrowSummary summary, {
    required threshold.Identifier walletIdentifier,
    required int minSigners,
  }) {
    if (summary.context.isEmpty) return null;
    final listed = threshold.Identifier.deserialize(
        Uint8List.fromList(summary.walletIdentifier));
    if (listed != walletIdentifier) {
      throw StateError(
          'the cosigner listed escrow ${summary.escrowKey} under another wallet identifier');
    }
    final package = threshold.PublicKeyPackage.fromJson(
        jsonDecode(summary.publicKeyPackageJson) as Map<String, dynamic>);
    return EscrowPublicState(
      escrowKeyHex: summary.escrowKey.toLowerCase(),
      wallet: WalletPublicState.fromPublicKeyPackage(package, walletIdentifier,
          minSigners: minSigners),
      contextHex: hex.encode(summary.context),
    );
  }

  factory EscrowPublicState.fromJson(Map<String, dynamic> json) => EscrowPublicState(
        escrowKeyHex: json['escrowKey'] as String,
        wallet: WalletPublicState.fromJson(
          Map<String, dynamic>.from(json['wallet'] as Map),
        ),
        contextHex: json['context'] as String,
      );

  @override
  String toString() => 'EscrowPublicState(${escrowKeyHex.substring(0, 16)}…)';
}
