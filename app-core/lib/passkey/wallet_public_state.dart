/// Everything this device keeps about the wallet's key. All of it is public.
///
/// The share used to sit here too — blinded, but here. It does not any more: a share is rebuilt
/// for one operation from the passkey's PRF and the half the cosigner dealt, and forgotten when the
/// operation ends (`operation_secrets.dart`). What is left is what a rebuilt share is *checked
/// against*, which has to come from somewhere the cosigner cannot rewrite on the day it is asked:
/// the identifier, the verifying share and the group key, as the ceremony produced them.
///
/// None of it helps anybody sign. The verifying share and the group key are points; the identifier
/// is a hash of one. They are on the wire in every ceremony and inside every key package.
library;

import 'dart:typed_data';

import 'package:convert/convert.dart';

import 'package:app_core/threshold/threshold.dart' as threshold;

class WalletPublicState {
  WalletPublicState({
    required this.identifier,
    required this.verifyingShare,
    required this.minSigners,
    required this.publicKeyPackage,
  });

  /// From the ceremony's public key package and this wallet's place in it. Throws
  /// [ArgumentError] if [identifier] is not a member — a wallet cannot be described by a ceremony
  /// it took no part in.
  factory WalletPublicState.fromPublicKeyPackage(
    threshold.PublicKeyPackage publicKeyPackage,
    threshold.Identifier identifier, {
    required int minSigners,
  }) {
    final verifyingShare = publicKeyPackage.verifyingShares[identifier];
    if (verifyingShare == null) {
      throw ArgumentError('the identifier is not a member of this key package');
    }
    return WalletPublicState(
      identifier: identifier,
      verifyingShare: verifyingShare.toLowerCase(),
      minSigners: minSigners,
      publicKeyPackage: publicKeyPackage,
    );
  }

  /// The wallet's FROST identifier: `Identifier.derive(compressed(a0·G))`.
  final threshold.Identifier identifier;

  /// `share·G`, compressed hex, lowercase. What a rebuilt share must multiply out to.
  final String verifyingShare;

  final int minSigners;

  /// The group key and every member's verifying share.
  final threshold.PublicKeyPackage publicKeyPackage;

  /// The group verifying key, compressed hex, lowercase — the wallet's public identity.
  String get groupKeyHex => publicKeyPackage.verifyingKey.E.toLowerCase();

  factory WalletPublicState.fromJson(Map<String, dynamic> json) {
    final package = threshold.PublicKeyPackage.fromJson(
        Map<String, dynamic>.from(json['publicKeyPackage'] as Map));
    final identifier = threshold.Identifier.deserialize(
        Uint8List.fromList(hex.decode(json['identifier'] as String)));
    final state = WalletPublicState.fromPublicKeyPackage(
      package,
      identifier,
      minSigners: json['minSigners'] as int,
    );
    // Stored beside the package that also contains it, so a box edited in one place and not the
    // other is caught here instead of as a share that will not verify.
    final stored = (json['verifyingShare'] as String).toLowerCase();
    if (stored != state.verifyingShare) {
      throw const FormatException(
          'the stored verifying share is not the one in the stored key package');
    }
    return state;
  }

  Map<String, dynamic> toJson() => {
        'identifier': hex.encode(identifier.serialize()),
        'verifyingShare': verifyingShare,
        'minSigners': minSigners,
        'publicKeyPackage': publicKeyPackage.toJson(),
      };
}
