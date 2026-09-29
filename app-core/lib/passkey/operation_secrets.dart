/// The wallet's secrets, for as long as one operation needs them and no longer.
///
/// Nothing secret is stored on this device (`wallet_public_state.dart`), so an operation that signs
/// has to make its secrets and then let them go. A [WalletOperation] is that lifetime, made
/// explicit: it begins with the passkey's PRF output, turns it into the wallet's polynomial, turns
/// that and the cosigner's contribution into a key package when the stream's first round brings
/// one, and is disposed in a `finally` whether the operation succeeded, failed or was cancelled.
///
/// It replaces a time-based cache. The PRF output used to be kept for two minutes so that the
/// several FROST rounds of one send would not each prompt; what bounded its life was a clock, and
/// anything that ran inside the window could use it. Here the bound is the operation itself: the
/// secrets are reachable from this object and from nothing else, and the object is reachable from
/// one call frame.
///
/// # What "released" means, and what it does not
///
/// The seed is bytes, and is overwritten with zeros the moment the polynomial has been derived
/// from it. Everything after that is a `BigInt` — the coefficients, the share — and Dart offers no
/// way to overwrite one: `dispose` drops the references, and the garbage collector reclaims the
/// memory when it chooses to, without clearing it. The FFI also takes a key package as JSON, so
/// signing makes short-lived string copies of the share that nothing here can reach. **This is
/// reference hygiene, not guaranteed zeroization**, and it is not described as more than that
/// anywhere. What it does guarantee is narrower and checkable: after `dispose` this object can
/// produce no secret, and using it throws.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/passkey/share_reconstruction.dart';
import 'package:app_core/passkey/wallet_public_state.dart';
import 'package:app_core/threshold/threshold.dart' as threshold;

/// Turns the cosigner's contribution into the key package a stream signs with.
///
/// Called by a session driver with the `wallet_dealt_share` of **every** sighashes message it
/// receives. The first call rebuilds the share; the later ones must bring nothing, and return the
/// same package — a settle signs two or three rounds, and they are one reconstruction.
typedef KeyResolver = threshold.KeyPackage Function(List<int> dealtShare);

/// The cosigner broke the one-contribution-per-stream rule. Not a wrong share — a wrong protocol.
class ContributionProtocolException implements Exception {
  ContributionProtocolException(this.message);
  final String message;
  @override
  String toString() => 'cosigner: $message';
}

/// An operation was cancelled — `MpcClient.cancelOperation`. Not a failure of anybody's: the owner
/// left, and what the operation held has been let go.
class OperationCancelled implements Exception {
  const OperationCancelled();
  @override
  String toString() => 'the operation was cancelled';
}

/// The owner's way of stopping an operation that is waiting on somebody else.
///
/// An operation holds the wallet's rebuilt share for as long as it runs, and much of a settle's
/// running is waiting — on the ASP's batch schedule, on its event stream, on the indexer. Closing
/// the cosigner's stream interrupts none of those: a driver parked on an ASP that has gone quiet
/// would keep its share, and its turn, for as long as the silence lasted. So every wait a driver
/// makes on a party other than the cosigner goes through [guard], and cancelling ends it there
/// and then — the driver's frame unwinds, and with it the last reference to the share.
class CancelSignal {
  final Completer<void> _cancelled = Completer<void>();

  bool get isCancelled => _cancelled.isCompleted;

  void cancel() {
    if (!_cancelled.isCompleted) _cancelled.complete();
  }

  /// [work], or [OperationCancelled] the moment this is cancelled — whichever is first.
  ///
  /// The work itself is not stopped, only no longer waited for: whatever it later returns or
  /// throws is dropped. That is the right trade for a wait on a remote party — what matters is
  /// that the waiter lets go.
  Future<T> guard<T>(Future<T> work) {
    if (isCancelled) {
      // Not left to float: an error nobody awaits is an unhandled one.
      work.ignore();
      return Future.error(const OperationCancelled());
    }
    return Future.any([
      work,
      _cancelled.future.then<T>((_) => throw const OperationCancelled()),
    ]);
  }
}

class WalletOperation {
  WalletOperation._(
    this._polynomial,
    this._escrowDelta,
    this._pairingSlope,
    this.identifier,
    this._wallet,
    this._escrow,
    this.cancel,
  );

  /// Begin an operation from the passkey's PRF output.
  ///
  /// **Takes ownership of [seed]**, and overwrites it before returning — on success and on failure.
  /// A caller that needs the bytes afterwards has misunderstood what this is for.
  ///
  /// With [wallet] — every operation but DKG and recovery — the identifier the seed derives is
  /// checked against the wallet's here, so a wrong passkey is refused before a stream is opened
  /// or anything is sent. Throws [WrongPasskey].
  ///
  /// [escrowContext] derives that escrow's delta here as well — for the operation that mints the
  /// escrow, and for the ones that sign with it ([escrowKeyPackage]). It is done now rather than
  /// later because the seed is overwritten before this returns and never read twice: whatever an
  /// operation will need from the passkey, it takes in this one place. [escrow] is what a rebuilt
  /// escrow share is checked against.
  static Future<WalletOperation> begin(
    Uint8List seed, {
    WalletPublicState? wallet,
    WalletPublicState? escrow,
    CancelSignal? cancel,
    Uint8List? escrowContext,
    Uint8List? pairingContext,
  }) async {
    try {
      final polynomial = await walletPolynomial(seed);
      final identifier = identifierOf(polynomial);
      if (wallet != null && identifier != wallet.identifier) throw const WrongPasskey();
      final escrowDelta =
          escrowContext == null ? null : await escrowPolynomial(seed, escrowContext);
      final slope = pairingContext == null ? null : await pairingSlope(seed, pairingContext);
      return WalletOperation._(
        polynomial,
        escrowDelta,
        slope,
        identifier,
        wallet,
        escrow,
        cancel ?? CancelSignal(),
      );
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  /// How this operation is stopped. Every wait it makes on a party other than the cosigner goes
  /// through `cancel.guard` — see [CancelSignal].
  final CancelSignal cancel;

  /// The identifier this passkey deals as. Public; it is what each stream's open names.
  final threshold.Identifier identifier;

  final WalletPublicState? _wallet;
  final WalletPublicState? _escrow;
  WalletPolynomial? _polynomial;
  WalletPolynomial? _escrowDelta;
  BigInt? _pairingSlope;
  threshold.KeyPackage? _keyPackage;
  threshold.KeyPackage? _escrowKeyPackage;
  bool _disposed = false;

  bool get isDisposed => _disposed;

  /// Whether this operation currently holds anything secret. False after [dispose], always.
  bool get holdsSecrets =>
      _polynomial != null ||
      _escrowDelta != null ||
      _pairingSlope != null ||
      _keyPackage != null ||
      _escrowKeyPackage != null;

  /// The key package for this operation — see [KeyResolver].
  ///
  /// The polynomial is dropped as soon as the share exists: it has done its work, and what the
  /// remaining rounds need is the share alone.
  threshold.KeyPackage keyPackage(List<int> dealtShare) {
    _ensureLive();
    final existing = _keyPackage;
    if (existing != null) {
      if (dealtShare.isNotEmpty) {
        throw ContributionProtocolException(
            'sent the wallet\'s dealt share a second time on one stream');
      }
      return existing;
    }
    if (dealtShare.isEmpty) {
      throw ContributionProtocolException(
          'asked for a signature without returning the wallet\'s dealt share. A cosigner from '
          'before shares were rebuilt per operation does this — it needs redeploying.');
    }
    final wallet = _wallet;
    if (wallet == null) {
      throw StateError('this operation was begun without a wallet to rebuild a share for');
    }
    final rebuilt = reconstructWalletShare(
      polynomial: _polynomial!,
      dealtShare: dealtShare,
      wallet: wallet,
    );
    _polynomial = null;
    return _keyPackage = rebuilt;
  }

  /// The key package for one ESCROW, from the two halves the cosigner sends on the first round of
  /// a pairing or a reclaim — see [keyPackage] for the contract, which is the same: rebuilt once,
  /// held for the stream, released with the operation. Both polynomials are dropped as soon as
  /// the share exists.
  ///
  /// Inside the operation rather than in a closure the caller builds, because a closure over the
  /// polynomial and the delta is one [dispose] cannot reach.
  threshold.KeyPackage escrowKeyPackage(List<int> dealtShare, List<int> deltaShare) {
    _ensureLive();
    final existing = _escrowKeyPackage;
    if (existing != null) {
      if (dealtShare.isNotEmpty || deltaShare.isNotEmpty) {
        throw ContributionProtocolException(
            'sent the escrow halves a second time on one stream');
      }
      return existing;
    }
    if (dealtShare.isEmpty || deltaShare.isEmpty) {
      throw ContributionProtocolException(
          'asked for an escrow signature without returning both halves of the share');
    }
    final wallet = _wallet;
    final escrow = _escrow;
    final delta = _escrowDelta;
    if (wallet == null || escrow == null || delta == null) {
      throw StateError('this operation was begun without an escrow to rebuild a share for');
    }
    final rebuilt = reconstructEscrowShare(
      polynomial: _polynomial!,
      escrowDelta: delta,
      dealtShare: dealtShare,
      deltaShare: deltaShare,
      wallet: wallet,
      escrow: escrow,
    );
    _polynomial = null;
    _escrowDelta = null;
    return _escrowKeyPackage = rebuilt;
  }

  /// The escrow share the operation that mints an escrow has just made — held here so it is let go
  /// with the operation, for the pairing that follows on the same stream. Nothing is rebuilt: the
  /// reshare produced it. One per operation.
  threshold.KeyPackage holdEscrowKeyPackage(threshold.KeyPackage minted) {
    _ensureLive();
    if (_escrowKeyPackage != null) {
      throw ContributionProtocolException('two escrow shares on one stream');
    }
    return _escrowKeyPackage = minted;
  }

  /// The slope this operation deals a service pairing on. Derived under the escrow's context and
  /// the attempt id, so retrying one attempt's delivery reproduces the same contribution.
  BigInt takePairingSlope() {
    _ensureLive();
    final slope = _pairingSlope;
    if (slope == null) {
      throw StateError('this operation was not begun with a pairing context');
    }
    _pairingSlope = null;
    return slope;
  }

  /// The escrow delta this operation was begun with, for the one operation that DEALS it — minting
  /// an escrow key. The operation keeps no copy. An operation that signs with an escrow does not
  /// take it; it rebuilds through [escrowKeyPackage] instead.
  WalletPolynomial takeEscrowDelta() {
    _ensureLive();
    final delta = _escrowDelta;
    if (delta == null) {
      throw StateError('this operation was not begun with an escrow context');
    }
    _escrowDelta = null;
    return delta;
  }

  /// The polynomial itself, for the two operations that deal with it directly: DKG deals it, and
  /// recovery rebuilds from it before there is a [WalletPublicState] to check against. The
  /// operation keeps no copy.
  WalletPolynomial takePolynomial() {
    _ensureLive();
    final polynomial = _polynomial;
    if (polynomial == null) throw StateError('the polynomial was already taken or used');
    _polynomial = null;
    return polynomial;
  }

  /// Let go of everything. Idempotent, and safe on an operation that never got as far as a share.
  void dispose() {
    _disposed = true;
    _polynomial = null;
    _escrowDelta = null;
    _pairingSlope = null;
    _keyPackage = null;
    _escrowKeyPackage = null;
  }

  void _ensureLive() {
    if (_disposed) throw StateError('this operation is over: its secrets have been released');
  }
}
