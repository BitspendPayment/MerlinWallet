import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:blockchain_utils/blockchain_utils.dart'
    hide hex; // For Regtest address encoding
import 'package:bitcoin_base/bitcoin_base.dart';
import 'package:app_core/client.dart';
// `BoardingUtxo` moved to the session proto with the Settle stream that consumes it.
import 'package:protocol/cosigner_v1.dart' show BoardingUtxo;
import 'package:convert/convert.dart';
import 'package:app_core/persistence/wallet_store.dart';
import 'package:app_core/coin_selection.dart';
import 'package:app_core/electrum.dart';
import 'package:app_core/fees.dart';
import 'package:app_core/ark/ark.dart';
import 'package:fixnum/fixnum.dart';

/// A wallet on-chain transaction summary for the history UI (was the
/// `TransactionSummary` proto message; on-chain history is now wallet-derived).
class WalletTransaction {
  final String txHash;
  final int amountSats; // signed: + received, - sent
  final int timestamp; // seconds; 0 if unknown/pending
  final bool isPending;

  const WalletTransaction({
    required this.txHash,
    required this.amountSats,
    required this.timestamp,
    required this.isPending,
  });
}

/// Maps a server/ASP network string to bitcoin_base BitcoinNetwork.
/// Throws on empty or unknown input — silently defaulting was a real bug
/// vector when the server returned an empty `bitcoin_network` field; users
/// would get testnet HRP addresses on a regtest deployment.
BitcoinNetwork parseBitcoinNetwork(String network) {
  if (network.isEmpty) {
    throw ArgumentError(
        'parseBitcoinNetwork: empty network string — server returned no '
        'bitcoin_network value, address rendering cannot be safely defaulted');
  }
  switch (network) {
    case 'bitcoin':
    case 'mainnet':
      return BitcoinNetwork.mainnet;
    case 'testnet':
    case 'testnet3':
      return BitcoinNetwork.testnet;
    case 'signet':
    case 'mutinynet':
      return BitcoinNetwork.signet;
    case 'regtest':
      // regtest has no BitcoinNetwork constant; use testnet (same tb HRP).
      // Regtest bcrt addresses are handled separately via SegwitBech32Encoder.
      return BitcoinNetwork.testnet;
    default:
      throw ArgumentError(
          'parseBitcoinNetwork: unknown network "$network" — expected one of '
          'mainnet, testnet, signet, mutinynet, regtest');
  }
}

bool isRegtestNetwork(String network) => network == 'regtest';

/// An Electrum server to scan and broadcast against.
class ElectrumEndpoint {
  final String host;
  final int port;

  const ElectrumEndpoint(this.host, this.port);
}

/// The Electrum server for [network].
///
/// [MpcBitcoinWallet] keeps its OWN chain view — boarding scans, broadcast and
/// history all go through Electrum, and the cosigner has no Bitcoin-node
/// dependency. So the chain source has to follow the network the cosigner
/// reports, not the build: a fixed loopback default silently finds zero UTXOs
/// against a remote deployment, and boarding then looks like it did nothing at
/// all — no error, just an empty wallet.
///
/// Unknown networks throw rather than falling back, on the same reasoning as
/// [parseBitcoinNetwork]: scanning the wrong chain is worse than not starting.
/// `mainnet` is deliberately absent — nothing serves it yet, and it needs a
/// chosen server rather than an inherited default.
ElectrumEndpoint defaultElectrumEndpoint(String network) {
  switch (network) {
    case 'regtest':
      // Alongside the cosigner on the workstation. A physical phone reaches it
      // over `adb reverse`, the emulator via its 10.0.2.2 host alias.
      return const ElectrumEndpoint('127.0.0.1', 50001);
    case 'signet':
    case 'mutinynet':
      // 50001 is plaintext; 50002 is the TLS port, which ElectrumClient cannot
      // speak yet (it uses a raw Socket). That leaks the boarding address and
      // UTXO set to the network path — acceptable for signet, not for real coins.
      return const ElectrumEndpoint('electrum.mutinynet.com', 50001);
    default:
      throw ArgumentError(
          'defaultElectrumEndpoint: no Electrum server configured for network '
          '"$network" — pass electrumHost/electrumPort explicitly');
  }
}

class UnsignedTransaction {
  final BtcTransaction btcTransaction;
  final List<List<int>> sighashes;

  UnsignedTransaction(this.btcTransaction, this.sighashes);
}

/// A VTXO input for script-path spending.
class VtxoInput {
  final String txHash;
  final int vout;
  final BigInt value;
  final ArkVtxo vtxo;

  const VtxoInput({
    required this.txHash,
    required this.vout,
    required this.value,
    required this.vtxo,
  });
}

/// Which taproot script-path leaf to spend through.
enum ScriptPathType { forfeit, exit }

/// An unsigned transaction that spends Ark VTXOs via a taproot script path.
class UnsignedScriptPathTransaction {
  final BtcTransaction btcTransaction;
  final List<List<int>> sighashes;
  final List<SpendInfo> spendInfos;
  final ScriptPathType spendType;

  UnsignedScriptPathTransaction(
    this.btcTransaction,
    this.sighashes,
    this.spendInfos,
    this.spendType,
  );
}

class MpcBitcoinWallet {
  final MpcClient client;
  final WalletStore store;
  final String networkName;

  BitcoinNetwork get bitcoinNetwork => parseBitcoinNetwork(networkName);
  bool get isRegtest => isRegtestNetwork(networkName);

  /// Called after a background sync completes (e.g. from a transaction
  /// notification). The caller (MpcService) can use this to update
  /// balance and notify the UI.
  Future<void> Function()? onSyncComplete;

  late P2trAddress _address;
  P2trAddress get address {
    if (client.getTweakedPublicKeyPackage(null) == null) {
      throw StateError("Wallet not initialized. Call init() first.");
    }
    return _address;
  }

  List<WalletTransaction> _transactions = [];
  List<WalletTransaction> get transactions => List.unmodifiable(_transactions);

  Future<BigInt> getBalance() async {
    final utxos = await store.getUtxos();
    return utxos.fold<BigInt>(BigInt.zero, (sum, u) => sum + u.utxo.value);
  }

  /// The wallet's own Electrum client — all on-chain Bitcoin (UTXO scan,
  /// broadcast, history) goes through here, never the cosigner.
  final ElectrumClient electrum;

  MpcBitcoinWallet(this.client,
      {this.networkName = 'regtest',
      String? storageId,
      bool useIdentity2 = false,
      String? electrumHost,
      int? electrumPort})
      : store = WalletStore(
          boxName: storageId ?? 'mpc_wallet_state_default',
          network: parseBitcoinNetwork(networkName),
        ),
        // Defaults derive from the network rather than being fixed at regtest
        // loopback, so choosing a server also chooses its chain source. Explicit
        // values still win. See [defaultElectrumEndpoint].
        electrum = ElectrumClient(
          electrumHost ?? defaultElectrumEndpoint(networkName).host,
          electrumPort ?? defaultElectrumEndpoint(networkName).port,
        );

  Future<void> init() async {
    await store.init();

    // 1. Try to restore Client/Wallet state from persistence
    final restored = await client.restoreState();

    if (!restored || !client.isInitialized) {
      // 2. If not found, run fresh DKG
      await initializeNewWallet();
    }

    // 3. Setup derivates and sync
    _deriveAddress();

    // Start sync and subscribe in background
    unawaited(_startBackgroundSync());
  }

  Future<void> _startBackgroundSync() async {
    try {
      await sync();
      await onSyncComplete?.call();
    } catch (e) {
      stderr.writeln('[WARN] bitcoin: initial sync error: $e');
    }
    subscribe();
  }

  /// Explicitly runs the DKG protocol.
  /// Call this when creating a fresh wallet or resetting.
  Future<void> initializeNewWallet() async {
    stderr.writeln('[INFO] bitcoin: initializing new wallet…');
    if (!client.isInitialized) {
      stderr.writeln('[INFO] bitcoin: client not initialized — running DKG…');
      await client.doDkg();
    } else {
      stderr.writeln('[INFO] bitcoin: client already initialized, skipping DKG.');
    }
  }

  /// The wallet's single-key on-chain signer (the DKG dealer secret). On-chain
  /// receive/scan/spend/broadcast are wallet-alone — the cosigner is never
  /// involved. The FROST group key stays the Ark owner key (boarding + VTXO).
  ECPrivate get _onchainKey {
    final secretBytes = client.onchainSecretBytes;
    if (secretBytes == null) {
      throw StateError("Wallet not initialized. Call init() first.");
    }
    return ECPrivate.fromBytes(secretBytes);
  }

  void _deriveAddress() {
    // The on-chain utxo address is the BIP-341 key-path taproot address of the
    // single on-chain key (the dealer pubkey is the internal key, tweaked).
    _address = _onchainKey.getPublic().toTaprootAddress();
  }

  /// Helper to generate address with custom HRP (e.g. 'bcrt' for Regtest)
  String toAddressCustom({required String hrp}) {
    // Generate valid Testnet address first (program is same for Testnet/Regtest)
    final addr = address.toAddress(BitcoinNetwork.testnet);
    // Decode to get version/program (Tuple<int, List<int>>)
    final decoded = SegwitBech32Decoder.decode("tb", addr);
    final version = decoded.item1;
    final program = decoded.item2;
    // Encode with custom HRP
    return SegwitBech32Encoder.encode(hrp, version, program);
  }

  /// Returns the wallet address formatted for the configured network.
  String toAddress() {
    if (isRegtest) {
      return toAddressCustom(hrp: 'bcrt');
    }
    return address.toAddress(bitcoinNetwork);
  }

  /// Builds an unsigned transaction, hashes it, and returns the UnsignedTransaction object.
  /// [feeRate] is in sats/vbyte.
  Future<UnsignedTransaction> createTransaction({
    required String destination,
    required BigInt amount,
    required int feeRate,
  }) async {
    // 1. Iterative Coin Selection
    final availableUtxos = await store.getUtxos();

    // Estimates used by P2trFeeEstimator

    List<UtxoWithAddress> selected = [];
    BigInt fee = BigInt.zero;
    BigInt totalIn = BigInt.zero;

    // Attempt loop to stabilize fee
    bool sufficient = false;
    for (int i = 0; i < 5; i++) {
      // Calculate estimated fee for current input count (start with 1 if empty)
      int inputCount = selected.isEmpty ? 1 : selected.length;
      // 1 output provided + potential change output (assume 1 for estimation safety)
      int outputCount = 2;

      fee = P2trFeeEstimator.calculateFee(
          inputCount: inputCount, outputCount: outputCount, feeRate: feeRate);

      try {
        final result = CoinSelection.select(availableUtxos, amount, fee);
        selected = result.$1;
        totalIn = result.$2;

        // Check if clean match (no change needed? unlikely)
        // Re-evaluate size with ACTUAL selected count
        final newFee = P2trFeeEstimator.calculateFee(
            inputCount: selected.length,
            outputCount: outputCount,
            feeRate: feeRate);

        if (newFee <= fee) {
          // We have covered the fee.
          // Actually, if we selected enough for 'fee', and 'newFee' is <= 'fee', we are good.
          // We should use the calculated newFee for the transaction construction if we want to be precise,
          // or just pay the slightly higher 'fee' we selected for.
          // Let's settle on the new calculated fee.
          fee = newFee;
          sufficient = true;
          break;
        }
        // Otherwise, fee increased (more inputs added?), loop again with higher fee
        fee = newFee;
      } catch (e) {
        // Insufficient funds even for estimation, re-throw if last attempt
        if (i == 4) rethrow;
        // Otherwise loop might try again? No, if select fails, we are out of money.
        rethrow;
      }
    }

    if (!sufficient) {
      throw Exception("Could not stabilize fee calculation");
    }

    // 2. Build Transaction
    // Calculate Change
    final inputsValue = totalIn;
    final changeValue = inputsValue - amount - fee;

    BitcoinBaseAddress outputAddress; // Was BitcoinAddress

    // TODO (Joshua) We are only concerned about taproot address for now
    if (destination.startsWith('bcrt')) {
      // Manual decoding for custom/Regtest HRP
      final decoded = SegwitBech32Decoder.decode("bcrt", destination);
      final program = decoded.item2;
      outputAddress = P2trAddress.fromProgram(program: hex.encode(program));
    } else {
      outputAddress = P2trAddress.fromAddress(
          address: destination,
          network: bitcoinNetwork);
    }

    final outputs = <BitcoinOutput>[
      BitcoinOutput(
        address: outputAddress,
        value: amount,
      ),
    ];

    // Add change output if above dust threshold (approx 546 sats)
    if (changeValue > BigInt.from(546)) {
      outputs.add(BitcoinOutput(
        address: address, // Send change back to self
        value: changeValue,
      ));
    }

    final builder = BitcoinTransactionBuilder(
      outPuts: outputs,
      fee: fee,
      network: bitcoinNetwork,
      utxos: selected,
    );

    // 3. MPC Signing Callback (Synchronous collection of hashes)
    final List<List<int>> sighashes = [];

    final txPointer =
        await builder.buildTransaction((sighash, utxo, publicKey, index) {
      sighashes.add(sighash);
      // Return dummy signature (64 bytes hex) to satisfy builder.
      return List.filled(64, 0)
          .map((e) => e.toRadixString(16).padLeft(2, '0'))
          .join();
    });

    // 5. Return Unsigned Transaction
    return UnsignedTransaction(txPointer, sighashes);
  }

  /// Signs an on-chain transaction with the wallet's single on-chain key
  /// (BIP-340 key-path, taproot-tweaked). No cosigner round-trip — on-chain
  /// UTXOs are single-key and signed by the wallet alone.
  Future<String> signTransaction(UnsignedTransaction unsigned) async {
    final txPointer = unsigned.btcTransaction;
    final sighashes = unsigned.sighashes;

    if (sighashes.length != txPointer.inputs.length) {
      throw StateError("Sighash count mismatch");
    }

    final key = _onchainKey;
    final witnesses = <TxWitnessInput>[];

    for (int i = 0; i < txPointer.inputs.length; i++) {
      // Key-path taproot spend: tweak the internal key and Schnorr-sign the
      // BIP-341 digest. `signBip340(tweak: true)` applies the taptweak so the
      // signature verifies under the output key in the UTXO scriptPubKey.
      final sigHex = key.signBip340(sighashes[i], tweak: true);
      witnesses.add(TxWitnessInput(stack: [sigHex]));
    }

    final signedTx = BtcTransaction(
      inputs: txPointer.inputs,
      outputs: txPointer.outputs,
      witnesses: witnesses,
      version: txPointer.version,
    );

    return signedTx.serialize();
  }

  /// Syncs the wallet's single-key UTXOs + history directly from electrum
  /// (the cosigner is not involved in on-chain reads).
  Future<void> sync() async {
    final scriptHash = ElectrumClient.scriptHashForAddress(address);

    final utxos = await electrum.listUnspentByScriptHash(scriptHash);

    try {
      _transactions = await _loadRecentTransactions(scriptHash);
    } catch (e) {
      stderr.writeln('[WARN] bitcoin: error fetching recent transactions: $e');
    }

    final p2trType = BitcoinAddressType.values.firstWhere(
        (e) => e.toString().toLowerCase().contains('tr'),
        orElse: () => BitcoinAddressType.values.last);

    // Single-key on-chain: ownerDetails carries the internal (untweaked) key so
    // the builder computes the right key-path digest; signing tweaks it.
    final ownerDetails = UtxoAddressDetails(
        publicKey: _onchainKey.getPublic().toHex(), address: address);

    final newUtxos = utxos.map((u) {
      return UtxoWithAddress(
        utxo: BitcoinUtxo(
          txHash: u.txHash,
          vout: u.vout,
          value: u.value,
          scriptType: p2trType,
        ),
        ownerDetails: ownerDetails,
      );
    }).toList();

    final deduped = <String, UtxoWithAddress>{};
    for (final utxo in newUtxos) {
      deduped['${utxo.utxo.txHash}:${utxo.utxo.vout}'] = utxo;
    }
    await store.saveUtxos(deduped.values.toList());
  }

  /// Best-effort on-chain history for the UI: net = (my outputs) − (my inputs)
  /// per tx, with the block-header timestamp. Wrapped per-tx so a parse error
  /// on one entry doesn't sink the sync.
  Future<List<WalletTransaction>> _loadRecentTransactions(
      String scriptHash) async {
    final myScriptHex = address.toScriptPubKey().toHex();
    final history = await electrum.getHistory(scriptHash);
    final result = <WalletTransaction>[];
    for (final item in history) {
      try {
        final tx = BtcTransaction.deserialize(
            hex.decode(await electrum.getTransaction(item.txHash)));
        BigInt received = BigInt.zero;
        for (final o in tx.outputs) {
          if (o.scriptPubKey.toHex() == myScriptHex) received += o.amount;
        }
        BigInt spent = BigInt.zero;
        for (final i in tx.inputs) {
          try {
            final prev = BtcTransaction.deserialize(
                hex.decode(await electrum.getTransaction(i.txId)));
            final out = prev.outputs[i.txIndex];
            if (out.scriptPubKey.toHex() == myScriptHex) spent += out.amount;
          } catch (_) {/* prevout unavailable — skip */}
        }
        final ts = item.height > 0
            ? await electrum.getBlockHeaderTime(item.height)
            : 0;
        result.add(WalletTransaction(
          txHash: item.txHash,
          amountSats: (received - spent).toInt(),
          timestamp: ts,
          isPending: item.height <= 0,
        ));
      } catch (e) {
        stderr.writeln('[WARN] bitcoin: tx parse error ${item.txHash}: $e');
      }
    }
    return result;
  }

  Timer? _pollTimer;
  bool _syncing = false;


  void subscribe() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(const Duration(seconds: 15), (_) {
      if (_syncing) return;
      _syncing = true;
      sync()
          .then((_) => onSyncComplete?.call())
          .catchError((e) {
        stderr.writeln('[WARN] bitcoin: poll sync error: $e');
      }).whenComplete(() => _syncing = false);
    });
  }

  /// Stop background polling + close the electrum socket.
  void dispose() {
    _pollTimer?.cancel();
    electrum.close();
  }

  /// Scans the boarding address on-chain and returns the deposits to settle.
  /// The wallet is the only component with a chain view, so it polls + supplies
  /// these to the cosigner's `settle()`.
  ///
  /// **Confirmed deposits only.** The ASP validates every boarding input and
  /// rejects the whole intent if one is still in the mempool:
  /// `INVALID_PSBT_INPUT (5): failed to validate boarding input: tx <id> not
  /// confirmed`. Because one unconfirmed deposit fails the entire settle, an
  /// unfiltered scan makes boarding impossible until every deposit confirms.
  /// Use [scanBoardingPending] to show what is still waiting.
  Future<List<BoardingUtxo>> scanBoarding(String boardingAddress) async {
    return _scanBoarding(boardingAddress, confirmed: true);
  }

  /// Deposits seen on-chain but not yet confirmed, so the UI can say "waiting
  /// for a confirmation" instead of showing nothing at all.
  Future<List<BoardingUtxo>> scanBoardingPending(String boardingAddress) async {
    return _scanBoarding(boardingAddress, confirmed: false);
  }

  Future<List<BoardingUtxo>> _scanBoarding(String boardingAddress,
      {required bool confirmed}) async {
    final addr = _parseP2trDestination(boardingAddress);
    final utxos = await electrum.listUnspent(addr);
    // Electrum reports height 0 for a mempool output; anything greater is mined.
    return utxos
        .where((u) => confirmed ? u.height > 0 : u.height <= 0)
        .map((u) => BoardingUtxo()
          ..txid = u.txHash
          ..vout = u.vout
          ..amountSats = Int64(u.value.toInt()))
        .toList();
  }

  // ---------------------------------------------------------------------------
  // Script-path (Ark VTXO) transaction building
  // ---------------------------------------------------------------------------

  /// Parses a P2TR destination address into a [BitcoinBaseAddress].
  BitcoinBaseAddress _parseP2trDestination(String destination) {
    if (destination.startsWith('bcrt')) {
      final decoded = SegwitBech32Decoder.decode("bcrt", destination);
      final program = decoded.item2;
      return P2trAddress.fromProgram(program: hex.encode(program));
    }
    return P2trAddress.fromAddress(
      address: destination,
      network: bitcoinNetwork,
    );
  }

  /// Encode a block-height CSV delay as a 4-byte little-endian nSequence
  /// value per BIP-68 (type flag clear = block-based relative lock-time).
  static List<int> _csvSequence(int blocks) {
    final v = blocks & 0xFFFF; // lower 16 bits, type-flag bit 22 = 0
    return [v & 0xFF, (v >> 8) & 0xFF, 0x00, 0x00];
  }

  /// Builds an unsigned script-path transaction spending one or more Ark VTXOs.
  ///
  /// [vtxoInputs] — the VTXOs to spend.
  /// [spendType]  — which leaf to use (forfeit = cooperative, exit = unilateral).
  /// [feeRate]    — fee rate in sat/vB.
  Future<UnsignedScriptPathTransaction> createScriptPathTransaction({
    required List<VtxoInput> vtxoInputs,
    required String destination,
    required BigInt amount,
    required int feeRate,
    required ScriptPathType spendType,
  }) async {
    if (vtxoInputs.isEmpty) {
      throw ArgumentError('vtxoInputs must not be empty');
    }

    // 1. Derive spend info for each input
    final spendInfos = vtxoInputs.map((input) {
      return spendType == ScriptPathType.forfeit
          ? input.vtxo.forfeitSpendInfo()
          : input.vtxo.exitSpendInfo();
    }).toList();

    // 2. Estimate fee
    final sigCount = spendType == ScriptPathType.forfeit ? 2 : 1;
    int totalInputVBytes = 0;
    for (final info in spendInfos) {
      totalInputVBytes += P2trFeeEstimator.estimateScriptPathVBytes(
        scriptSize: info.scriptHex.length ~/ 2,
        controlBlockSize: info.controlBlockHex.length ~/ 2,
        stackItemCount: sigCount,
        totalStackSize: sigCount * 64,
      );
    }
    // Assume destination + change output
    final estVBytes = P2trFeeEstimator.overhead +
        totalInputVBytes +
        2 * P2trFeeEstimator.outputVBytes;
    final fee = BigInt.from(estVBytes * feeRate);

    final totalIn =
        vtxoInputs.fold<BigInt>(BigInt.zero, (sum, i) => sum + i.value);
    if (totalIn < amount + fee) {
      throw Exception(
          'Insufficient VTXO funds. Available: $totalIn, Required: ${amount + fee}');
    }

    // 3. Build inputs (set nSequence for CSV on exit path)
    final txInputs = vtxoInputs.map((input) {
      return TxInput(
        txId: input.txHash,
        txIndex: input.vout,
        sequance: spendType == ScriptPathType.exit
            ? _csvSequence(input.vtxo.exitDelay)
            : null, // default 0xFFFFFFFF
      );
    }).toList();

    // 4. Build outputs
    final outputAddress = _parseP2trDestination(destination);

    final txOutputs = <TxOutput>[
      TxOutput(amount: amount, scriptPubKey: outputAddress.toScriptPubKey()),
    ];

    final changeValue = totalIn - amount - fee;
    if (changeValue > BigInt.from(546)) {
      txOutputs.add(
        TxOutput(amount: changeValue, scriptPubKey: address.toScriptPubKey()),
      );
    }

    // 5. Assemble unsigned transaction
    final btcTx = BtcTransaction(inputs: txInputs, outputs: txOutputs);

    // 6. Compute script-path sighashes (BIP-341 with tapleaf)
    final scriptPubKeys = vtxoInputs.map((input) {
      return Script.deserialize(
          bytes: hex.decode(input.vtxo.scriptPubkeyHex()));
    }).toList();
    final amounts = vtxoInputs.map((i) => i.value).toList();

    final sighashes = <List<int>>[];
    for (int i = 0; i < vtxoInputs.length; i++) {
      final leafScript =
          Script.deserialize(bytes: hex.decode(spendInfos[i].scriptHex));
      final tapleaf = TaprootLeaf(script: leafScript);

      final digest = btcTx.getTransactionTaprootDigset(
        txIndex: i,
        scriptPubKeys: scriptPubKeys,
        amounts: amounts,
        tapleafScript: tapleaf,
      );
      sighashes.add(digest);
    }

    return UnsignedScriptPathTransaction(
        btcTx, sighashes, spendInfos, spendType);
  }

  /// Signs a script-path transaction using MPC (no taproot tweak).
  ///
  /// For **forfeit** (cooperative) spending, [serverSignatures] must supply one
  /// 64-byte hex signature per input (the Ark server's Schnorr signature).
  ///
  /// For **exit** (unilateral) spending, only the owner's MPC signature is
  /// required; [serverSignatures] is ignored.
  Future<String> signScriptPathTransaction(
    UnsignedScriptPathTransaction unsigned, {
    List<String>? serverSignatures,
  }) async {
    final tx = unsigned.btcTransaction;
    final sighashes = unsigned.sighashes;
    final spendInfos = unsigned.spendInfos;

    if (sighashes.length != tx.inputs.length) {
      throw StateError('Sighash count mismatch');
    }

    if (unsigned.spendType == ScriptPathType.forfeit &&
        (serverSignatures == null ||
            serverSignatures.length != sighashes.length)) {
      throw ArgumentError(
          'Forfeit spending requires one server signature per input');
    }

    final witnesses = <TxWitnessInput>[];

    for (int i = 0; i < tx.inputs.length; i++) {
      final sighashUint8 = Uint8List.fromList(sighashes[i]);

      // MPC sign without taproot tweak (script-path)
      final signature = await client.sign(
        sighashUint8,
        applyTweak: false,
      );

      final sigBytes = signature.serialize();
      final ownerSigHex =
          sigBytes.map((e) => e.toRadixString(16).padLeft(2, '0')).join();

      // Witness stack: [witness items..., leaf_script, control_block]
      //
      // Forfeit script: <server_pk> CHECKSIGVERIFY <owner_pk> CHECKSIG
      //   → stack consumed bottom-to-top: owner_sig then server_sig
      //   → witness order: [owner_sig, server_sig, script, control_block]
      //
      // Exit script: <owner_pk> CHECKSIGVERIFY <sequence> CSV DROP
      //   → witness order: [owner_sig, script, control_block]
      final stack = <String>[];

      if (unsigned.spendType == ScriptPathType.forfeit) {
        stack.add(ownerSigHex);
        stack.add(serverSignatures![i]);
      } else {
        stack.add(ownerSigHex);
      }

      stack.add(spendInfos[i].scriptHex);
      stack.add(spendInfos[i].controlBlockHex);

      witnesses.add(TxWitnessInput(stack: stack));
    }

    final signedTx = BtcTransaction(
      inputs: tx.inputs,
      outputs: tx.outputs,
      witnesses: witnesses,
      version: tx.version,
    );

    return signedTx.serialize();
  }

  /// Broadcasts a signed transaction via the wallet's own electrum client.
  Future<String> broadcast(String txHex) async {
    return await electrum.broadcast(txHex);
  }
}
