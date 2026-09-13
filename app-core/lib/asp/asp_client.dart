/// The wallet's own connection to the ASP.
///
/// The cosigner used to hold this. It registered intents, opened event streams and submitted
/// transactions, which made it the caller's Ark client as well as its signer — and a thing that is
/// *called* rather than running cannot keep a socket. So the wallet talks to the ASP itself and
/// relays what it learns to the cosigner, which answers with what to send next.
///
/// Transliterated from `crates/ark/src/client/asp_client.rs`, which is the same eleven calls in
/// Rust. [`ElectrumClient`] is the shape this follows on the Dart side: a small client app-core
/// owns end to end, rather than a capability borrowed from a server.
library;

import 'package:grpc/grpc.dart';
import 'package:protocol/ark_v1.dart' as ark;

import 'ark_info.dart';

export 'ark_info.dart';

/// Raised when the ASP refuses or cannot be reached. Distinct from a cosigner failure: the two are
/// different parties and a caller usually wants to retry one and not the other.
class AspException implements Exception {
  AspException(this.call, this.cause);
  final String call;
  final Object cause;
  @override
  String toString() => 'ASP $call failed: $cause';
}

class AspClient {
  AspClient(this._channel)
      : _service = ark.ArkServiceClient(_channel),
        _indexer = ark.IndexerServiceClient(_channel);

  /// Connect to `host:port`. Plaintext for a local regtest ASP, TLS otherwise — the same rule the
  /// Rust client applies from the URL scheme.
  factory AspClient.connect(String host, int port, {bool secure = false}) {
    return AspClient(ClientChannel(
      host,
      port: port,
      options: ChannelOptions(
        credentials:
            secure ? const ChannelCredentials.secure() : const ChannelCredentials.insecure(),
      ),
    ));
  }

  final ClientChannel _channel;
  final ark.ArkServiceClient _service;
  final ark.IndexerServiceClient _indexer;

  /// Cached after the first call, as the Rust client does. The parameters change on a redeployment,
  /// not between two sends.
  ArkInfo? _info;

  Future<T> _call<T>(String name, Future<T> Function() f) async {
    try {
      return await f();
    } catch (e) {
      throw AspException(name, e);
    }
  }

  // --- Driving a send or a settle ---------------------------------------------------------------

  /// The ASP's published parameters. Pass `refresh: true` after a redeployment.
  Future<ArkInfo> getInfo({bool refresh = false}) async {
    final cached = _info;
    if (cached != null && !refresh) return cached;
    final resp = await _call('GetInfo', () => _service.getInfo(ark.GetInfoRequest()));
    return _info = ArkInfo.fromResponse(resp);
  }

  /// Register the intent the cosigner built. Returns the id the ASP assigned it, which the cosigner
  /// needs to tell its own batch from the ones a public ASP broadcasts for everybody else.
  Future<String> registerIntent(String proof, String message) async {
    final resp = await _call(
      'RegisterIntent',
      () => _service.registerIntent(
        ark.RegisterIntentRequest(intent: ark.Intent(proof: proof, message: message)),
      ),
    );
    return resp.intentId;
  }

  /// The batch round, as it happens.
  ///
  /// Open this *after* [registerIntent] returns — the topics ride with the proof — but *before*
  /// telling the cosigner the intent is registered, so nothing between the two is missed. A gap
  /// remains between registration and subscription in which a `BatchStarted` can fire; the Rust
  /// client had the same one. Treat it as a round to retry, not as a thing that cannot happen.
  Stream<ark.GetEventStreamResponse> getEventStream(List<String> topics) {
    return _service.getEventStream(ark.GetEventStreamRequest(topics: topics));
  }

  Future<void> confirmRegistration(String intentId) => _call(
        'ConfirmRegistration',
        () => _service.confirmRegistration(ark.ConfirmRegistrationRequest(intentId: intentId)),
      );

  Future<void> submitTreeNonces(
    String batchId,
    String pubkey,
    Map<String, String> nonces,
  ) =>
      _call(
        'SubmitTreeNonces',
        () => _service.submitTreeNonces(
          ark.SubmitTreeNoncesRequest(batchId: batchId, pubkey: pubkey, treeNonces: nonces),
        ),
      );

  Future<void> submitTreeSignatures(
    String batchId,
    String pubkey,
    Map<String, String> signatures,
  ) =>
      _call(
        'SubmitTreeSignatures',
        () => _service.submitTreeSignatures(
          ark.SubmitTreeSignaturesRequest(
            batchId: batchId,
            pubkey: pubkey,
            treeSignatures: signatures,
          ),
        ),
      );

  /// Two distinct fields, not one list. The cosigner used to pack the signed commitment onto the
  /// end of the forfeits, which made a one-element list ambiguous between the two.
  Future<void> submitSignedForfeitTxs({
    List<String> forfeitTxs = const [],
    String commitmentTx = '',
  }) =>
      _call(
        'SubmitSignedForfeitTxs',
        () => _service.submitSignedForfeitTxs(
          ark.SubmitSignedForfeitTxsRequest(
            signedForfeitTxs: forfeitTxs,
            signedCommitmentTx: commitmentTx,
          ),
        ),
      );

  /// Submit a send. The ASP signs its leg of each checkpoint and hands them back for the cosigner
  /// to finalize.
  Future<({String arkTxid, List<String> signedCheckpointTxs})> submitTx(
    String signedArkTx,
    List<String> checkpointTxs,
  ) async {
    final resp = await _call(
      'SubmitTx',
      () => _service.submitTx(
        ark.SubmitTxRequest(signedArkTx: signedArkTx, checkpointTxs: checkpointTxs),
      ),
    );
    return (arkTxid: resp.arkTxid, signedCheckpointTxs: resp.signedCheckpointTxs);
  }

  Future<void> finalizeTx(String arkTxid, List<String> finalCheckpointTxs) => _call(
        'FinalizeTx',
        () => _service.finalizeTx(
          ark.FinalizeTxRequest(arkTxid: arkTxid, finalCheckpointTxs: finalCheckpointTxs),
        ),
      );

  // --- Finding out what we hold -----------------------------------------------------------------

  /// The spendable VTXOs under `scripts`.
  ///
  /// Pass BOTH of the wallet's scripts — the unilateral-delay one and the boarding-delay one. A
  /// wallet holds a mixed set: a boarded VTXO keeps the boarding delay while received and refreshed
  /// ones use the unilateral delay, so they sit under different scripts. Asking for one makes the
  /// other bucket invisible, and invisible is indistinguishable from empty.
  Future<List<IndexerVtxo>> getVtxosByScripts(List<String> scripts) async {
    if (scripts.isEmpty) return const [];
    final resp = await _call(
      'GetVtxos',
      () => _indexer.getVtxos(ark.GetVtxosRequest(scripts: scripts, spendableOnly: true)),
    );
    return resp.vtxos.map(_vtxo).toList();
  }

  /// Everything this wallet holds, with each VTXO tagged by the exit delay of the script it came
  /// under.
  ///
  /// Both scripts, always. A wallet holds a mixed set — a boarded VTXO keeps the boarding delay
  /// while received and refreshed ones use the unilateral delay — so they sit under different
  /// scripts, and asking for one makes the other bucket invisible. Invisible is indistinguishable
  /// from empty, which is how a balance quietly goes missing.
  ///
  /// The tagging is why this exists rather than callers using [getVtxosByScripts] directly: the
  /// cosigner refuses a VTXO whose delay is not one of the ASP's two, and only the caller knows
  /// which script produced which.
  Future<List<IndexerVtxo>> getOwnedVtxos({
    required String unilateralScript,
    required String boardingScript,
    required ArkInfo info,
  }) async {
    final byScript = {
      unilateralScript.toLowerCase(): info.unilateralExitDelay,
      boardingScript.toLowerCase(): info.boardingExitDelay,
    };
    final vtxos = await getVtxosByScripts([unilateralScript, boardingScript]);
    return [
      for (final v in vtxos)
        v.withExitDelay(byScript[v.script.toLowerCase()] ?? info.unilateralExitDelay),
    ];
  }

  /// The VTXOs at these outpoints, spent or not — how a wallet confirms its change landed.
  Future<List<IndexerVtxo>> getVtxosByOutpoints(List<String> outpoints) async {
    if (outpoints.isEmpty) return const [];
    final resp = await _call(
      'GetVtxos',
      () => _indexer.getVtxos(ark.GetVtxosRequest(outpoints: outpoints)),
    );
    return resp.vtxos.map(_vtxo).toList();
  }

  static IndexerVtxo _vtxo(ark.IndexerVtxo v) => IndexerVtxo(
        txid: v.outpoint.txid,
        vout: v.outpoint.vout,
        amountSats: v.amount.toInt(),
        script: v.script,
        isSpent: v.isSpent || v.isSwept || v.isUnrolled,
        createdAt: v.createdAt.toInt(),
        expiresAt: v.expiresAt.toInt(),
      );

  Future<void> shutdown() => _channel.shutdown();
}
