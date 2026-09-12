//! Ark batch/settle protocol for boarding on-chain UTXOs into VTXOs.
//!
//! This module splits the settlement flow into discrete phases so that FROST
//! threshold signing can happen externally between phases.
//!
//! ## Phases
//!
//! 1. **Prepare intent** (`new_boarding`) -- build the intent proof PSBT, return
//!    sighashes that need FROST signing.
//! 2. **Register intent** (`register_with_signatures`) -- insert FROST signatures
//!    into the proof PSBT and register the intent with the ASP.
//! 3. **Drive batch** (`drive`) -- consume the ASP event stream: confirm
//!    registration, generate ephemeral nonces, sign tree txs, and extract
//!    commitment PSBT sighashes for FROST.
//! 4. **Complete** (`submit_commitment_signatures`) -- insert FROST signatures
//!    for the commitment PSBT and submit forfeit/commitment to the ASP.

use std::collections::HashMap;
use std::str::FromStr;

use ark_core::batch::{NonceKps, OnChainInput};
use ark_core::batch::{aggregate_nonces, generate_nonce_tree, sign_batch_tree_tx};
use ark_core::intent::IntentMessage;
use ark_core::server::PartialSigTree;
use ark_core::{BoardingOutput, TxGraph, TxGraphChunk, VTXO_TAPROOT_KEY};

use bitcoin::absolute;
use bitcoin::base64::{self, Engine};
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::psbt::{self, PsbtSighashType};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{self, LeafVersion};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction,
    TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};

#[cfg(feature = "client")]
use crate::client::asp_client::AspClient;
use crate::client::proto;

/// Whether `event`'s batch actually contains our intent.
///
/// A public ASP batches many clients together, and `BatchStarted` is broadcast
/// regardless of whose intents made it into that batch. Confirming
/// unconditionally makes us join a batch we were never registered in, and the
/// ASP then aborts it with "not enough intent confirmations received" — its
/// real participants never confirmed. On a single-tenant regtest ASP every
/// batch is ours, which is why this only ever fails against a shared server.
///
/// The hash is `sha256(intent_id)` lowercase-hex, matching arkd and the
/// reference client in `third_party/rust-sdk/ark-client/src/batch.rs`.
/// The batch id of a batch-scoped `event` that `is_ours` rejects, or `None` when
/// the event is ours or carries no batch id at all.
///
/// Central so every settle loop gates on the same set. `BatchStarted` is
/// deliberately excluded — it is filtered by intent hash instead
/// (see [`batch_includes_intent`]), and it is what establishes the batch id
/// everything else is matched against. Heartbeat/StreamStarted are not
/// batch-scoped.
pub fn foreign_batch_id<F>(event: &Event, is_ours: F) -> Option<String>
where
    F: Fn(&str) -> bool,
{
    let id = match event {
        Event::BatchStarted(_) | Event::Heartbeat(_) | Event::StreamStarted(_) => return None,
        Event::TreeSigningStarted(e) => &e.id,
        Event::TreeNoncesAggregated(e) => &e.id,
        Event::TreeTx(e) => &e.id,
        Event::TreeNonces(e) => &e.id,
        Event::TreeSignature(e) => &e.id,
        Event::BatchFinalization(e) => &e.id,
        Event::BatchFinalized(e) => &e.id,
        Event::BatchFailed(e) => &e.id,
    };
    if is_ours(id) {
        None
    } else {
        Some(id.clone())
    }
}

pub fn batch_includes_intent(event: &proto::BatchStartedEvent, intent_id: &str) -> bool {
    let hash = sha256::Hash::hash(intent_id.as_bytes());
    let hash_hex: String = hash.as_byte_array().iter().map(|b| format!("{b:02x}")).collect();
    event.intent_id_hashes.iter().any(|h| h == &hash_hex)
}
// A prost message type, not transport: classifying an event needs no ASP connection, and the guest
// that drives a settle from relayed events needs exactly this.
use crate::client::proto::get_event_stream_response::Event;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Action the caller must take after calling [`SettleSession::drive`].
pub enum SettleAction {
    /// FROST signatures are needed on these sighashes (script-path, no tweak).
    NeedSignatures { sighashes: Vec<[u8; 32]> },
    /// Plan A Phase 2: the MuSig2 tree-signing secret lives in the cosigner guest, not here. The
    /// caller must dispatch these (public) tree chunks + commitment PSBT to the guest's
    /// `BoardingGenNonces`, then call [`SettleSession::submit_tree_nonces`] with the result.
    NeedTreeNonces {
        tree_tx_chunks: Vec<(String, String, Vec<(u32, String)>)>,
        commitment_psbt_b64: String,
    },
    /// Plan A Phase 2: the caller must dispatch the aggregated per-node nonces to the guest's
    /// `BoardingTreeSign`, then call [`SettleSession::submit_tree_signatures`] with the result.
    NeedTreeSign {
        pending_nonces: Vec<(String, Vec<(String, String)>)>,
        batch_expiry: u32,
        forfeit_pk_hex: String,
    },
    /// Batch is still processing; poll `drive` again.
    WaitingForBatch,
    /// Settlement complete.
    Settled {
        commitment_txid: String,
        /// The VTXO tree leaf outpoint (txid, vout).
        vtxo_outpoint: Option<(String, u32)>,
    },
}

/// Internal phase of the settle session state machine.
enum Phase {
    /// Intent prepared, waiting for FROST signatures on intent proof.
    AwaitingIntentSignatures,
    /// Intent registered, driving the event stream.
    Driving,
    /// Commitment PSBT received, waiting for FROST signatures.
    AwaitingCommitmentSignatures,
    /// Settlement complete.
    Done,
}

/// A session for settling boarding UTXOs into Ark VTXOs.
///
/// Splits the batch protocol into phases so that FROST signing can happen
/// externally between each phase.
pub struct SettleSession {
    phase: Phase,

    // -- identity --
    owner_pk: XOnlyPublicKey,
    #[allow(dead_code)]
    asp_pk: XOnlyPublicKey,
    /// ASP's forfeit x-only public key (used for tree signing sweep scripts).
    forfeit_pk: XOnlyPublicKey,
    #[allow(dead_code)]
    network: Network,
    #[allow(dead_code)]
    exit_delay: Sequence,

    // -- boarding input --
    boarding_output: BoardingOutput,
    onchain_input: OnChainInput,

    // -- intent --
    intent_proof_psbt: Option<Psbt>,
    intent_message: Option<IntentMessage>,
    /// Sighash index -> (psbt input index, leaf_hash) for inserting sigs later.
    intent_sighash_meta: Vec<(usize, TapLeafHash)>,
    // Used by the host (`client` feature) confirm path; the guest drives its own intent id locally.
    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    intent_id: Option<String>,

    // -- cosigner identity (PUBLIC only) --
    // Plan A Phase 2: the MuSig2 cosigner keypair + secret per-node nonces live in the cosigner
    // guest, NOT here. This session keeps only the PUBLIC cosigner key (for the intent + event-
    // stream topic); tree-signing is delegated out via `SettleAction::NeedTreeNonces`/`NeedTreeSign`.
    cosigner_pk: bitcoin::secp256k1::PublicKey,

    // -- batch state --
    batch_id: Option<String>,
    batch_expiry: Option<Sequence>,
    #[cfg(feature = "client")]
    event_stream: Option<tonic::Streaming<proto::GetEventStreamResponse>>,
    tx_graph_chunks: Vec<TxGraphChunk>,
    tx_graph: Option<TxGraph>,
    commitment_psbt: Option<Psbt>,
    /// Accumulated raw nonces per tree txid (from TreeNonces events).
    /// We only sign + submit once ALL nonces for every node in the graph
    /// have been collected (matching the reference ark-client).
    pending_nonces: HashMap<Txid, HashMap<String, String>>,

    // -- commitment signing --
    commitment_sighash_meta: Vec<(usize, TapLeafHash)>,
}

/// Standalone boarding tree-signer (Plan A Phase 2). Does ONLY the secret MuSig2 tree-signing of a
/// boarding settle — so it can run inside the cosigner guest while the host keeps the batch state
/// machine, the event stream, and the FROST rounds. It holds the secret per-node nonces between
/// `gen_nonces` and `sign`. All inputs/outputs are wire-friendly (hex / base64 / strings), so the
/// guest needs no `ark_core` types: the host passes the public tree graph; the secret stays here.
pub struct BoardingTreeSigner {
    cosigner_kp: Keypair,
    tx_graph: Option<TxGraph>,
    commitment_psbt: Option<Psbt>,
    nonce_kps: Option<NonceKps>,
}

impl BoardingTreeSigner {
    /// Build from the cosigner's MuSig2 tree-signing secret (the Ark `dkg-secret`, held in-guest).
    pub fn new(cosigner_secret_hex: &str) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let bytes = hex_decode_32(cosigner_secret_hex)?;
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes)
            .map_err(|e| format!("bad cosigner secret: {e}"))?;
        Ok(Self {
            cosigner_kp: Keypair::from_secret_key(&secp, &sk),
            tx_graph: None,
            commitment_psbt: None,
            nonce_kps: None,
        })
    }

    /// The cosigner's MuSig2 public key (33-byte compressed, hex) — the host needs it for the
    /// boarding intent's `own_cosigner_pks` and never has to derive it from the secret.
    pub fn cosigner_pubkey_hex(&self) -> String {
        self.cosigner_kp.public_key().to_string()
    }

    /// Rebuild the tx graph from the (public) tree chunks, generate the secret nonce tree, and
    /// return the cosigner pubkey + per-node public nonce points to submit. Holds the secret nonces
    /// + graph for the matching `sign`. `tree_tx_chunks` = `(txid_or_empty, psbt_b64, [(vout, child_txid)])`.
    pub fn gen_nonces(
        &mut self,
        tree_tx_chunks: &[(String, String, Vec<(u32, String)>)],
        commitment_psbt_b64: &str,
    ) -> Result<(String, Vec<(String, String)>), String> {
        let commitment_psbt = decode_psbt_b64(commitment_psbt_b64)?;
        let mut chunks = Vec::with_capacity(tree_tx_chunks.len());
        for (txid_str, psbt_b64, children_wire) in tree_tx_chunks {
            let tx = decode_psbt_b64(psbt_b64)?;
            let txid = if txid_str.is_empty() {
                None
            } else {
                Some(txid_str.parse().map_err(|e| format!("bad chunk txid: {e}"))?)
            };
            let children = children_wire
                .iter()
                .map(|(vout, ctxid)| {
                    Ok::<_, String>((
                        *vout,
                        ctxid.parse().map_err(|e| format!("bad child txid: {e}"))?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, String>>()?;
            chunks.push(TxGraphChunk { txid, tx, children });
        }
        let tx_graph = TxGraph::new(chunks).map_err(|e| format!("TxGraph::new: {e}"))?;

        let cosigner_pk = self.cosigner_kp.public_key();
        let nonce_kps = {
            let mut rng = rand::thread_rng();
            generate_nonce_tree(&mut rng, &tx_graph, cosigner_pk, &commitment_psbt)
                .map_err(|e| format!("generate_nonce_tree: {e}"))?
        };
        let nonce_map: Vec<(String, String)> =
            nonce_kps.to_nonce_pks().encode().into_iter().collect();

        self.nonce_kps = Some(nonce_kps);
        self.tx_graph = Some(tx_graph);
        self.commitment_psbt = Some(commitment_psbt);
        Ok((cosigner_pk.to_string(), nonce_map))
    }

    /// MuSig2-sign every tree tx with the in-guest cosigner key + held nonces. `pending_nonces` =
    /// `(tree_txid, [(cosigner_pk_hex, nonce_pk_hex)])` for every node. Returns the cosigner pubkey
    /// + per-node partial signatures, and consumes the held session.
    pub fn sign(
        &mut self,
        pending_nonces: &[(String, Vec<(String, String)>)],
        batch_expiry: u32,
        forfeit_pk_hex: &str,
    ) -> Result<(String, Vec<(String, String)>), String> {
        let tx_graph = self
            .tx_graph
            .as_ref()
            .ok_or("no tx_graph (call gen_nonces first)")?;
        let commitment_psbt = self.commitment_psbt.as_ref().ok_or("no commitment_psbt")?;
        let nonce_kps = self.nonce_kps.as_mut().ok_or("no nonce_kps")?;
        let batch_expiry = Sequence::from_consensus(batch_expiry);
        let forfeit_pk = bitcoin::XOnlyPublicKey::from_str(forfeit_pk_hex)
            .map_err(|e| format!("bad forfeit_pk: {e}"))?;

        let mut nonces_by_txid: HashMap<Txid, HashMap<String, String>> = HashMap::new();
        for (txid_str, nonces) in pending_nonces {
            let txid: Txid = txid_str.parse().map_err(|e| format!("bad txid: {e}"))?;
            nonces_by_txid.insert(txid, nonces.iter().cloned().collect());
        }

        let mut combined = PartialSigTree::default();
        for (tree_txid, _) in tx_graph.as_map() {
            let raw = nonces_by_txid
                .get(&tree_txid)
                .ok_or_else(|| format!("missing nonces for {tree_txid}"))?;
            let nonce_pks = ark_core::server::TreeTxNoncePks::decode(raw.clone())
                .map_err(|e| format!("decode TreeTxNoncePks: {e}"))?;
            let agg = aggregate_nonces(nonce_pks);
            let partial = sign_batch_tree_tx(
                tree_txid,
                batch_expiry,
                forfeit_pk,
                &self.cosigner_kp,
                agg,
                tx_graph,
                commitment_psbt,
                nonce_kps,
            )
            .map_err(|e| format!("sign_batch_tree_tx {tree_txid}: {e}"))?;
            combined.0.extend(partial.0);
        }
        let sig_map: Vec<(String, String)> = combined.encode().into_iter().collect();
        let cosigner_pk_hex = self.cosigner_kp.public_key().to_string();
        self.tx_graph = None;
        self.commitment_psbt = None;
        self.nonce_kps = None;
        Ok((cosigner_pk_hex, sig_map))
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl SettleSession {
    /// Create a new settle session for boarding UTXOs.
    ///
    /// Returns `(session, sighashes)` where `sighashes` are the taproot
    /// script-path sighashes that need FROST signing for the intent proof.
    pub fn new_boarding(
        owner_pk_hex: &str,
        asp_pk_hex: &str,
        forfeit_pk_hex: &str,
        boarding_address: &str,
        boarding_utxo_txid: &str,
        boarding_utxo_vout: u32,
        boarding_utxo_amount_sat: u64,
        exit_delay: u32,
        network: &str,
        cosigner_pk_hex: &str,
    ) -> Result<(Self, Vec<[u8; 32]>), String> {
        let secp = Secp256k1::new();
        let network = parse_network(network)?;

        let owner_pk = parse_xonly(owner_pk_hex)?;
        let asp_pk = parse_xonly(asp_pk_hex)?;
        let forfeit_pk = parse_xonly(forfeit_pk_hex)?;

        let exit_seq = ark_core::server::parse_sequence_number(exit_delay as i64)
            .map_err(|e| format!("invalid exit_delay: {e}"))?;

        let boarding_output =
            BoardingOutput::new(&secp, asp_pk, owner_pk, exit_seq, network)
                .map_err(|e| format!("BoardingOutput::new: {e}"))?;

        // Verify the address matches what the caller expects.
        let derived_addr = boarding_output.address().to_string();
        if derived_addr != boarding_address {
            return Err(format!(
                "derived boarding address {derived_addr} != expected {boarding_address}"
            ));
        }

        let outpoint = OutPoint {
            txid: boarding_utxo_txid
                .parse()
                .map_err(|e| format!("invalid txid: {e}"))?,
            vout: boarding_utxo_vout,
        };

        let amount = Amount::from_sat(boarding_utxo_amount_sat);

        let onchain_input = OnChainInput::new(boarding_output.clone(), amount, outpoint);

        // Plan A Phase 2: the MuSig2 cosigner SECRET lives in the cosigner guest. Here we only need
        // its PUBLIC key, supplied by the caller (fetched from the guest), to declare the cosigner
        // in the intent. The actual tree-signing is delegated out during `drive`.
        let cosigner_pk = bitcoin::secp256k1::PublicKey::from_str(cosigner_pk_hex)
            .map_err(|e| format!("invalid cosigner pubkey: {e}"))?;

        // Build the intent message.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("time error: {e}"))?
            .as_secs();
        let expire_at = now + 120; // 2 minutes

        let intent_message = IntentMessage::Register {
            onchain_output_indexes: vec![],
            valid_at: now,
            expire_at,
            own_cosigner_pks: vec![cosigner_pk],
        };

        // Build the BIP-322-like proof PSBT manually since
        // `build_proof_psbt` is pub(crate) in ark-core.
        let (forfeit_script, forfeit_cb) = boarding_output.forfeit_spend_info();
        let script_pubkey = boarding_output.script_pubkey();
        let tapscripts = boarding_output.tapscripts();

        let message_json = intent_message
            .encode()
            .map_err(|e| format!("encode intent message: {e}"))?;

        // BIP-322 "to_spend" transaction.
        let to_spend_tx = build_to_spend_tx(&message_json, &script_pubkey);
        let fake_outpoint = OutPoint {
            txid: to_spend_tx.compute_txid(),
            vout: 0,
        };

        // "to_sign" proof PSBT: input 0 = fake BIP-322 input, input 1 = boarding.
        let proof_tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: fake_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
                TxIn {
                    previous_output: outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
            ],
            output: vec![TxOut {
                value: amount,
                script_pubkey: boarding_output
                    .to_ark_address(network, asp_pk)
                    .to_p2tr_script_pubkey(),
            }],
        };

        let mut proof_psbt = Psbt::from_unsigned_tx(proof_tx)
            .map_err(|e| format!("Psbt::from_unsigned_tx: {e}"))?;

        // Populate witness UTXOs and sighash types.
        proof_psbt.inputs[0].witness_utxo = Some(to_spend_tx.output[0].clone());
        proof_psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(1));
        proof_psbt.inputs[0].witness_script = Some(forfeit_script.clone());

        proof_psbt.inputs[1].witness_utxo = Some(TxOut {
            value: amount,
            script_pubkey: script_pubkey.clone(),
        });
        proof_psbt.inputs[1].sighash_type = Some(PsbtSighashType::from_u32(1));
        proof_psbt.inputs[1].witness_script = Some(forfeit_script.clone());

        // Populate tap_scripts for both inputs.
        // Input 0 (BIP-322 fake) uses the same spend info as the boarding input.
        proof_psbt.inputs[0].tap_scripts.insert(
            forfeit_cb.clone(),
            (forfeit_script.clone(), LeafVersion::TapScript),
        );

        // Input 1 (boarding): add tap_scripts and taptree encoding.
        proof_psbt.inputs[1].tap_scripts.insert(
            forfeit_cb.clone(),
            (forfeit_script.clone(), LeafVersion::TapScript),
        );
        let taptree_bytes = encode_taptree(&tapscripts);
        proof_psbt.inputs[1].unknown.insert(
            psbt::raw::Key {
                type_value: 222,
                key: VTXO_TAPROOT_KEY.to_vec(),
            },
            taptree_bytes,
        );

        // Compute sighashes for every input in the proof PSBT.
        let prevouts: Vec<TxOut> = proof_psbt
            .inputs
            .iter()
            .filter_map(|i| i.witness_utxo.clone())
            .collect();

        let mut sighashes = Vec::new();
        let mut sighash_meta = Vec::new();

        for (i, proof_input) in proof_psbt.inputs.iter().enumerate() {
            let (_, (script, leaf_version)) = proof_input
                .tap_scripts
                .first_key_value()
                .ok_or_else(|| format!("missing tap_scripts for input {i}"))?;

            let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
            let prevs = Prevouts::All(&prevouts);

            let tap_sighash = SighashCache::new(&proof_psbt.unsigned_tx)
                .taproot_script_spend_signature_hash(
                    i,
                    &prevs,
                    leaf_hash,
                    TapSighashType::Default,
                )
                .map_err(|e| format!("sighash error input {i}: {e}"))?;

            sighashes.push(tap_sighash.to_raw_hash().to_byte_array());
            sighash_meta.push((i, leaf_hash));
        }

        let session = SettleSession {
            phase: Phase::AwaitingIntentSignatures,
            owner_pk,
            asp_pk,
            forfeit_pk,
            network,
            exit_delay: exit_seq,
            boarding_output,
            onchain_input,
            intent_proof_psbt: Some(proof_psbt),
            intent_message: Some(intent_message),
            intent_sighash_meta: sighash_meta,
            intent_id: None,
            cosigner_pk,
            batch_id: None,
            batch_expiry: None,
            #[cfg(feature = "client")]
            event_stream: None,
            tx_graph_chunks: Vec::new(),
            tx_graph: None,
            commitment_psbt: None,
            pending_nonces: HashMap::new(),
            commitment_sighash_meta: Vec::new(),
        };

        Ok((session, sighashes))
    }
}

// ---------------------------------------------------------------------------
// Phase transitions (ASP transport — host only)
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
impl SettleSession {
    #[cfg(feature = "client")]
    /// Submit FROST signatures for the intent proof and register with the ASP.
    ///
    /// `signatures` must be in the same order as the sighashes returned by
    /// `new_boarding`.
    pub async fn register_with_signatures(
        &mut self,
        asp: &mut AspClient,
        signatures: Vec<[u8; 64]>,
    ) -> Result<(), String> {
        if !matches!(self.phase, Phase::AwaitingIntentSignatures) {
            return Err("register_with_signatures called in wrong phase".into());
        }

        let proof_psbt = self
            .intent_proof_psbt
            .as_mut()
            .ok_or("missing intent proof PSBT")?;

        if signatures.len() != self.intent_sighash_meta.len() {
            return Err(format!(
                "expected {} signatures, got {}",
                self.intent_sighash_meta.len(),
                signatures.len()
            ));
        }

        // Insert each FROST signature into the proof PSBT.
        for (sig_bytes, (input_idx, leaf_hash)) in
            signatures.iter().zip(self.intent_sighash_meta.iter())
        {
            let schnorr_sig =
                bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
                    .map_err(|e| format!("invalid schnorr sig: {e}"))?;

            let sig = taproot::Signature {
                signature: schnorr_sig,
                sighash_type: TapSighashType::Default,
            };

            proof_psbt.inputs[*input_idx]
                .tap_script_sigs
                .insert((self.owner_pk, *leaf_hash), sig);
        }

        // Serialize the proof and message for registration.
        let proof_b64 = encode_psbt_b64(proof_psbt);

        let message_json = self
            .intent_message
            .as_ref()
            .ok_or("missing intent message")?
            .encode()
            .map_err(|e| format!("encode intent message: {e}"))?;

        let intent_id = asp
            .register_intent(proof_b64, message_json)
            .await
            .map_err(|e| format!("register_intent: {e}"))?;

        self.intent_id = Some(intent_id);
        self.phase = Phase::Driving;

        // Open the event stream with outpoint + cosigner key topics
        // (matching the reference ark-client implementation).
        let outpoint_topic = self.onchain_input.outpoint().to_string();
        let cosigner_bytes = self.cosigner_pk.serialize();
        let cosigner_topic = cosigner_bytes.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        eprintln!(
            "event stream topics: outpoint={outpoint_topic}, cosigner={cosigner_topic}"
        );
        let stream = asp
            .get_event_stream(vec![outpoint_topic, cosigner_topic])
            .await
            .map_err(|e| format!("get_event_stream: {e}"))?;
        self.event_stream = Some(stream);

        Ok(())
    }

    #[cfg(feature = "client")]
    /// Drive the event stream forward.
    ///
    /// Call this repeatedly until it returns [`SettleAction::Settled`] or
    /// [`SettleAction::NeedSignatures`] (for the commitment PSBT).
    pub async fn drive(&mut self, asp: &mut AspClient) -> Result<SettleAction, String> {
        match self.phase {
            Phase::AwaitingIntentSignatures => {
                return Err("call register_with_signatures first".into());
            }
            Phase::AwaitingCommitmentSignatures => {
                return Err("call submit_commitment_signatures first".into());
            }
            Phase::Done => {
                return Err("session already complete".into());
            }
            Phase::Driving => {}
        }

        let stream = self.event_stream.as_mut().ok_or("event stream not open")?;

        use tokio_stream::StreamExt;
        let msg = stream
            .next()
            .await
            .ok_or("event stream ended unexpectedly")?
            .map_err(|e| format!("stream error: {e}"))?;

        let event = match msg.event {
            Some(e) => e,
            None => return Ok(SettleAction::WaitingForBatch),
        };

        // Batch-scoped events from a batch we did not join are not ours to act on.
        if let Some(other) = foreign_batch_id(&event, |id| self.is_our_batch(id)) {
            eprintln!("event: ignoring event for foreign batch id={other}");
            return Ok(SettleAction::WaitingForBatch);
        }

        match event {
            Event::BatchStarted(e) => {
                eprintln!("event: BatchStarted id={}", e.id);
                self.handle_batch_started(asp, e).await?;
                Ok(SettleAction::WaitingForBatch)
            }
            Event::TreeSigningStarted(e) => {
                eprintln!(
                    "event: TreeSigningStarted id={} cosigners={} chunks_so_far={}",
                    e.id, e.cosigners_pubkeys.len(), self.tx_graph_chunks.len()
                );
                // Plan A Phase 2: nonce generation needs the cosigner SECRET, which lives in the
                // guest — return the public tree data so the caller can dispatch it.
                self.on_tree_signing_started(e)
            }
            Event::TreeNoncesAggregated(e) => {
                eprintln!("event: TreeNoncesAggregated id={}", e.id);
                // Signing already done in handle_tree_nonces_and_sign.
                Ok(SettleAction::WaitingForBatch)
            }
            Event::TreeTx(e) => {
                eprintln!(
                    "event: TreeTx id={} txid={} topic={:?}",
                    e.id, e.txid, e.topic
                );
                self.handle_tree_tx(e)?;
                Ok(SettleAction::WaitingForBatch)
            }
            Event::TreeNonces(e) => {
                eprintln!(
                    "event: TreeNonces id={} txid={} nonces_count={}",
                    e.id, e.txid, e.nonces.len()
                );
                // Plan A Phase 2: accumulate; once every node has nonces, return them so the caller
                // can dispatch tree-signing to the guest (the secret is there, not here).
                match self.on_tree_nonces(e)? {
                    Some(action) => Ok(action),
                    None => Ok(SettleAction::WaitingForBatch),
                }
            }
            Event::TreeSignature(_) => {
                // Per-tx signature events from other cosigners; ignored.
                Ok(SettleAction::WaitingForBatch)
            }
            Event::BatchFinalization(e) => {
                eprintln!("event: BatchFinalization id={}", e.id);
                let sighashes = self.handle_batch_finalization(e)?;
                self.phase = Phase::AwaitingCommitmentSignatures;
                Ok(SettleAction::NeedSignatures { sighashes })
            }
            Event::BatchFinalized(e) => {
                eprintln!("event: BatchFinalized txid={}", e.commitment_txid);
                self.phase = Phase::Done;
                // Extract the VTXO leaf outpoint from the tree graph.
                let vtxo_outpoint = self.tx_graph.as_ref().map(|g| {
                    let leaf = first_tree_leaf(g);
                    (leaf.unsigned_tx.compute_txid().to_string(), 0u32)
                });
                Ok(SettleAction::Settled {
                    commitment_txid: e.commitment_txid,
                    vtxo_outpoint,
                })
            }
            Event::BatchFailed(e) => Err(format!("batch failed: {}", e.reason)),
            Event::Heartbeat(_) | Event::StreamStarted(_) => Ok(SettleAction::WaitingForBatch),
        }
    }

    #[cfg(feature = "client")]
    /// Submit FROST signatures for the commitment PSBT and finalize.
    pub async fn submit_commitment_signatures(
        &mut self,
        asp: &mut AspClient,
        signatures: Vec<[u8; 64]>,
    ) -> Result<(), String> {
        if !matches!(self.phase, Phase::AwaitingCommitmentSignatures) {
            return Err("submit_commitment_signatures called in wrong phase".into());
        }

        let commitment_psbt = self
            .commitment_psbt
            .as_mut()
            .ok_or("missing commitment PSBT")?;

        if signatures.len() != self.commitment_sighash_meta.len() {
            return Err(format!(
                "expected {} commitment sigs, got {}",
                self.commitment_sighash_meta.len(),
                signatures.len()
            ));
        }

        // Insert FROST signatures into the commitment PSBT.
        for (sig_bytes, (input_idx, leaf_hash)) in
            signatures.iter().zip(self.commitment_sighash_meta.iter())
        {
            let schnorr_sig =
                bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
                    .map_err(|e| format!("invalid schnorr sig: {e}"))?;

            let sig = taproot::Signature {
                signature: schnorr_sig,
                sighash_type: TapSighashType::Default,
            };

            commitment_psbt.inputs[*input_idx]
                .tap_script_sigs
                .insert((self.owner_pk, *leaf_hash), sig);
        }

        // Serialize the signed commitment PSBT.
        let signed_commitment_b64 = encode_psbt_b64(commitment_psbt);

        // For boarding-only (no existing VTXOs being forfeited), there are no
        // forfeit txs to sign.
        asp.submit_signed_forfeit_txs(vec![], signed_commitment_b64)
            .await
            .map_err(|e| format!("submit_signed_forfeit_txs: {e}"))?;

        // Return to driving phase so the caller can poll for BatchFinalized.
        self.phase = Phase::Driving;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Event handlers. The sync `on_*` step methods are guest-driveable (no ASP transport);
// the `async fn handle_*`/`submit_*` (ASP `AspClient`) are host-only (per-method cfg).
// ---------------------------------------------------------------------------

impl SettleSession {
    #[cfg(feature = "client")]
    /// Whether `id` names the batch this session actually joined.
    ///
    /// Every batch-scoped event is broadcast for every batch on a public ASP, so
    /// each one has to be matched against the batch we confirmed into. Filtering
    /// `BatchStarted` alone is not enough: an unrelated batch's `BatchFailed`
    /// would abort a settle still waiting for its own, and its `BatchFinalized`
    /// would be recorded as our settlement.
    ///
    /// A `None` batch_id means we have not joined anything yet, so nothing is
    /// ours — same as the reference client, which ignores every batch event
    /// until its `Step` leaves `Start`.
    fn is_our_batch(&self, id: &str) -> bool {
        self.batch_id.as_deref() == Some(id)
    }

    #[cfg(feature = "client")]
    async fn handle_batch_started(
        &mut self,
        asp: &mut AspClient,
        event: proto::BatchStartedEvent,
    ) -> Result<(), String> {
        let intent_id = self
            .intent_id
            .as_ref()
            .ok_or("no intent_id to confirm")?
            .clone();

        // Not our batch: leave batch_id/expiry untouched and keep waiting. Adopting a
        // foreign batch id here is what later mis-routes tree signing.
        if !batch_includes_intent(&event, &intent_id) {
            return Ok(());
        }

        self.batch_id = Some(event.id.clone());

        if event.batch_expiry > 0 {
            self.batch_expiry = Some(
                ark_core::server::parse_sequence_number(event.batch_expiry)
                    .map_err(|e| format!("parse batch_expiry: {e}"))?,
            );
        }

        asp.confirm_registration(intent_id)
            .await
            .map_err(|e| format!("confirm_registration: {e}"))?;

        Ok(())
    }

    /// TreeSigningStarted (Plan A Phase 2): build + store the tx graph from collected chunks, and
    /// return the (public) tree data the caller must dispatch to the guest's `BoardingGenNonces`.
    /// No secret is touched here — nonce generation happens in the guest.
    pub fn on_tree_signing_started(
        &mut self,
        event: proto::TreeSigningStartedEvent,
    ) -> Result<SettleAction, String> {
        // Use batch_id from BatchStarted if available, else the event id (public ASPs may skip it).
        if self.batch_id.is_none() {
            self.batch_id = Some(event.id.clone());
        }
        let commitment_psbt = decode_psbt_b64(&event.unsigned_commitment_tx)?;
        if self.tx_graph_chunks.is_empty() {
            return Err("no tree tx chunks collected yet".into());
        }
        let chunks: Vec<TxGraphChunk> = self.tx_graph_chunks.drain(..).collect();

        // Serialize the (public) chunks for the guest, then build our own graph for tracking.
        let tree_tx_chunks: Vec<(String, String, Vec<(u32, String)>)> = chunks
            .iter()
            .map(|c| {
                let txid = c.txid.map(|t| t.to_string()).unwrap_or_default();
                let psbt_b64 = encode_psbt_b64(&c.tx);
                let children = c.children.iter().map(|(v, t)| (*v, t.to_string())).collect();
                (txid, psbt_b64, children)
            })
            .collect();
        let commitment_psbt_b64 = encode_psbt_b64(&commitment_psbt);

        let tx_graph = TxGraph::new(chunks).map_err(|e| format!("TxGraph::new: {e}"))?;
        self.tx_graph = Some(tx_graph);
        self.commitment_psbt = Some(commitment_psbt);

        Ok(SettleAction::NeedTreeNonces {
            tree_tx_chunks,
            commitment_psbt_b64,
        })
    }

    /// Submit the guest-generated tree nonces to the ASP.
    #[cfg(feature = "client")]
    pub async fn submit_tree_nonces(
        &mut self,
        asp: &mut AspClient,
        cosigner_pk_hex: String,
        nonce_map: Vec<(String, String)>,
    ) -> Result<(), String> {
        let batch_id = self.batch_id.as_ref().ok_or("no batch_id set")?.clone();
        let nonce_map: HashMap<String, String> = nonce_map.into_iter().collect();
        asp.submit_tree_nonces(&batch_id, cosigner_pk_hex, nonce_map)
            .await
            .map_err(|e| format!("submit_tree_nonces: {e}"))
    }

    /// TreeNonces (Plan A Phase 2): accumulate; once every node has nonces, return them (+ batch
    /// expiry + forfeit key) for the caller to dispatch tree-signing to the guest. `None` while
    /// still waiting. No secret is touched here — signing happens in the guest.
    pub fn on_tree_nonces(
        &mut self,
        event: proto::TreeNoncesEvent,
    ) -> Result<Option<SettleAction>, String> {
        let txid: Txid = event
            .txid
            .parse()
            .map_err(|e| format!("invalid txid {}: {e}", event.txid))?;
        self.pending_nonces.insert(txid, event.nonces);

        let tx_graph = self.tx_graph.as_ref().ok_or("no tx_graph built")?;
        let expected = tx_graph.nb_of_nodes();
        eprintln!(
            "  accumulated nonces for txid={txid}, {}/{} collected",
            self.pending_nonces.len(),
            expected
        );
        if self.pending_nonces.len() < expected {
            return Ok(None);
        }

        let batch_expiry = self.batch_expiry.ok_or("no batch_expiry")?.to_consensus_u32();
        let forfeit_pk_hex = self.forfeit_pk.to_string();
        let pending_nonces: Vec<(String, Vec<(String, String)>)> = self
            .pending_nonces
            .iter()
            .map(|(txid, nonces)| {
                (
                    txid.to_string(),
                    nonces.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                )
            })
            .collect();

        Ok(Some(SettleAction::NeedTreeSign {
            pending_nonces,
            batch_expiry,
            forfeit_pk_hex,
        }))
    }

    /// Submit the guest-generated tree signatures to the ASP, then clear the accumulated nonces.
    #[cfg(feature = "client")]
    pub async fn submit_tree_signatures(
        &mut self,
        asp: &mut AspClient,
        cosigner_pk_hex: String,
        sig_map: Vec<(String, String)>,
    ) -> Result<(), String> {
        let batch_id = self.batch_id.as_ref().ok_or("no batch_id set")?.clone();
        let sig_map: HashMap<String, String> = sig_map.into_iter().collect();
        asp.submit_tree_signatures(&batch_id, cosigner_pk_hex, sig_map)
            .await
            .map_err(|e| format!("submit_tree_signatures: {e}"))?;
        self.pending_nonces.clear();
        Ok(())
    }

    pub fn handle_tree_tx(&mut self, event: proto::TreeTxEvent) -> Result<(), String> {
        let psbt = decode_psbt_b64(&event.tx)?;

        let children: HashMap<u32, Txid> = event
            .children
            .into_iter()
            .map(|(vout, txid_str)| {
                let txid: Txid = txid_str
                    .parse()
                    .map_err(|e| format!("invalid child txid: {e}"))?;
                Ok((vout, txid))
            })
            .collect::<Result<_, String>>()?;

        let txid = if event.txid.is_empty() {
            None
        } else {
            Some(
                event
                    .txid
                    .parse()
                    .map_err(|e| format!("invalid txid: {e}"))?,
            )
        };

        self.tx_graph_chunks.push(TxGraphChunk {
            txid,
            tx: psbt,
            children,
        });

        Ok(())
    }

    pub fn handle_batch_finalization(
        &mut self,
        event: proto::BatchFinalizationEvent,
    ) -> Result<Vec<[u8; 32]>, String> {
        // Decode the commitment PSBT from the finalization event.
        let commitment_psbt = decode_psbt_b64(&event.commitment_tx)?;

        let (forfeit_script, forfeit_cb) = self.boarding_output.forfeit_spend_info();
        let boarding_outpoint = self.onchain_input.outpoint();

        let prevouts: Vec<TxOut> = commitment_psbt
            .inputs
            .iter()
            .filter_map(|i| i.witness_utxo.clone())
            .collect();

        let mut sighashes = Vec::new();
        let mut sighash_meta = Vec::new();

        // Find our boarding input(s) in the commitment PSBT and compute sighashes.
        for (i, _psbt_input) in commitment_psbt.inputs.iter().enumerate() {
            let prev_outpoint = commitment_psbt.unsigned_tx.input[i].previous_output;

            if prev_outpoint == boarding_outpoint {
                let leaf_version = forfeit_cb.leaf_version;
                let leaf_hash = TapLeafHash::from_script(&forfeit_script, leaf_version);
                let prevs = Prevouts::All(&prevouts);

                let tap_sighash = SighashCache::new(&commitment_psbt.unsigned_tx)
                    .taproot_script_spend_signature_hash(
                        i,
                        &prevs,
                        leaf_hash,
                        TapSighashType::Default,
                    )
                    .map_err(|e| format!("commitment sighash: {e}"))?;

                sighashes.push(tap_sighash.to_raw_hash().to_byte_array());
                sighash_meta.push((i, leaf_hash));
            }
        }

        if sighashes.is_empty() {
            return Err("boarding input not found in commitment PSBT".into());
        }

        // Store the commitment PSBT and sighash metadata.
        // Also insert tap_scripts for our inputs so finalization can proceed.
        let mut commitment_psbt = commitment_psbt;
        for &(input_idx, _) in &sighash_meta {
            let leaf_version = forfeit_cb.leaf_version;
            commitment_psbt.inputs[input_idx].tap_scripts.insert(
                forfeit_cb.clone(),
                (forfeit_script.clone(), leaf_version),
            );
        }

        self.commitment_psbt = Some(commitment_psbt);
        self.commitment_sighash_meta = sighash_meta;
        self.phase = Phase::AwaitingCommitmentSignatures;

        Ok(sighashes)
    }

    // ----- guest-driveable step API (Plan A: the GUEST drives the boarding settle itself,
    // mirroring DelegateSettleSession; the host relays the two FROST rounds) -----

    /// Insert the FROST signatures over the intent-proof sighashes (from `new_boarding`), so the
    /// proof is ready to register. Mirrors the insert half of `register_with_signatures`.
    pub fn insert_intent_signatures(&mut self, signatures: Vec<[u8; 64]>) -> Result<(), String> {
        if !matches!(self.phase, Phase::AwaitingIntentSignatures) {
            return Err("insert_intent_signatures called in wrong phase".into());
        }
        let proof_psbt = self
            .intent_proof_psbt
            .as_mut()
            .ok_or("missing intent proof PSBT")?;
        if signatures.len() != self.intent_sighash_meta.len() {
            return Err(format!(
                "expected {} intent sigs, got {}",
                self.intent_sighash_meta.len(),
                signatures.len()
            ));
        }
        for (sig_bytes, (input_idx, leaf_hash)) in
            signatures.iter().zip(self.intent_sighash_meta.iter())
        {
            let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
                .map_err(|e| format!("invalid schnorr sig: {e}"))?;
            let sig = taproot::Signature {
                signature: schnorr_sig,
                sighash_type: TapSighashType::Default,
            };
            proof_psbt.inputs[*input_idx]
                .tap_script_sigs
                .insert((self.owner_pk, *leaf_hash), sig);
        }
        self.phase = Phase::Driving;
        Ok(())
    }

    /// The registration payload `(proof_b64, message_json, topics)` for `RegisterIntent` +
    /// `GetEventStream` — topics are the boarding outpoint + the cosigner pubkey hex.
    pub fn register_payload(&self) -> Result<(String, String, Vec<String>), String> {
        let proof_psbt = self
            .intent_proof_psbt
            .as_ref()
            .ok_or("missing intent proof PSBT")?;
        let proof_b64 = encode_psbt_b64(proof_psbt);
        let message_json = self
            .intent_message
            .as_ref()
            .ok_or("missing intent message")?
            .encode()
            .map_err(|e| format!("encode intent message: {e}"))?;
        let outpoint_topic = self.onchain_input.outpoint().to_string();
        let cosigner_topic: String = self
            .cosigner_pk
            .serialize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok((proof_b64, message_json, vec![outpoint_topic, cosigner_topic]))
    }

    /// BatchStarted: record batch id + expiry. (The guest then sends ConfirmRegistration itself.)
    pub fn on_batch_started(&mut self, event: proto::BatchStartedEvent) -> Result<(), String> {
        self.batch_id = Some(event.id.clone());
        if event.batch_expiry > 0 {
            self.batch_expiry = Some(
                ark_core::server::parse_sequence_number(event.batch_expiry)
                    .map_err(|e| format!("parse batch_expiry: {e}"))?,
            );
        }
        Ok(())
    }

    /// Insert the FROST signatures over the commitment sighashes (from `handle_batch_finalization`)
    /// and return the signed commitment PSBT b64 to submit (`SubmitSignedForfeitTxs`, no forfeits).
    pub fn insert_commitment_signatures(
        &mut self,
        signatures: Vec<[u8; 64]>,
    ) -> Result<String, String> {
        if !matches!(self.phase, Phase::AwaitingCommitmentSignatures) {
            return Err("insert_commitment_signatures called in wrong phase".into());
        }
        let commitment_psbt = self
            .commitment_psbt
            .as_mut()
            .ok_or("missing commitment PSBT")?;
        if signatures.len() != self.commitment_sighash_meta.len() {
            return Err(format!(
                "expected {} commitment sigs, got {}",
                self.commitment_sighash_meta.len(),
                signatures.len()
            ));
        }
        for (sig_bytes, (input_idx, leaf_hash)) in
            signatures.iter().zip(self.commitment_sighash_meta.iter())
        {
            let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
                .map_err(|e| format!("invalid schnorr sig: {e}"))?;
            let sig = taproot::Signature {
                signature: schnorr_sig,
                sighash_type: TapSighashType::Default,
            };
            commitment_psbt.inputs[*input_idx]
                .tap_script_sigs
                .insert((self.owner_pk, *leaf_hash), sig);
        }
        let signed_commitment_b64 = encode_psbt_b64(commitment_psbt);
        self.phase = Phase::Driving;
        Ok(signed_commitment_b64)
    }

    /// The current batch id (for the guest's `SubmitTreeNonces`/`SubmitTreeSignatures`).
    pub fn batch_id(&self) -> String {
        self.batch_id.clone().unwrap_or_default()
    }

    /// After submitting the signed commitment, return the new VTXO WITHOUT waiting for a
    /// BatchFinalized event — the commitment txid is the commitment-PSBT txid (witness-independent)
    /// and the VTXO is the first tree leaf. Lets the guest finalize boarding without resuming the
    /// (now mid-batch) event stream across the commitment-FROST pause.
    pub fn finalize_optimistic(&self) -> Result<(String, Option<(String, u32)>), String> {
        let commitment_psbt = self.commitment_psbt.as_ref().ok_or("no commitment PSBT")?;
        let commitment_txid = commitment_psbt.unsigned_tx.compute_txid().to_string();
        let vtxo = self.tx_graph.as_ref().map(|g| {
            let leaf = first_tree_leaf(g);
            (leaf.unsigned_tx.compute_txid().to_string(), 0u32)
        });
        Ok((commitment_txid, vtxo))
    }

    /// BatchFinalized: mark done and return `(commitment_txid, vtxo_outpoint)`.
    pub fn on_batch_finalized(
        &mut self,
        event: proto::BatchFinalizedEvent,
    ) -> (String, Option<(String, u32)>) {
        self.phase = Phase::Done;
        let vtxo_outpoint = self.tx_graph.as_ref().map(|g| {
            let leaf = first_tree_leaf(g);
            (leaf.unsigned_tx.compute_txid().to_string(), 0u32)
        });
        (event.commitment_txid, vtxo_outpoint)
    }
}

// ===========================================================================
// DelegateSettleSession — settle existing VTXOs via the delegate pattern.
//
// The delegate pattern cleanly separates FROST (owner key) from MuSig2
// (tree signing):
//   Phase 1: generate_delegate() → build intent + forfeit PSBTs, return sighashes
//   Phase 2: sign_with_frost() → insert FROST signatures
//   Phase 3: settle() → register intent, drive batch with delegate cosigner key
// ===========================================================================

/// Input VTXO descriptor for delegate settle. The server passes these from
/// its VTXO store; the `DelegateSettleSession` reconstructs the `ark_core`
/// types needed for `prepare_delegate_psbts`.
pub struct DelegateVtxoInput {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    /// Whether this VTXO was already swept by the ASP.
    pub is_swept: bool,
    /// This VTXO's unilateral-exit delay (consensus sequence value). Per-input
    /// because a wallet naturally holds a mix: a boarded VTXO keeps the
    /// boarding delay while received/refreshed ones use the unilateral delay.
    pub exit_delay: u32,
}

/// Output descriptor for delegate settle.
pub struct DelegateOutput {
    /// Ark address string (bech32m encoded).
    pub ark_address: String,
    pub amount_sats: u64,
}

/// Phase of the delegate session state machine.
enum DelegatePhase {
    AwaitingSignatures,
    ReadyToSettle,
    Settling,
    Done,
}

/// A session for settling existing VTXOs using the delegate pattern.
///
/// Unlike `SettleSession` (boarding), this requires only a single round of
/// FROST signatures upfront.  The server then drives the batch autonomously
/// using its DKG private key for MuSig2 tree signing.
pub struct DelegateSettleSession {
    phase: DelegatePhase,

    // -- identity --
    owner_pk: XOnlyPublicKey,
    #[allow(dead_code)]
    asp_pk: XOnlyPublicKey,
    /// ASP's forfeit x-only public key (used for tree signing sweep scripts).
    forfeit_pk: XOnlyPublicKey,
    #[allow(dead_code)]
    network: Network,
    #[allow(dead_code)]
    exit_delay: Sequence,

    // -- delegate data --
    delegate: ark_core::batch::Delegate,
    delegate_cosigner_kp: Keypair,

    // -- sighash metadata for FROST --
    sighash_meta: Vec<SighashEntry>,

    // -- batch state --
    batch_id: Option<String>,
    batch_expiry: Option<Sequence>,
    vtxo_graph_chunks: Vec<TxGraphChunk>,
    connector_graph_chunks: Vec<TxGraphChunk>,
    vtxo_graph: Option<TxGraph>,
    nonce_kps: Option<NonceKps>,
    commitment_psbt: Option<Psbt>,
    /// Accumulated raw nonces per tree txid (from TreeNonces events).
    pending_nonces: HashMap<Txid, HashMap<String, String>>,
}

/// Tracks which PSBT and input index a sighash belongs to.
struct SighashEntry {
    /// 0 = intent proof PSBT, 1..N = forfeit PSBT index + 1
    psbt_type: usize,
    input_idx: usize,
    leaf_hash: TapLeafHash,
}

// ---------------------------------------------------------------------------
// Persistence — only valid while in `ReadyToSettle` phase.
//
// The live batch-state fields (`batch_id`, `nonce_kps`, `vtxo_graph_chunks`,
// `connector_graph_chunks`, `commitment_psbt`, `pending_nonces`) are all
// `None`/empty at `ReadyToSettle` time, so we don't persist them — they'd
// either be wrong or absent on rehydration. `nonce_kps` specifically is
// MuSig2 secret-nonce material that MUST NEVER be persisted: rehydrating
// a partially-settled session would risk nonce re-use.
//
// `delegate_cosigner_kp` is the server's MuSig2 cosigner secret. It's the
// same value as the user's `dkg-secret.<canonical>` already kept in the
// `SecretStore`. We deliberately do NOT persist it here — the cosigner-
// runtime looks it up from `SecretStore` at rehydration time and passes
// it into `from_persisted`. See GitHub issue #31 for why this matters.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedSighashEntry {
    pub psbt_type: usize,
    pub input_idx: usize,
    /// Hex of `TapLeafHash::to_byte_array()` (32 bytes).
    pub leaf_hash_hex: String,
}

/// Serializable snapshot of a `DelegateSettleSession` in `ReadyToSettle`
/// phase. Does NOT contain the cosigner secret — see module-level note.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedDelegate {
    pub owner_pk_hex: String,
    pub asp_pk_hex: String,
    pub forfeit_pk_hex: String,
    /// Network string as understood by `ark::client::parse_network` —
    /// "bitcoin", "testnet", "signet", "regtest", "mutinynet".
    pub network: String,
    /// `Sequence` consensus value for unilateral exit.
    pub exit_delay: u32,
    /// Base64-encoded PSBT.
    pub intent_proof_psbt_b64: String,
    /// JSON-encoded `IntentMessage`.
    pub intent_message_json: String,
    /// Base64-encoded forfeit PSBTs.
    pub forfeit_psbts_b64: Vec<String>,
    /// Hex of the cosigner public key (33-byte compressed).
    pub delegate_cosigner_pk_hex: String,
    pub sighash_meta: Vec<PersistedSighashEntry>,
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

// ---------------------------------------------------------------------------
// DelegateSettleSession – construction
// ---------------------------------------------------------------------------

impl DelegateSettleSession {
    /// Generate a delegate for existing VTXOs.
    ///
    /// Reconstructs `ark_core::Vtxo` objects from the provided metadata,
    /// calls `prepare_delegate_psbts`, and returns sighashes that need
    /// FROST signing (intent proof + all forfeit PSBTs).
    pub fn generate_delegate(
        owner_pk_hex: &str,
        asp_pk_hex: &str,
        forfeit_pk_hex: &str,
        delegate_cosigner_secret_hex: &str,
        vtxo_inputs: &[DelegateVtxoInput],
        outputs: &[DelegateOutput],
        forfeit_address: &str,
        dust_sats: u64,
        network_str: &str,
        // When set, the renewal time (Unix secs) the delegate becomes valid;
        // arkd rejects settling before it, and the intent never expires
        // (expire_at = 0). `None` keeps the legacy 2-minute window.
        intent_valid_at: Option<u64>,
    ) -> Result<(Self, Vec<[u8; 32]>), String> {
        let secp = Secp256k1::new();
        let network = parse_network(network_str)?;

        let owner_pk = parse_xonly(owner_pk_hex)?;
        let asp_pk = parse_xonly(asp_pk_hex)?;
        let forfeit_pk = parse_xonly(forfeit_pk_hex)?;

        if vtxo_inputs.is_empty() {
            return Err("no VTXO inputs".to_string());
        }

        // Build delegate cosigner keypair from server's DKG secret.
        let cosigner_secret_bytes = hex_decode_32(delegate_cosigner_secret_hex)?;
        let cosigner_secret = bitcoin::secp256k1::SecretKey::from_slice(&cosigner_secret_bytes)
            .map_err(|e| format!("invalid delegate cosigner secret: {e}"))?;
        let delegate_cosigner_kp = Keypair::from_secret_key(&secp, &cosigner_secret);
        let delegate_cosigner_pk = delegate_cosigner_kp.public_key();

        // Reconstruct default VTXOs for spend info — one per DISTINCT exit
        // delay, since each input's script embeds its own delay.
        let mut vtxo_by_delay: HashMap<u32, (Sequence, ark_core::Vtxo)> = HashMap::new();
        for vi in vtxo_inputs {
            if let std::collections::hash_map::Entry::Vacant(slot) =
                vtxo_by_delay.entry(vi.exit_delay)
            {
                let exit_seq = ark_core::server::parse_sequence_number(vi.exit_delay as i64)
                    .map_err(|e| format!("invalid exit_delay: {e}"))?;
                let vtxo =
                    ark_core::Vtxo::new_default(&secp, asp_pk, owner_pk, exit_seq, network)
                        .map_err(|e| format!("Vtxo::new_default: {e}"))?;
                slot.insert((exit_seq, vtxo));
            }
        }

        // Build intent::Input for each VTXO with its own delay's spend info.
        let intent_inputs: Vec<ark_core::intent::Input> = vtxo_inputs
            .iter()
            .map(|vi| {
                let outpoint = OutPoint {
                    txid: vi.txid.parse().map_err(|e| format!("invalid txid: {e}"))?,
                    vout: vi.vout,
                };
                let (exit_seq, vtxo) = &vtxo_by_delay[&vi.exit_delay];
                let forfeit_spend_info = vtxo
                    .forfeit_spend_info()
                    .map_err(|e| format!("forfeit_spend_info: {e}"))?;
                Ok(ark_core::intent::Input::new(
                    outpoint,
                    *exit_seq,
                    None,
                    TxOut {
                        value: Amount::from_sat(vi.amount_sats),
                        script_pubkey: vtxo.script_pubkey(),
                    },
                    vtxo.tapscripts(),
                    forfeit_spend_info,
                    false, // is_onchain = false (existing VTXOs)
                    vi.is_swept,
                    Vec::new(), // assets — none (ark-core 0.9)
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;

        // Build intent::Output for each destination.
        let intent_outputs: Vec<ark_core::intent::Output> = outputs
            .iter()
            .map(|o| {
                let ark_addr: ark_core::ArkAddress = o.ark_address.parse()
                    .map_err(|e| format!("invalid ark address: {e}"))?;
                Ok(ark_core::intent::Output::Offchain(TxOut {
                    value: Amount::from_sat(o.amount_sats),
                    script_pubkey: ark_addr.to_p2tr_script_pubkey(),
                }))
            })
            .collect::<Result<Vec<_>, String>>()?;

        // Parse forfeit address.
        let forfeit_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            forfeit_address.parse()
                .map_err(|e| format!("invalid forfeit address: {e}"))?;
        let forfeit_addr = forfeit_addr.require_network(network)
            .map_err(|e| format!("forfeit address network mismatch: {e}"))?;

        // Prepare delegate PSBTs (intent proof + forfeit PSBTs).
        let delegate = ark_core::batch::prepare_delegate_psbts_at(
            intent_inputs,
            intent_outputs,
            delegate_cosigner_pk,
            &forfeit_addr,
            Amount::from_sat(dust_sats),
            intent_valid_at,
        ).map_err(|e| format!("prepare_delegate_psbts_at: {e}"))?;

        // Compute all sighashes that need FROST signing.
        let mut sighashes = Vec::new();
        let mut sighash_meta = Vec::new();

        // Intent proof PSBT sighashes.
        Self::collect_psbt_sighashes(
            &delegate.intent.proof,
            0, // psbt_type = intent
            &mut sighashes,
            &mut sighash_meta,
        )?;

        // Forfeit PSBT sighashes.
        for (fi, forfeit_psbt) in delegate.forfeit_psbts.iter().enumerate() {
            Self::collect_forfeit_psbt_sighashes(
                forfeit_psbt,
                fi + 1, // psbt_type = forfeit index + 1
                &mut sighashes,
                &mut sighash_meta,
            )?;
        }

        let session = DelegateSettleSession {
            phase: DelegatePhase::AwaitingSignatures,
            owner_pk,
            asp_pk,
            forfeit_pk,
            network,
            // Unused downstream (the PSBTs embed per-input spend info); kept
            // for the persisted-snapshot shape. First input's delay.
            exit_delay: vtxo_by_delay[&vtxo_inputs[0].exit_delay].0,
            delegate,
            delegate_cosigner_kp,
            sighash_meta,
            batch_id: None,
            batch_expiry: None,
            vtxo_graph_chunks: Vec::new(),
            connector_graph_chunks: Vec::new(),
            vtxo_graph: None,
            nonce_kps: None,
            commitment_psbt: None,
            pending_nonces: HashMap::new(),
        };

        Ok((session, sighashes))
    }

    /// Compute taproot script-path sighashes for intent proof PSBT inputs.
    fn collect_psbt_sighashes(
        psbt: &Psbt,
        psbt_type: usize,
        sighashes: &mut Vec<[u8; 32]>,
        meta: &mut Vec<SighashEntry>,
    ) -> Result<(), String> {
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .filter_map(|i| i.witness_utxo.clone())
            .collect();

        for (i, psbt_input) in psbt.inputs.iter().enumerate() {
            let (_, (script, leaf_version)) = match psbt_input.tap_scripts.first_key_value() {
                Some(kv) => kv,
                None => continue, // skip inputs without tap_scripts
            };

            let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
            let prevs = Prevouts::All(&prevouts);

            let tap_sighash = SighashCache::new(&psbt.unsigned_tx)
                .taproot_script_spend_signature_hash(
                    i,
                    &prevs,
                    leaf_hash,
                    TapSighashType::Default,
                )
                .map_err(|e| format!("intent sighash error input {i}: {e}"))?;

            sighashes.push(tap_sighash.to_raw_hash().to_byte_array());
            meta.push(SighashEntry {
                psbt_type,
                input_idx: i,
                leaf_hash,
            });
        }
        Ok(())
    }

    /// Compute taproot script-path sighashes for forfeit PSBT inputs
    /// (using SIGHASH_ALL | ANYONECANPAY).
    fn collect_forfeit_psbt_sighashes(
        psbt: &Psbt,
        psbt_type: usize,
        sighashes: &mut Vec<[u8; 32]>,
        meta: &mut Vec<SighashEntry>,
    ) -> Result<(), String> {
        // Forfeit PSBTs have a single VTXO input at index 0.
        if psbt.inputs.is_empty() {
            return Ok(());
        }

        let psbt_input = &psbt.inputs[0];
        let (_, (script, leaf_version)) = psbt_input
            .tap_scripts
            .first_key_value()
            .ok_or("forfeit PSBT missing tap_scripts")?;

        let leaf_hash = TapLeafHash::from_script(script, *leaf_version);

        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .filter_map(|i| i.witness_utxo.clone())
            .collect();
        let prevs = Prevouts::All(&prevouts);

        let tap_sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_script_spend_signature_hash(
                0,
                &prevs,
                leaf_hash,
                TapSighashType::AllPlusAnyoneCanPay,
            )
            .map_err(|e| format!("forfeit sighash error: {e}"))?;

        sighashes.push(tap_sighash.to_raw_hash().to_byte_array());
        meta.push(SighashEntry {
            psbt_type,
            input_idx: 0,
            leaf_hash,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DelegateSettleSession – FROST signature insertion
// ---------------------------------------------------------------------------

impl DelegateSettleSession {
    /// The batch this session joined, or `None` before a matching `BatchStarted`.
    /// Callers driving the event stream gate batch-scoped events on this — see
    /// [`foreign_batch_id`].
    pub fn joined_batch_id(&self) -> Option<&str> {
        self.batch_id.as_deref()
    }

    /// Insert FROST signatures into the intent proof and forfeit PSBTs.
    ///
    /// `signatures` must match the sighashes returned by `generate_delegate`.
    pub fn sign_with_frost(
        &mut self,
        signatures: Vec<[u8; 64]>,
    ) -> Result<(), String> {
        if !matches!(self.phase, DelegatePhase::AwaitingSignatures) {
            return Err("sign_with_frost called in wrong phase".into());
        }
        if signatures.len() != self.sighash_meta.len() {
            return Err(format!(
                "expected {} signatures, got {}",
                self.sighash_meta.len(),
                signatures.len()
            ));
        }

        for (sig_bytes, entry) in signatures.iter().zip(self.sighash_meta.iter()) {
            let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
                .map_err(|e| format!("invalid schnorr sig: {e}"))?;

            let sighash_type = if entry.psbt_type == 0 {
                TapSighashType::Default
            } else {
                TapSighashType::AllPlusAnyoneCanPay
            };

            let sig = taproot::Signature {
                signature: schnorr_sig,
                sighash_type,
            };

            let psbt_input = if entry.psbt_type == 0 {
                &mut self.delegate.intent.proof.inputs[entry.input_idx]
            } else {
                let fi = entry.psbt_type - 1;
                &mut self.delegate.forfeit_psbts[fi].inputs[entry.input_idx]
            };

            psbt_input
                .tap_script_sigs
                .insert((self.owner_pk, entry.leaf_hash), sig);
        }

        self.phase = DelegatePhase::ReadyToSettle;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DelegateSettleSession – persistence (ReadyToSettle phase only)
// ---------------------------------------------------------------------------

impl DelegateSettleSession {
    /// Serialize a session in `ReadyToSettle` phase for sled storage.
    ///
    /// Refuses for any other phase: persisting `AwaitingSignatures` would
    /// drop FROST sigs the client paid to compute, and persisting `Settling`
    /// would expose MuSig2 secret nonces in `nonce_kps`. The cosigner-
    /// runtime calls this from `settle_delegate` Phase 2 (store_only) after
    /// `sign_with_frost` has moved the session to `ReadyToSettle`.
    pub fn to_persisted(&self) -> Result<PersistedDelegate, String> {
        if !matches!(self.phase, DelegatePhase::ReadyToSettle) {
            return Err(format!(
                "to_persisted requires ReadyToSettle phase, got {:?}",
                std::mem::discriminant(&self.phase)
            ));
        }

        let intent_proof_b64 = self.delegate.intent.serialize_proof();
        let intent_message_json = self
            .delegate
            .intent
            .serialize_message()
            .map_err(|e| format!("serialize intent message: {e}"))?;

        let forfeit_psbts_b64 = self
            .delegate
            .forfeit_psbts
            .iter()
            .map(|p| b64_encode(&p.serialize()))
            .collect();

        let delegate_cosigner_pk_hex = hex::encode(
            self.delegate
                .delegate_cosigner_pk
                .serialize(),
        );

        let sighash_meta = self
            .sighash_meta
            .iter()
            .map(|e| PersistedSighashEntry {
                psbt_type: e.psbt_type,
                input_idx: e.input_idx,
                leaf_hash_hex: hex::encode(e.leaf_hash.to_byte_array()),
            })
            .collect();

        Ok(PersistedDelegate {
            owner_pk_hex: self.owner_pk.to_string(),
            asp_pk_hex: self.asp_pk.to_string(),
            forfeit_pk_hex: self.forfeit_pk.to_string(),
            network: self.network.to_string(),
            exit_delay: self.exit_delay.to_consensus_u32(),
            intent_proof_psbt_b64: intent_proof_b64,
            intent_message_json,
            forfeit_psbts_b64,
            delegate_cosigner_pk_hex,
            sighash_meta,
        })
    }

    /// Reconstruct a `ReadyToSettle` session from a `PersistedDelegate` +
    /// the cosigner secret looked up out-of-band from the `SecretStore`.
    ///
    /// The persisted record deliberately doesn't carry the secret — see
    /// the module-level note and GitHub issue #31 for the security
    /// rationale.
    pub fn from_persisted(
        p: &PersistedDelegate,
        delegate_cosigner_secret_hex: &str,
    ) -> Result<Self, String> {
        let owner_pk = XOnlyPublicKey::from_str(&p.owner_pk_hex)
            .map_err(|e| format!("parse owner_pk: {e}"))?;
        let asp_pk = XOnlyPublicKey::from_str(&p.asp_pk_hex)
            .map_err(|e| format!("parse asp_pk: {e}"))?;
        let forfeit_pk = XOnlyPublicKey::from_str(&p.forfeit_pk_hex)
            .map_err(|e| format!("parse forfeit_pk: {e}"))?;
        let network =
            Network::from_str(&p.network).map_err(|e| format!("parse network: {e}"))?;
        let exit_delay = Sequence::from_consensus(p.exit_delay);

        let intent_proof_bytes = b64_decode(&p.intent_proof_psbt_b64)?;
        let intent_proof = Psbt::deserialize(&intent_proof_bytes)
            .map_err(|e| format!("deserialize intent proof PSBT: {e}"))?;
        let intent_message: IntentMessage = serde_json::from_str(&p.intent_message_json)
            .map_err(|e| format!("parse intent message JSON: {e}"))?;
        let intent = ark_core::intent::Intent::new(intent_proof, intent_message);

        let forfeit_psbts: Result<Vec<Psbt>, String> = p
            .forfeit_psbts_b64
            .iter()
            .map(|s| {
                let bytes = b64_decode(s)?;
                Psbt::deserialize(&bytes)
                    .map_err(|e| format!("deserialize forfeit PSBT: {e}"))
            })
            .collect();
        let forfeit_psbts = forfeit_psbts?;

        let delegate_cosigner_pk_bytes = hex::decode(&p.delegate_cosigner_pk_hex)
            .map_err(|e| format!("decode cosigner pk hex: {e}"))?;
        let delegate_cosigner_pk =
            bitcoin::secp256k1::PublicKey::from_slice(&delegate_cosigner_pk_bytes)
                .map_err(|e| format!("parse cosigner pk: {e}"))?;

        let cosigner_secret_bytes = hex_decode_32(delegate_cosigner_secret_hex)?;
        let secp = Secp256k1::new();
        let cosigner_secret = bitcoin::secp256k1::SecretKey::from_slice(&cosigner_secret_bytes)
            .map_err(|e| format!("parse cosigner secret: {e}"))?;
        let delegate_cosigner_kp = Keypair::from_secret_key(&secp, &cosigner_secret);
        // Sanity check: the persisted pubkey must match the one derivable
        // from the secret we got from SecretStore. If they diverge, the
        // delegate was stored under a different user's identity (or the
        // SecretStore is corrupt). Refuse rather than sign with the wrong
        // key.
        if delegate_cosigner_kp.public_key() != delegate_cosigner_pk {
            return Err(
                "delegate cosigner secret does not match persisted pubkey".into(),
            );
        }

        let sighash_meta = p
            .sighash_meta
            .iter()
            .map(|e| {
                let bytes = hex::decode(&e.leaf_hash_hex)
                    .map_err(|err| format!("decode leaf_hash hex: {err}"))?;
                if bytes.len() != 32 {
                    return Err(format!(
                        "leaf_hash must be 32 bytes, got {}",
                        bytes.len()
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(SighashEntry {
                    psbt_type: e.psbt_type,
                    input_idx: e.input_idx,
                    leaf_hash: TapLeafHash::from_byte_array(arr),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(Self {
            phase: DelegatePhase::ReadyToSettle,
            owner_pk,
            asp_pk,
            forfeit_pk,
            network,
            exit_delay,
            delegate: ark_core::batch::Delegate {
                intent,
                forfeit_psbts,
                delegate_cosigner_pk,
            },
            delegate_cosigner_kp,
            sighash_meta,
            batch_id: None,
            batch_expiry: None,
            vtxo_graph_chunks: Vec::new(),
            connector_graph_chunks: Vec::new(),
            vtxo_graph: None,
            nonce_kps: None,
            commitment_psbt: None,
            pending_nonces: HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// DelegateSettleSession – batch driving, transport-free step methods.
//
// These are the signing-available halves of `settle()`: each consumes one
// decoded batch event, runs the MuSig2 / forfeit math (using the secret
// cosigner key + nonces), mutates session state, and RETURNS the unary gRPC
// payload to submit (if any) — without doing any I/O. The WASM guest drives
// the event loop (ServerStream + grpc::unary) over these; the host's `settle()`
// (below) inlines both halves against `AspClient`.
// ---------------------------------------------------------------------------
impl DelegateSettleSession {
    /// Pre-loop: the registration payload `(proof_b64, message_json)` and the
    /// event-stream topics (VTXO input outpoints + cosigner pubkey hex).
    pub fn register_payload(&self) -> Result<(String, String, Vec<String>), String> {
        let proof_b64 = encode_psbt_b64(&self.delegate.intent.proof);
        let message_json = self
            .delegate
            .intent
            .serialize_message()
            .map_err(|e| format!("serialize intent message: {e}"))?;

        let mut topics = Vec::new();
        for input in &self.delegate.intent.proof.unsigned_tx.input {
            topics.push(input.previous_output.to_string());
        }
        let cosigner_bytes = self.delegate_cosigner_kp.public_key().serialize();
        let cosigner_topic: String = cosigner_bytes.iter().map(|b| format!("{b:02x}")).collect();
        topics.push(cosigner_topic);

        Ok((proof_b64, message_json, topics))
    }

    /// BatchStarted: record batch id + expiry. The guest then submits
    /// ConfirmRegistration with the intent id from RegisterIntent.
    pub fn on_batch_started(&mut self, event: proto::BatchStartedEvent) -> Result<(), String> {
        self.batch_id = Some(event.id.clone());
        if event.batch_expiry > 0 {
            self.batch_expiry = Some(
                ark_core::server::parse_sequence_number(event.batch_expiry)
                    .map_err(|e| format!("parse batch_expiry: {e}"))?,
            );
        }
        Ok(())
    }

    /// TreeTx: accumulate a tree chunk into the vtxo (0) or connector (1) graph.
    pub fn on_tree_tx(&mut self, event: proto::TreeTxEvent) -> Result<(), String> {
        let psbt = decode_psbt_b64(&event.tx)?;
        let children: HashMap<u32, Txid> = event
            .children
            .into_iter()
            .map(|(vout, txid_str)| {
                let txid: Txid = txid_str
                    .parse()
                    .map_err(|e| format!("invalid child txid: {e}"))?;
                Ok((vout, txid))
            })
            .collect::<Result<_, String>>()?;
        let txid = if event.txid.is_empty() {
            None
        } else {
            Some(
                event
                    .txid
                    .parse()
                    .map_err(|e| format!("invalid txid: {e}"))?,
            )
        };
        let chunk = TxGraphChunk {
            txid,
            tx: psbt,
            children,
        };
        match event.batch_index {
            0 => self.vtxo_graph_chunks.push(chunk),
            1 => self.connector_graph_chunks.push(chunk),
            n => return Err(format!("unsupported TreeTx batch_index: {n}")),
        }
        Ok(())
    }

    /// TreeSigningStarted: build the VTXO graph, generate ephemeral nonces, and
    /// return `(batch_id, cosigner_pk_hex, nonce_map)` to submit.
    pub fn on_tree_signing_started(
        &mut self,
        event: proto::TreeSigningStartedEvent,
    ) -> Result<(String, String, HashMap<String, String>), String> {
        let commitment_psbt = decode_psbt_b64(&event.unsigned_commitment_tx)?;
        if self.vtxo_graph_chunks.is_empty() {
            return Err("no VTXO tree tx chunks collected".into());
        }
        let vtxo_graph = TxGraph::new(self.vtxo_graph_chunks.drain(..).collect())
            .map_err(|e| format!("TxGraph::new: {e}"))?;

        let cosigner_pk = self.delegate_cosigner_kp.public_key();
        let nonce_kps = {
            let mut rng = rand::thread_rng();
            generate_nonce_tree(&mut rng, &vtxo_graph, cosigner_pk, &commitment_psbt)
                .map_err(|e| format!("generate_nonce_tree: {e}"))?
        };
        let nonce_map = nonce_kps.to_nonce_pks().encode();
        let batch_id = self.batch_id.as_ref().ok_or("no batch_id")?.clone();
        let cosigner_pk_hex = cosigner_pk.to_string();

        self.nonce_kps = Some(nonce_kps);
        self.vtxo_graph = Some(vtxo_graph);
        self.commitment_psbt = Some(commitment_psbt);

        Ok((batch_id, cosigner_pk_hex, nonce_map))
    }

    /// TreeNonces: accumulate; once every tree node has nonces, MuSig2-sign all
    /// tree txs and return `(batch_id, cosigner_pk_hex, sig_map)`. Returns `None`
    /// while still waiting for more nonces.
    pub fn on_tree_nonces(
        &mut self,
        event: proto::TreeNoncesEvent,
    ) -> Result<Option<(String, String, HashMap<String, String>)>, String> {
        let txid: Txid = event
            .txid
            .parse()
            .map_err(|e| format!("invalid txid: {e}"))?;
        self.pending_nonces.insert(txid, event.nonces);

        let vtxo_graph = self.vtxo_graph.as_ref().ok_or("no vtxo_graph")?;
        let expected = vtxo_graph.nb_of_nodes();
        if self.pending_nonces.len() < expected {
            return Ok(None);
        }

        let batch_id = self.batch_id.as_ref().ok_or("no batch_id")?.clone();
        let commitment_psbt = self.commitment_psbt.as_ref().ok_or("no commitment_psbt")?;
        let nonce_kps = self.nonce_kps.as_mut().ok_or("no nonce_kps")?;
        let batch_expiry = self.batch_expiry.ok_or("no batch_expiry")?;

        let mut combined_sigs = PartialSigTree::default();
        for (tree_txid, _) in vtxo_graph.as_map() {
            let raw_nonces = self
                .pending_nonces
                .get(&tree_txid)
                .ok_or_else(|| format!("missing nonces for {tree_txid}"))?;
            let tree_tx_nonce_pks = ark_core::server::TreeTxNoncePks::decode(raw_nonces.clone())
                .map_err(|e| format!("decode TreeTxNoncePks: {e}"))?;
            let agg_nonce = aggregate_nonces(tree_tx_nonce_pks);
            let partial_sig = sign_batch_tree_tx(
                tree_txid,
                batch_expiry,
                self.forfeit_pk,
                &self.delegate_cosigner_kp,
                agg_nonce,
                vtxo_graph,
                commitment_psbt,
                nonce_kps,
            )
            .map_err(|e| format!("sign_batch_tree_tx: {e}"))?;
            combined_sigs.0.extend(partial_sig.0);
        }

        let sig_map = combined_sigs.encode();
        let cosigner_pk_hex = self.delegate_cosigner_kp.public_key().to_string();
        self.pending_nonces.clear();
        Ok(Some((batch_id, cosigner_pk_hex, sig_map)))
    }

    /// BatchFinalization: complete the delegated forfeit txs from the connector
    /// graph leaves. Returns the signed forfeit b64s to submit, or `None` when
    /// there are no connectors (nothing to forfeit).
    pub fn on_batch_finalization(
        &mut self,
        _event: proto::BatchFinalizationEvent,
    ) -> Result<Option<Vec<String>>, String> {
        if self.connector_graph_chunks.is_empty() {
            return Ok(None);
        }
        let connectors_graph = TxGraph::new(self.connector_graph_chunks.drain(..).collect())
            .map_err(|e| format!("TxGraph::new (connectors): {e}"))?;
        let connector_leaves = connectors_graph.leaves();
        let completed_forfeits = ark_core::batch::complete_delegate_forfeit_txs(
            &self.delegate.forfeit_psbts,
            &connector_leaves,
        )
        .map_err(|e| format!("complete_delegate_forfeit_txs: {e}"))?;
        let signed_forfeits: Vec<String> =
            completed_forfeits.iter().map(encode_psbt_b64).collect();
        Ok(Some(signed_forfeits))
    }

    /// BatchFinalized: mark done and return `(commitment_txid, vtxo_outpoint)`.
    pub fn on_batch_finalized(
        &mut self,
        event: proto::BatchFinalizedEvent,
    ) -> (String, Option<(String, u32)>) {
        self.phase = DelegatePhase::Done;
        let vtxo_outpoint = self.vtxo_graph.as_ref().map(|g| {
            let leaf = first_tree_leaf(g);
            (leaf.unsigned_tx.compute_txid().to_string(), 0u32)
        });
        (event.commitment_txid, vtxo_outpoint)
    }
}

// ---------------------------------------------------------------------------
// DelegateSettleSession – batch driving (ASP transport — host only)
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
impl DelegateSettleSession {
    #[cfg(feature = "client")]
    /// Drive the entire batch protocol autonomously.
    ///
    /// This registers the pre-signed intent, subscribes to the event stream,
    /// and handles all batch events including MuSig2 tree signing (using the
    /// delegate cosigner key) and forfeit completion.
    ///
    /// Returns `(commitment_txid, vtxo_outpoint)` on success.
    pub async fn settle(&mut self, asp: &mut AspClient) -> Result<(String, Option<(String, u32)>), String> {
        if !matches!(self.phase, DelegatePhase::ReadyToSettle) {
            return Err("settle called in wrong phase".into());
        }
        self.phase = DelegatePhase::Settling;

        // Register the pre-signed intent.
        let proof_b64 = encode_psbt_b64(&self.delegate.intent.proof);
        let message_json = self.delegate.intent.serialize_message()
            .map_err(|e| format!("serialize intent message: {e}"))?;

        let intent_id = asp
            .register_intent(proof_b64, message_json)
            .await
            .map_err(|e| format!("register_intent: {e}"))?;

        // Open event stream with VTXO outpoint + cosigner key topics.
        let mut topics = Vec::new();

        // Add VTXO input outpoints as topics.
        for input in &self.delegate.intent.proof.unsigned_tx.input {
            topics.push(input.previous_output.to_string());
        }

        // Add cosigner public key as hex topic.
        let cosigner_bytes = self.delegate_cosigner_kp.public_key().serialize();
        let cosigner_topic: String = cosigner_bytes.iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        topics.push(cosigner_topic);

        eprintln!("delegate: event stream topics: {topics:?}");

        let mut stream = asp
            .get_event_stream(topics)
            .await
            .map_err(|e| format!("get_event_stream: {e}"))?;

        // Event loop.
        use tokio_stream::StreamExt;
        loop {
            let msg = stream
                .next()
                .await
                .ok_or("event stream ended unexpectedly")?
                .map_err(|e| format!("stream error: {e}"))?;

            let event = match msg.event {
                Some(e) => e,
                None => continue,
            };

            // Same gate as SettleSession::drive — a foreign batch's Tree*/Finalized/
            // Failed events must not drive or abort this session.
            if let Some(other) =
                foreign_batch_id(&event, |id| self.batch_id.as_deref() == Some(id))
            {
                eprintln!("delegate: ignoring event for foreign batch id={other}");
                continue;
            }

            match event {
                Event::BatchStarted(e) => {
                    eprintln!("delegate: BatchStarted id={}", e.id);
                    // Only join batches our intent is actually in — see batch_includes_intent.
                    if !batch_includes_intent(&e, &intent_id) {
                        continue;
                    }
                    self.batch_id = Some(e.id.clone());
                    if e.batch_expiry > 0 {
                        self.batch_expiry = Some(
                            ark_core::server::parse_sequence_number(e.batch_expiry)
                                .map_err(|e| format!("parse batch_expiry: {e}"))?,
                        );
                    }
                    asp.confirm_registration(intent_id.clone())
                        .await
                        .map_err(|e| format!("confirm_registration: {e}"))?;
                }
                Event::TreeTx(e) => {
                    eprintln!(
                        "delegate: TreeTx batch_index={} txid={} topic={:?}",
                        e.batch_index, e.txid, e.topic
                    );
                    let psbt = decode_psbt_b64(&e.tx)?;
                    let children: HashMap<u32, Txid> = e
                        .children
                        .into_iter()
                        .map(|(vout, txid_str)| {
                            let txid: Txid = txid_str
                                .parse()
                                .map_err(|e| format!("invalid child txid: {e}"))?;
                            Ok((vout, txid))
                        })
                        .collect::<Result<_, String>>()?;
                    let txid = if e.txid.is_empty() {
                        None
                    } else {
                        Some(e.txid.parse().map_err(|e| format!("invalid txid: {e}"))?)
                    };

                    // ASP discriminates the two trees via `batch_index`:
                    //   0 → VTXO graph (refresh tree, cosigner co-signs MuSig2)
                    //   1 → connector graph (forfeit-spend tree)
                    // Matches `BatchTreeEventType::{Vtxo,Connector}` in the
                    // upstream Rust SDK at ark-grpc::client.
                    let chunk = TxGraphChunk { txid, tx: psbt, children };
                    match e.batch_index {
                        0 => self.vtxo_graph_chunks.push(chunk),
                        1 => self.connector_graph_chunks.push(chunk),
                        n => {
                            return Err(format!("unsupported TreeTx batch_index: {n}"));
                        }
                    }
                }
                Event::TreeSigningStarted(e) => {
                    eprintln!(
                        "delegate: TreeSigningStarted cosigners={} vtxo_chunks={} connector_chunks={}",
                        e.cosigners_pubkeys.len(),
                        self.vtxo_graph_chunks.len(),
                        self.connector_graph_chunks.len(),
                    );

                    let commitment_psbt = decode_psbt_b64(&e.unsigned_commitment_tx)?;

                    if self.vtxo_graph_chunks.is_empty() {
                        return Err("no VTXO tree tx chunks collected".into());
                    }

                    let vtxo_graph =
                        TxGraph::new(self.vtxo_graph_chunks.drain(..).collect())
                            .map_err(|e| format!("TxGraph::new: {e}"))?;

                    let cosigner_pk = self.delegate_cosigner_kp.public_key();
                    let nonce_kps = {
                        let mut rng = rand::thread_rng();
                        generate_nonce_tree(&mut rng, &vtxo_graph, cosigner_pk, &commitment_psbt)
                            .map_err(|e| format!("generate_nonce_tree: {e}"))?
                    };

                    let nonce_pks = nonce_kps.to_nonce_pks();
                    let nonce_map = nonce_pks.encode();
                    let batch_id = self.batch_id.as_ref().ok_or("no batch_id")?.clone();
                    let cosigner_pk_hex = cosigner_pk.to_string();

                    asp.submit_tree_nonces(&batch_id, cosigner_pk_hex, nonce_map)
                        .await
                        .map_err(|e| format!("submit_tree_nonces: {e}"))?;

                    self.nonce_kps = Some(nonce_kps);
                    self.vtxo_graph = Some(vtxo_graph);
                    self.commitment_psbt = Some(commitment_psbt);
                }
                Event::TreeNonces(e) => {
                    let txid: Txid = e.txid.parse()
                        .map_err(|e| format!("invalid txid: {e}"))?;

                    // Accumulate raw nonces per txid.
                    self.pending_nonces.insert(txid, e.nonces);

                    let vtxo_graph = self.vtxo_graph.as_ref().ok_or("no vtxo_graph")?;
                    let expected = vtxo_graph.nb_of_nodes();

                    eprintln!(
                        "delegate: TreeNonces txid={txid}, {}/{} collected",
                        self.pending_nonces.len(),
                        expected
                    );

                    // Only sign once ALL nonces collected.
                    if self.pending_nonces.len() >= expected {
                        let batch_id = self.batch_id.as_ref().ok_or("no batch_id")?.clone();
                        let commitment_psbt = self.commitment_psbt.as_ref().ok_or("no commitment_psbt")?;
                        let nonce_kps = self.nonce_kps.as_mut().ok_or("no nonce_kps")?;
                        let batch_expiry = self.batch_expiry.ok_or("no batch_expiry")?;

                        let mut combined_sigs = PartialSigTree::default();

                        for (tree_txid, _) in vtxo_graph.as_map() {
                            let raw_nonces = self.pending_nonces.get(&tree_txid)
                                .ok_or_else(|| format!("missing nonces for {tree_txid}"))?;

                            let tree_tx_nonce_pks =
                                ark_core::server::TreeTxNoncePks::decode(raw_nonces.clone())
                                    .map_err(|e| format!("decode TreeTxNoncePks: {e}"))?;
                            let agg_nonce = aggregate_nonces(tree_tx_nonce_pks);

                            let partial_sig = sign_batch_tree_tx(
                                tree_txid,
                                batch_expiry,
                                self.forfeit_pk,
                                &self.delegate_cosigner_kp,
                                agg_nonce,
                                vtxo_graph,
                                commitment_psbt,
                                nonce_kps,
                            )
                            .map_err(|e| format!("sign_batch_tree_tx: {e}"))?;

                            combined_sigs.0.extend(partial_sig.0);
                        }

                        let sig_map = combined_sigs.encode();
                        let cosigner_pk_hex = self.delegate_cosigner_kp.public_key().to_string();

                        asp.submit_tree_signatures(&batch_id, cosigner_pk_hex, sig_map)
                            .await
                            .map_err(|e| format!("submit_tree_signatures: {e}"))?;

                        self.pending_nonces.clear();
                    }
                }
                Event::TreeNoncesAggregated(_) | Event::TreeSignature(_) => {
                    // Already handled signing in TreeNonces.
                }
                Event::BatchFinalization(e) => {
                    eprintln!("delegate: BatchFinalization id={}", e.id);

                    // ark-core 0.9: a batch with no connector tree carries no
                    // delegated forfeit txs to complete — skip. Building a
                    // TxGraph from empty chunks errors otherwise. Mirrors
                    // ark-client's BatchFinalization handling.
                    if self.connector_graph_chunks.is_empty() {
                        eprintln!("delegate: no connectors — no forfeit txs to complete");
                    } else {
                        // `complete_delegate_forfeit_txs` expects the connector
                        // graph's LEAVES (the leaf txs whose outputs feed each
                        // forfeit PSBT), not all chunks. The ASP reconstructs the
                        // forfeit txid from these specific leaves; passing all
                        // chunks produces a different completed PSBT and a txid
                        // the ASP doesn't recognize.
                        let connectors_graph = TxGraph::new(
                            self.connector_graph_chunks.drain(..).collect(),
                        )
                        .map_err(|e| format!("TxGraph::new (connectors): {e}"))?;
                        let connector_leaves = connectors_graph.leaves();

                        let completed_forfeits =
                            ark_core::batch::complete_delegate_forfeit_txs(
                                &self.delegate.forfeit_psbts,
                                &connector_leaves,
                            )
                            .map_err(|e| format!("complete_delegate_forfeit_txs: {e}"))?;

                        // Serialize completed forfeits.
                        let signed_forfeits: Vec<String> = completed_forfeits
                            .iter()
                            .map(|p| encode_psbt_b64(p))
                            .collect();

                        // No commitment signing needed — forfeits handle it.
                        asp.submit_signed_forfeit_txs(signed_forfeits, String::new())
                            .await
                            .map_err(|e| format!("submit_signed_forfeit_txs: {e}"))?;
                    }
                }
                Event::BatchFinalized(e) => {
                    eprintln!("delegate: BatchFinalized txid={}", e.commitment_txid);
                    self.phase = DelegatePhase::Done;
                    let vtxo_outpoint = self.vtxo_graph.as_ref().map(|g| {
                        let leaf = first_tree_leaf(g);
                        (leaf.unsigned_tx.compute_txid().to_string(), 0u32)
                    });
                    return Ok((e.commitment_txid, vtxo_outpoint));
                }
                Event::BatchFailed(e) => {
                    return Err(format!("batch failed: {}", e.reason));
                }
                Event::Heartbeat(_) | Event::StreamStarted(_) => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_xonly(hex: &str) -> Result<XOnlyPublicKey, String> {
    // Accept both 64-char x-only and 66-char compressed.
    let hex = if hex.len() == 66 && (hex.starts_with("02") || hex.starts_with("03")) {
        &hex[2..]
    } else {
        hex
    };
    XOnlyPublicKey::from_str(hex).map_err(|e| format!("invalid x-only pubkey: {e}"))
}

fn parse_network(network: &str) -> Result<Network, String> {
    match network {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" | "testnet3" => Ok(Network::Testnet),
        "signet" | "mutinynet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(format!("unknown network: {network}")),
    }
}

fn decode_psbt_b64(b64: &str) -> Result<Psbt, String> {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new(),
    );
    let bytes = engine
        .decode(b64)
        .map_err(|e| format!("base64 decode: {e}"))?;
    Psbt::deserialize(&bytes).map_err(|e| format!("PSBT deserialize: {e}"))
}

fn encode_psbt_b64(psbt: &Psbt) -> String {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new(),
    );
    engine.encode(psbt.serialize())
}

/// Compute the BIP-322 intent message hash using the same tagged hash
/// construction as ark-core.
fn intent_message_hash(message: &[u8]) -> sha256::Hash {
    const TAG: &[u8] = b"ark-intent-proof-message";
    let hashed_tag = sha256::Hash::hash(TAG);

    let mut v = Vec::new();
    v.extend_from_slice(hashed_tag.as_byte_array());
    v.extend_from_slice(hashed_tag.as_byte_array());
    v.extend_from_slice(message);

    sha256::Hash::hash(&v)
}

/// Build the BIP-322 "to_spend" transaction for intent proofs.
fn build_to_spend_tx(message_json: &str, script_pubkey: &ScriptBuf) -> Transaction {
    let hash = intent_message_hash(message_json.as_bytes());

    let script_sig = ScriptBuf::builder()
        .push_opcode(bitcoin::opcodes::OP_0)
        .push_slice(hash.as_byte_array())
        .into_script();

    Transaction {
        version: Version::non_standard(0),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0xFFFFFFFF,
            },
            script_sig,
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script_pubkey.clone(),
        }],
    }
}

/// Encode a list of tapscripts in the format used by ark-core's PSBT
/// unknown field (key type 222, key "taptree").
///
/// Format: for each script: [depth=1] [leaf_version=0xc0] [compact_size(len)]
/// [script_bytes].
fn encode_taptree(tapscripts: &[ScriptBuf]) -> Vec<u8> {
    let mut buf = Vec::new();
    for script in tapscripts {
        buf.push(1); // depth
        buf.push(0xc0); // leaf version (base tapscript)
        write_compact_size(&mut buf, script.len() as u64);
        buf.extend(script.as_bytes());
    }
    buf
}

/// Write a Bitcoin compact-size uint.
fn write_compact_size(w: &mut Vec<u8>, val: u64) {
    if val < 253 {
        w.push(val as u8);
    } else if val < 0x10000 {
        w.push(253);
        w.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val < 0x100000000 {
        w.push(254);
        w.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        w.push(255);
        w.extend_from_slice(&val.to_le_bytes());
    }
}

/// Get the first leaf PSBT from a TxGraph.
fn first_tree_leaf(graph: &TxGraph) -> &Psbt {
    let leaves = graph.leaves();
    leaves.into_iter().next().unwrap_or_else(|| graph.root())
}

/// Decode a 64-char hex string into a 32-byte array.
fn hex_decode_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("hex decode error at byte {i}: {e}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod batch_intent_tests {
    use super::*;

    fn event(hashes: &[&str]) -> proto::BatchStartedEvent {
        proto::BatchStartedEvent {
            id: "batch-1".to_string(),
            intent_id_hashes: hashes.iter().map(|s| s.to_string()).collect(),
            batch_expiry: 0,
        }
    }

    /// Pinned against `sha256sum`, so a change in hashing shows up here rather
    /// than as an aborted batch on a live ASP.
    const TEST_INTENT: &str = "test-intent";
    const TEST_INTENT_HASH: &str =
        "c65c50e6ddaf679c703ebc2705b82498136a5e9e5fcc2ebd50376b1935689768";


    fn started(id: &str) -> Event {
        Event::BatchStarted(proto::BatchStartedEvent {
            id: id.into(),
            intent_id_hashes: vec![],
            batch_expiry: 0,
        })
    }
    fn failed(id: &str) -> Event {
        Event::BatchFailed(proto::BatchFailedEvent { id: id.into(), reason: "x".into() })
    }
    fn finalized(id: &str) -> Event {
        Event::BatchFinalized(proto::BatchFinalizedEvent {
            id: id.into(),
            commitment_txid: "deadbeef".into(),
        })
    }
    fn tree_tx(id: &str) -> Event {
        Event::TreeTx(proto::TreeTxEvent {
            id: id.into(),
            topic: vec![],
            batch_index: 0,
            txid: String::new(),
            tx: String::new(),
            children: Default::default(),
        })
    }

    /// The bug this guards: a stranger's batch failing used to abort our settle,
    /// and a stranger's batch finalizing used to be recorded as our settlement.
    #[test]
    fn foreign_batch_events_are_rejected() {
        let ours = |id: &str| id == "ours";
        assert_eq!(foreign_batch_id(&failed("theirs"), ours).as_deref(), Some("theirs"));
        assert_eq!(foreign_batch_id(&finalized("theirs"), ours).as_deref(), Some("theirs"));
        assert_eq!(foreign_batch_id(&tree_tx("theirs"), ours).as_deref(), Some("theirs"));
    }

    #[test]
    fn our_own_batch_events_pass_through() {
        let ours = |id: &str| id == "ours";
        assert!(foreign_batch_id(&failed("ours"), ours).is_none());
        assert!(foreign_batch_id(&finalized("ours"), ours).is_none());
        assert!(foreign_batch_id(&tree_tx("ours"), ours).is_none());
    }

    /// BatchStarted is filtered by intent hash instead, and establishes the id
    /// everything else is matched against, so it must never be gated here.
    #[test]
    fn batch_started_is_never_gated() {
        assert!(foreign_batch_id(&started("theirs"), |_| false).is_none());
    }

    /// Before joining a batch nothing is ours — matching the reference client,
    /// which ignores every batch event until its Step leaves Start.
    #[test]
    fn nothing_is_ours_before_joining() {
        let none = |_: &str| false;
        assert_eq!(foreign_batch_id(&finalized("any"), none).as_deref(), Some("any"));
    }

    #[test]
    fn matches_sha256_hex_of_the_intent_id() {
        assert!(batch_includes_intent(&event(&[TEST_INTENT_HASH]), TEST_INTENT));
    }

    #[test]
    fn finds_our_intent_among_other_participants() {
        let e = event(&["00".repeat(32).as_str(), TEST_INTENT_HASH, "ff".repeat(32).as_str()]);
        assert!(batch_includes_intent(&e, TEST_INTENT));
    }

    #[test]
    fn rejects_a_batch_we_are_not_in() {
        // The case that aborted boarding on mutinynet: a batch of other people's
        // intents, which we used to confirm into unconditionally.
        assert!(!batch_includes_intent(&event(&["00".repeat(32).as_str()]), TEST_INTENT));
    }

    #[test]
    fn rejects_an_empty_batch() {
        assert!(!batch_includes_intent(&event(&[]), TEST_INTENT));
    }

    #[test]
    fn does_not_match_the_raw_intent_id() {
        // arkd sends hashes, never the ids themselves.
        assert!(!batch_includes_intent(&event(&[TEST_INTENT]), TEST_INTENT));
    }
}
