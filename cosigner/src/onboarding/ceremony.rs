//! Shared FROST ceremony machinery for the DKG (`onboarding`) and contract-create
//! (`contract`) flows. Holds the round state as REAL `threshold` structs (keyed by
//! `Identifier`, which is `Ord` but not `Hash`, so `BTreeMap`), converting to/from
//! JSON only at the wire boundary (proto `map<string,string>` of id_hex → pkg_json).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use tokio::sync::oneshot;
use tonic::Status;

use threshold::dkg::{Round1Package, Round1SecretPackage, Round2Package, Round2SecretPackage};
use threshold::identifier::Identifier;
use threshold::scalar::scalar_from_bytes;

/// A parked reply for a participant waiting on a ceremony round to complete.
pub type Reply<T> = oneshot::Sender<Result<T, Status>>;


/// Fail every parked `(id, reply)` pair (step3 pools carry the sender id).
pub fn drain_pairs_with_err<K, T>(pool: &mut Vec<(K, Reply<T>)>, msg: &str) {
    for (_, s) in pool.drain(..) {
        let _ = s.send(Err(Status::aborted(msg.to_string())));
    }
}

/// The typed FROST round state shared by both ceremonies. `server_id` is the
/// cosigner's own FROST identifier (the key under which its round1 package lives).
#[derive(Default)]
pub struct CeremonyRounds {
    pub round1_packages: BTreeMap<Identifier, Round1Package>,
    /// Round2 packages addressed TO the cosigner, keyed by sender id.
    pub round2_received: BTreeMap<Identifier, Round2Package>,
    /// The cosigner's own round2 packages FOR each recipient.
    pub round2_local: BTreeMap<Identifier, Round2Package>,
    /// All round2 packages for relay: sender id → { recipient id → package }.
    pub round2_relay: BTreeMap<Identifier, BTreeMap<Identifier, Round2Package>>,
    /// Passive receivers (no round1 package). Empty in 2-of-2.
    pub receiver_identifiers: BTreeSet<Identifier>,
    pub server_id: Option<Identifier>,
    pub round1_secret: Option<Round1SecretPackage>,
    pub round2_secret: Option<Round2SecretPackage>,
}

impl CeremonyRounds {
    pub fn total_participants(&self) -> usize {
        self.round1_packages.len() + self.receiver_identifiers.len()
    }

    pub fn relay_sender_count(&self) -> usize {
        self.round2_relay.len()
    }

    pub fn is_round2_local_empty(&self) -> bool {
        self.round2_local.is_empty()
    }

    pub fn receiver_ids(&self) -> Vec<Identifier> {
        self.receiver_identifiers.iter().cloned().collect()
    }

    /// All round1 packages except the one keyed by `exclude` (the cosigner's own,
    /// when feeding `dkg_part2`/`dkg_part3`).
    pub fn round1_packages_excluding(
        &self,
        exclude: &Identifier,
    ) -> BTreeMap<Identifier, Round1Package> {
        self.round1_packages
            .iter()
            .filter(|(id, _)| *id != exclude)
            .map(|(id, pkg)| (id.clone(), pkg.clone()))
            .collect()
    }

    pub fn insert_relay_packages(
        &mut self,
        sender: Identifier,
        pkgs: BTreeMap<Identifier, Round2Package>,
    ) {
        self.round2_relay.insert(sender, pkgs);
    }

    /// Fold the cosigner's own round2 packages into the relay under its id.
    pub fn insert_relay_from_local(&mut self, server: Identifier) {
        self.round2_relay.insert(server, self.round2_local.clone());
    }

    // --- wire (egress) serializers: typed → proto `map<string,string>` ---

    /// All round1 packages as `{id_hex: pkg_json}`.
    pub fn round1_packages_wire(&self) -> HashMap<String, String> {
        self.round1_packages
            .iter()
            .map(|(id, pkg)| (hex::encode(id.serialize()), pkg.to_json()))
            .collect()
    }

    /// Round2 packages destined for `recipient`, as `{sender_id_hex: pkg_json}`.
    pub fn relay_packages_for(&self, recipient: &Identifier) -> HashMap<String, String> {
        let mut out = HashMap::new();
        for (sender, by_recipient) in &self.round2_relay {
            if let Some(pkg) = by_recipient.get(recipient) {
                out.insert(hex::encode(sender.serialize()), pkg.to_json());
            }
        }
        out
    }
}

// --- wire (ingress) + hex helpers ---

fn hex_decode_32(s: &str) -> Result<[u8; 32], Status> {
    let bytes = hex::decode(s).map_err(|e| Status::internal(format!("bad hex: {e}")))?;
    let out: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Status::internal("expected 32 bytes"))?;
    Ok(out)
}

pub fn parse_identifier_hex(hex: &str) -> Result<Identifier, Status> {
    let bytes = hex_decode_32(hex)?;
    Identifier::deserialize(&bytes).map_err(|e| Status::internal(format!("bad identifier: {e}")))
}

pub fn parse_scalar_hex(hex: &str) -> Result<k256::Scalar, Status> {
    let bytes = hex_decode_32(hex)?;
    scalar_from_bytes(&bytes).map_err(|e| Status::internal(format!("bad scalar: {e}")))
}

pub fn round1_pkg_from_json(json: &str) -> Result<Round1Package, Status> {
    Round1Package::from_json(json).map_err(|e| Status::internal(format!("bad R1 pkg: {e}")))
}

/// Parse a proto `map<string,string>` of `recipient_id_hex → round2 pkg_json` into a
/// typed map. Used at step3 ingress.
pub fn round2_pkgs_from_wire(
    wire: &HashMap<String, String>,
) -> Result<BTreeMap<Identifier, Round2Package>, Status> {
    let mut out = BTreeMap::new();
    for (id_hex, pkg_json) in wire {
        let id = parse_identifier_hex(id_hex)?;
        let pkg = Round2Package::from_json(pkg_json)
            .map_err(|e| Status::internal(format!("bad R2 pkg: {e}")))?;
        out.insert(id, pkg);
    }
    Ok(out)
}
