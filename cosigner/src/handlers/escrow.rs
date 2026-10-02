//! Minting an escrow key: the same two parties, a second key, one reshare.
//!
//! # What an escrow key is
//!
//! A wallet's own key `V` is a 2-of-2 between the phone and this cosigner. Escrowed money needs a
//! key that a *third* interest can be paid from without the payer present at settlement — but
//! handing that interest a share of `V` would hand it the whole wallet. So escrow gets a key of its
//! own:
//!
//! ```text
//!   reshare {wallet, cosigner} over V   ──▶   V' = V + Δ_wallet + Δ_cosigner
//! ```
//!
//! Both sides deal a fresh non-zero `Δ` under the identifiers they already have, and both finalize.
//! `V'` is a new key held 2-of-2 by the same pair, and `V` is untouched — the wallet keeps spending
//! from it exactly as before. Funding an escrow is then an ordinary Ark send from `V` to `V'`'s
//! address, and everything afterwards is about who may spend `V'`.
//!
//! The service is paired into `V'` separately (see the pairing handler), never into `V`. That is
//! the whole reason this ceremony exists rather than reusing the wallet's key.
//!
//! # Nothing secret at rest, here too
//!
//! A wallet keeps no share; it rebuilds one for each operation from its passkey plus the half this
//! cosigner sealed. An escrow share has to work the same way or escrowed money would be the one
//! thing a lost phone could not recover. It is built on top of the wallet share rather than beside
//! it:
//!
//! ```text
//!   s_wallet  = ±[ f_wallet(id) + dealt_share ]        checked against V's verifying share
//!   s'_wallet = ±[ s_wallet + Δ_wallet(id) + Δ_cosigner(id) ]   against V''s
//!                              \__________/   \______________/
//!                              from the passkey   one scalar, sealed here
//! ```
//!
//! **The two `±` are why this seals `Δ_cosigner(id)` alone and not its sum with `dealt_share`.**
//! Every finalizer normalises to an even-Y group key, so a normalisation sits *between* those two
//! terms: when `V` came out with odd Y the wallet's share is negated before the deltas are added,
//! and a pre-added sum would be wrong for half of all wallets — silently, and only for those half.
//! A test caught exactly that. Keep them separate.
//!
//! # What this handler is not
//!
//! It does not decide anything. Whether a release is permitted is the policy's business
//! ([`crate::policy`]); this only mints the key that a policy will later guard.

use std::collections::BTreeMap;

use rand::rngs::OsRng;

use crate::grpc::Status;

use threshold::dkg::{self, Round1Package, Round1SecretPackage, Round2Package, Round2SecretPackage};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::random;
use threshold::scalar::scalar_to_bytes;

/// A 2-of-2 reshare is degree 1: one constant term and one coefficient above it.
const THRESHOLD_COUNT: usize = 2;
const TOTAL_PARTICIPANTS: usize = 2;

/// What a finished ceremony yields, ready to seal.
pub struct EscrowMaterial {
    /// `V'`, compressed hex — the escrow's identity and the owner key of its Ark address.
    pub escrow_key: String,
    pub key_package_json: String,
    pub public_key_package_json: String,
    /// The wallet's FROST identifier, as this ceremony recorded it.
    pub wallet_identifier_hex: String,
    /// The derivation context this escrow was dealt under, hex. See `EscrowOpen.context`.
    pub context_hex: String,
    /// `Δ_cosigner(id_wallet)`, hex: this cosigner's delta share for the wallet. **Its own term,
    /// never summed with anything** — see the module note on the two normalisations. Worth nothing
    /// without the wallet share and the passkey's delta.
    pub wallet_delta_share_hex: String,
}

// Redacting `Debug`: `wallet_delta_share_hex` is a term of the owner's escrow share and
// `key_package_json` holds this cosigner's own. Neither belongs in a log or a panic message.
impl core::fmt::Debug for EscrowMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EscrowMaterial")
            .field("escrow_key", &self.escrow_key)
            .field("wallet_identifier_hex", &self.wallet_identifier_hex)
            .field("context_hex", &self.context_hex)
            .field("key_package_json", &"<redacted>")
            .field("wallet_delta_share_hex", &"<redacted>")
            .finish()
    }
}

/// The reshare, owned by one stream handler's stack.
///
/// Like the onboarding ceremony and for the same reason: the round-1 and round-2 secrets are what
/// the key is born from, and a session in a map with a TTL is a window in which they can be read.
/// Here they live on one frame and die with it.
#[derive(Default)]
pub struct EscrowSession {
    wallet_id: Option<Identifier>,
    wallet_round1: Option<Round1Package>,
    context_hex: Option<String>,
    server_id: Option<Identifier>,
    round1_secret: Option<Round1SecretPackage>,
    pub material: Option<EscrowMaterial>,
}

impl EscrowSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// Round one: take the wallet's dealing, deal ours, and hand ours back.
    ///
    /// `old_kp` is this cosigner's key package for the wallet key `V` — the reshare is dealt under
    /// the identifier it already has there, so the deltas land on the same points as the old
    /// shares.
    pub fn begin(
        &mut self,
        old_kp: &KeyPackage,
        wallet_identifier: &[u8],
        wallet_round1_json: &str,
        context: &[u8],
    ) -> Result<String, Status> {
        if self.round1_secret.is_some() {
            return Err(Status::failed_precondition("this escrow ceremony already opened"));
        }
        // Enough to be unrepeatable by accident, small enough to seal for every escrow a wallet
        // holds.
        if context.len() < 16 || context.len() > 32 {
            return Err(Status::invalid_argument(
                "an escrow derivation context must be 16 to 32 bytes",
            ));
        }

        let wallet_id = Identifier::try_from(wallet_identifier)
            .map_err(|e| Status::invalid_argument(format!("bad identifier: {e}")))?;
        let server_id = old_kp.identifier.clone();
        if wallet_id == server_id {
            // Both deltas would land on one point and the reshare would not be a sharing at all.
            return Err(Status::invalid_argument(
                "the wallet's identifier is this cosigner's own",
            ));
        }

        let wallet_round1 = Round1Package::from_json(wallet_round1_json)
            .map_err(|e| Status::invalid_argument(format!("bad round1 package: {e}")))?;

        // Our own Δ. Fresh every ceremony and from the enclave's RNG: a delta reused across two
        // escrows would put two of this cosigner's dealings on one line.
        let mut rng = OsRng;
        let secret = random::mod_n_random(&mut rng);
        let coefficients: Vec<_> = (0..THRESHOLD_COUNT - 1)
            .map(|_| random::mod_n_random(&mut rng))
            .collect();
        let (r1_secret, r1_pub) = dkg::dkg_reshare_part1(
            &server_id,
            TOTAL_PARTICIPANTS,
            THRESHOLD_COUNT,
            &secret,
            &coefficients,
            &mut rng,
        )
        .map_err(|e| Status::internal(format!("dkg_reshare_part1: {e}")))?;

        self.context_hex = Some(hex::encode(context));
        self.wallet_id = Some(wallet_id);
        self.wallet_round1 = Some(wallet_round1);
        self.server_id = Some(server_id);
        self.round1_secret = Some(r1_secret);
        Ok(r1_pub.to_json())
    }

    /// Round two: take the wallet's share of its delta, finalize `V'`, and hand back ours.
    pub fn finalise(
        &mut self,
        old_kp: &KeyPackage,
        old_pkp: &PublicKeyPackage,
        wallet_round2_json: &str,
    ) -> Result<String, Status> {
        let (wallet_id, wallet_round1, server_id, r1_secret) = match (
            self.wallet_id.take(),
            self.wallet_round1.take(),
            self.server_id.take(),
            self.round1_secret.take(),
        ) {
            (Some(w), Some(p), Some(s), Some(r)) => (w, p, s, r),
            _ => return Err(Status::failed_precondition("this escrow ceremony has not opened")),
        };

        let wallet_round2 = Round2Package::from_json(wallet_round2_json)
            .map_err(|e| Status::invalid_argument(format!("bad round2 package: {e}")))?;

        let peers_round1: BTreeMap<Identifier, Round1Package> =
            [(wallet_id.clone(), wallet_round1)].into_iter().collect();

        // Our round 2: a share of our delta for the wallet. No passive receivers — both parties
        // deal and both finalize, so `dkg_part2` is given an empty receiver list.
        let (r2_secret, our_shares): (Round2SecretPackage, BTreeMap<Identifier, Round2Package>) =
            dkg::dkg_part2(&r1_secret, &peers_round1, &[])
                .map_err(|e| Status::internal(format!("dkg_part2: {e}")))?;
        let for_wallet = our_shares
            .get(&wallet_id)
            .ok_or_else(|| Status::internal("our reshare dealt the wallet nothing"))?
            .clone();

        let peers_round2: BTreeMap<Identifier, Round2Package> =
            [(wallet_id.clone(), wallet_round2)].into_iter().collect();
        let receivers = [wallet_id.clone(), server_id];

        let (new_kp, new_pkp) = dkg::dkg_reshare_part3(
            &r2_secret,
            &peers_round1,
            &peers_round2,
            old_pkp,
            old_kp,
            &receivers,
        )
        .map_err(|e| Status::internal(format!("dkg_reshare_part3: {e}")))?;

        let kp_json = new_kp.to_json();
        let pkp_json = new_pkp.to_json();
        let escrow_key = crate::serde::extract_verifying_key(&pkp_json)?;

        self.material = Some(EscrowMaterial {
            escrow_key,
            key_package_json: kp_json,
            public_key_package_json: pkp_json,
            wallet_identifier_hex: hex::encode(wallet_id.serialize()),
            context_hex: self.context_hex.take().unwrap_or_default(),
            wallet_delta_share_hex: hex::encode(scalar_to_bytes(&for_wallet.secret_share)),
        });

        Ok(for_wallet.to_json())
    }
}
