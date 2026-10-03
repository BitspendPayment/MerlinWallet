//! A signing session: FROST carried inside the stream that needs it — see `cosigner::sign`.
//!
//! The nested form — a second `Sign` stream per sighash while the outer stream waited — deadlocks
//! inside enclave-runtime, which runs one request per tenant for the whole life of a stream. That
//! was measured against a running enclave before any of this was written. These tests are about the
//! replacement being *correct*: that one round trip for a whole batch yields signatures the chain
//! accepts, and that everything which should be refused is.
//!
//! Signatures are checked with `bitcoin::secp256k1`'s BIP-340 verifier, not with this repository's
//! own `Signature::verify` — a test that verifies with the code that signed proves the two agree
//! with each other, not that either speaks BIP-340.

mod common;

use std::collections::BTreeMap;

use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
use rand::rngs::OsRng;

use cosigner::sign::{SigningSession, WalletHalf};
use cosigner::types::Commitment;

use threshold::commitment::SigningPackage;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments};
use threshold::point;
use threshold::scalar::scalar_to_bytes;
use threshold::signing;

/// The wallet's half of every message: a fresh nonce, then a share over both commitments.
fn wallet_answers(
    kp_user: &KeyPackage,
    messages: &[Vec<u8>],
    cosigner_commitments: &[Commitment],
) -> Vec<WalletHalf> {
    let mut rng = OsRng;
    messages
        .iter()
        .zip(cosigner_commitments)
        .map(|(message, theirs)| {
            let ours = nonce::new_nonce(&mut rng, &kp_user.secret_share);

            let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
            let id: [u8; 32] = hex::decode(&theirs.identifier_hex).unwrap().try_into().unwrap();
            commitments.insert(
                Identifier::deserialize(&id).unwrap(),
                SigningCommitments {
                    hiding: point::deserialize_compressed(&theirs.hiding.clone().try_into().unwrap())
                        .unwrap(),
                    binding: point::deserialize_compressed(
                        &theirs.binding.clone().try_into().unwrap(),
                    )
                    .unwrap(),
                },
            );
            commitments.insert(kp_user.identifier.clone(), ours.commitments.clone());

            let package = SigningPackage::new(commitments, message.clone());
            let share = signing::sign(&package, &ours, kp_user).expect("wallet share");
            WalletHalf {
                hiding: point::serialize_compressed(&ours.commitments.hiding).to_vec(),
                binding: point::serialize_compressed(&ours.commitments.binding).to_vec(),
                share: scalar_to_bytes(&share.s).to_vec(),
            }
        })
        .collect()
}

/// A BIP-340 verification of a 64-byte `R.x ‖ z` under the group key, x-only.
fn bip340_ok(pkp: &PublicKeyPackage, message: &[u8], signature: &[u8]) -> bool {
    let secp = Secp256k1::verification_only();
    let key = XOnlyPublicKey::from_slice(&pkp.verifying_key.serialize()[1..]).unwrap();
    let sig = schnorr::Signature::from_slice(signature).unwrap();
    let digest: [u8; 32] = message.try_into().expect("sighashes are 32 bytes");
    secp.verify_schnorr(&sig, &Message::from_digest(digest), &key).is_ok()
}

fn seeded() -> Option<(cosigner::Cosigner, Vec<KeyPackage>, PublicKeyPackage)> {
    let store = common::try_store()?;
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp);
    Some((cosigner.into_inner().unwrap(), kps, pkp))
}

/// Round one over [messages], with the wallet's own key.
fn begin(cosigner: &cosigner::Cosigner, messages: &[Vec<u8>]) -> (SigningSession, Vec<Commitment>) {
    SigningSession::begin(cosigner.signing_key().expect("a key"), messages)
}

/// Three sighashes, one round trip, three signatures the chain would accept.
#[test]
fn a_batch_signs_in_one_round_trip() {
    let Some((cosigner, kps, pkp)) = seeded() else { return };
    let messages: Vec<Vec<u8>> = (0u8..3).map(|i| vec![0x40 + i; 32]).collect();

    let (round, theirs) = begin(&cosigner, &messages);
    assert_eq!(theirs.len(), 3, "one commitment per message");

    let ours = wallet_answers(&kps[0], &messages, &theirs);
    let signatures = round.finish(ours).expect("finish");

    assert_eq!(signatures.len(), 3);
    for (i, (message, signature)) in messages.iter().zip(&signatures).enumerate() {
        assert_eq!(signature.len(), 64, "message {i}: BIP-340 is 64 bytes");
        assert!(
            bip340_ok(&pkp, message, signature),
            "message {i}: the aggregate must verify as BIP-340 under the group key"
        );
    }
}

/// Signatures are bound to their own message. Swapping two in a batch must not verify — which is
/// what proves the order the wallet answers in actually carries meaning.
#[test]
fn each_signature_belongs_to_its_own_message() {
    let Some((cosigner, kps, pkp)) = seeded() else { return };
    let messages: Vec<Vec<u8>> = vec![vec![0x11; 32], vec![0x22; 32]];

    let (round, theirs) = begin(&cosigner, &messages);
    let signatures = round
        .finish(wallet_answers(&kps[0], &messages, &theirs))
        .expect("finish");

    assert!(bip340_ok(&pkp, &messages[0], &signatures[0]));
    assert!(!bip340_ok(&pkp, &messages[0], &signatures[1]), "a signature must not transfer");
}

/// A share for the wrong message is refused at aggregation, and the error says which message.
///
/// Before, a bad share surfaced as the ASP rejecting a transaction with nothing useful to say.
#[test]
fn a_bad_share_is_refused_and_named() {
    let Some((cosigner, kps, _)) = seeded() else { return };
    let messages: Vec<Vec<u8>> = vec![vec![0x33; 32], vec![0x44; 32]];

    let (round, theirs) = begin(&cosigner, &messages);
    // Answer message 1 with a share computed over message 0's bytes.
    let mut ours = wallet_answers(&kps[0], &messages, &theirs);
    let wrong = wallet_answers(&kps[0], &[messages[0].clone()], &theirs[1..2]);
    ours[1] = WalletHalf {
        hiding: wrong[0].hiding.clone(),
        binding: wrong[0].binding.clone(),
        share: wrong[0].share.clone(),
    };

    let err = round
        .finish(ours)
        .expect_err("a share over the wrong message must not aggregate");
    assert!(err.starts_with("message 1:"), "the error must name the message, got: {err}");
}

/// One answer short is refused outright, rather than signing every message against its neighbour.
#[test]
fn a_short_batch_is_refused() {
    let Some((cosigner, kps, _)) = seeded() else { return };
    let messages: Vec<Vec<u8>> = vec![vec![0x55; 32], vec![0x66; 32]];

    let (round, theirs) = begin(&cosigner, &messages);
    let mut ours = wallet_answers(&kps[0], &messages, &theirs);
    ours.pop();

    let err = round.finish(ours).expect_err("short");
    assert!(err.contains("1 of 2"), "got: {err}");
}

/// Two rounds over the same message use different nonces — so the same message signed twice gives
/// two different, both-valid signatures. Equal signatures would mean a repeated nonce, which leaks
/// the key.
#[test]
fn nonces_are_fresh_every_round() {
    let Some((cosigner, kps, pkp)) = seeded() else { return };
    let messages: Vec<Vec<u8>> = vec![vec![0x77; 32]];

    let (round_a, theirs_a) = begin(&cosigner, &messages);
    let (round_b, theirs_b) = begin(&cosigner, &messages);
    assert_ne!(theirs_a[0].hiding, theirs_b[0].hiding, "the cosigner's nonce must not repeat");

    let a = round_a
        .finish(wallet_answers(&kps[0], &messages, &theirs_a))
        .expect("finish a");
    let b = round_b
        .finish(wallet_answers(&kps[0], &messages, &theirs_b))
        .expect("finish b");

    assert_ne!(a[0], b[0]);
    assert!(bip340_ok(&pkp, &messages[0], &a[0]));
    assert!(bip340_ok(&pkp, &messages[0], &b[0]));
}
