// Shared test helpers: each integration binary compiles this module and uses only part of it.
#![allow(dead_code)]

//! Shared setup for the integration tests. Builds `Store` against the local dev stack.
//!
//! Persistence is an in-process SQLite store, so there is no external dependency to reach and each
//! `try_shared` call gets its own isolated database. The ASP channel is created lazily, so a
//! reachable arkd is NOT needed for paths that never issue an ASP RPC (FROST signing, policy seal,
//! DKG onboarding bookkeeping) — which is every test using this helper. `try_shared` returns
//! `None` only if the ASP URL itself is malformed.

use cosigner::Cosigner;
use std::collections::BTreeMap;
use std::sync::Arc;

use rand::rngs::OsRng;

use cosigner::host::Host;
use cosigner::store::Store;

use threshold::dkg::{self, Round1Package, Round2Package};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::random;

use std::sync::Mutex;

pub fn try_store() -> Option<Arc<Store>> {
    // `:memory:` — a fresh, private store per caller. Tests no longer share one namespace, so a
    // leftover key from a failed run can't leak into the next one.
    Some(Arc::new(
        Store::open(":memory:", 1800).expect("open in-memory store"),
    ))
}

/// Host-side 2-of-2 DKG; even-Y-normalized outputs. Index 0 = user/client, 1 = cosigner/server.
/// The actor no longer performs DKG, so tests mint the key material themselves.
pub fn dkg_2of2() -> (Vec<KeyPackage>, PublicKeyPackage) {
    let mut rng = OsRng;
    let (min, max) = (2usize, 2usize);

    let mut r1_secrets = Vec::new();
    let mut r1_packages: BTreeMap<Identifier, Round1Package> = BTreeMap::new();
    for _ in 0..max {
        let secret = random::mod_n_random(&mut rng);
        let coefficients: Vec<_> = (0..min - 1)
            .map(|_| random::mod_n_random(&mut rng))
            .collect();
        let (secret_pkg, pub_pkg) =
            dkg::dkg_part1(max, min, &secret, &coefficients, &mut rng).expect("dkg_part1");
        r1_packages.insert(secret_pkg.identifier.clone(), pub_pkg);
        r1_secrets.push(secret_pkg);
    }

    let mut r2_secrets = Vec::new();
    let mut all_r2: Vec<BTreeMap<Identifier, Round2Package>> = Vec::new();
    for secret_pkg in &r1_secrets {
        let others: BTreeMap<Identifier, Round1Package> = r1_packages
            .iter()
            .filter(|(id, _)| **id != secret_pkg.identifier)
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        let (r2_secret, r2_out) = dkg::dkg_part2(secret_pkg, &others, &[]).expect("dkg_part2");
        r2_secrets.push(r2_secret);
        all_r2.push(r2_out);
    }

    let mut key_packages = Vec::new();
    let mut pkp_out: Option<PublicKeyPackage> = None;
    for (i, r2_secret) in r2_secrets.iter().enumerate() {
        let others_r1: BTreeMap<Identifier, Round1Package> = r1_packages
            .iter()
            .filter(|(id, _)| **id != r2_secret.identifier)
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        let mut our_r2: BTreeMap<Identifier, Round2Package> = BTreeMap::new();
        for (j, r2_pkgs) in all_r2.iter().enumerate() {
            if j == i {
                continue;
            }
            if let Some(pkg) = r2_pkgs.get(&r2_secret.identifier) {
                our_r2.insert(r1_secrets[j].identifier.clone(), pkg.clone());
            }
        }
        let (kp, pkp) =
            dkg::dkg_part3(&r1_secrets[i], r2_secret, &others_r1, &our_r2, &[]).expect("dkg_part3");
        key_packages.push(kp.into_even_y());
        pkp_out = Some(pkp.into_even_y());
    }

    (key_packages, pkp_out.unwrap())
}

/// Open the cosigner this process serves, loading whatever its seal already holds.
pub fn open_cosigner(store: &Arc<Store>, group_key: &str) -> Mutex<Cosigner> {
    Mutex::new(Cosigner::open(store.clone(), group_key.to_string()).expect("open cosigner"))
}

/// Install a wallet's key material and seal it, as DKG's final round does: the cosigner key
/// package, the group PKP, the user's signing identifier and the Ark cosigner secret.
pub fn seed_policy(
    cosigner: &Mutex<Cosigner>,
    group_key: &str,
    kp_cosigner: &KeyPackage,
    kp_user: &KeyPackage,
    pkp: &PublicKeyPackage,
    ark_cosigner_secret_hex: Option<String>,
) {
    seed_policy_with_dealt_share(
        cosigner,
        group_key,
        kp_cosigner,
        kp_user,
        pkp,
        ark_cosigner_secret_hex,
        None,
    );
}

/// As [`seed_policy`], plus the share the cosigner dealt the wallet at DKG — what `Recover` hands
/// back. `None` is a wallet onboarded before recovery existed.
pub fn seed_policy_with_dealt_share(
    cosigner: &Mutex<Cosigner>,
    group_key: &str,
    kp_cosigner: &KeyPackage,
    kp_user: &KeyPackage,
    pkp: &PublicKeyPackage,
    ark_cosigner_secret_hex: Option<String>,
    wallet_dealt_share_hex: Option<String>,
) {
    let mut actor = cosigner.lock().unwrap();
    actor
        .install_policy(
            group_key.to_string(),
            &kp_cosigner.to_json(),
            &pkp.to_json(),
            Some(&hex::encode(kp_user.identifier.serialize())),
            ark_cosigner_secret_hex,
            wallet_dealt_share_hex,
            )
        .expect("install policy");
    actor.seal();
}

/// A 2-of-2 BIP-340 signature over [message] by the group key, both halves played host-side.
///
/// What a wallet and its cosigner produce together — used where a test needs a group-key signature
/// without standing up a ceremony. `key_packages` is the pair `dkg_2of2` returns.
pub fn group_sign(
    key_packages: &[KeyPackage],
    public_key_package: &PublicKeyPackage,
    message: &[u8],
) -> [u8; 64] {
    use threshold::commitment::SigningPackage;
    use threshold::nonce;
    use threshold::signing;

    let mut rng = OsRng;
    let nonces: Vec<_> = key_packages
        .iter()
        .map(|kp| nonce::new_nonce(&mut rng, &kp.secret_share))
        .collect();
    let commitments = key_packages
        .iter()
        .zip(&nonces)
        .map(|(kp, n)| (kp.identifier.clone(), n.commitments.clone()))
        .collect::<BTreeMap<_, _>>();
    let package = SigningPackage::new(commitments, message.to_vec());
    let shares = key_packages
        .iter()
        .zip(&nonces)
        .map(|(kp, n)| {
            (
                kp.identifier.clone(),
                signing::sign(&package, n, kp).expect("share"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    signing::aggregate(&package, &shares, public_key_package)
        .expect("aggregate")
        .serialize()
}

/// The wallet's half of an in-band round over [messages]: a fresh nonce for each, then a share
/// over both commitments. What `answerRound` does in the app.
pub fn wallet_answers(
    kp_user: &KeyPackage,
    messages: &[Vec<u8>],
    cosigner_commitments: &[cosigner::types::Commitment],
) -> Vec<cosigner::cosigner::WalletHalf> {
    use threshold::commitment::SigningPackage;
    use threshold::nonce::{self, SigningCommitments};
    use threshold::point;
    use threshold::scalar::scalar_to_bytes;
    use threshold::signing;

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
            cosigner::cosigner::WalletHalf {
                hiding: point::serialize_compressed(&ours.commitments.hiding).to_vec(),
                binding: point::serialize_compressed(&ours.commitments.binding).to_vec(),
                share: scalar_to_bytes(&share.s).to_vec(),
            }
        })
        .collect()
}

/// An escrow on a wallet, optionally with a service paired into it.
pub fn seed_escrow(
    cosigner: &Mutex<Cosigner>,
    escrow_key: &str,
    paired: bool,
) {
    let mut c = cosigner.lock().unwrap();
    c.install_escrow(cosigner::types::EscrowRecord {
        escrow_key: escrow_key.to_string(),
        key_package_json: "{}".into(),
        public_key_package_json: "{}".into(),
        wallet_identifier_hex: "11".repeat(32),
        context_hex: "22".repeat(16),
        wallet_delta_share_hex: "33".repeat(32),
        created_at: 1_700_000_000,
        pairing: paired.then(|| cosigner::types::ServicePairing {
            service_identifier_hex: "44".repeat(32),
            key_package_json: "{}".into(),
            public_key_package_json: "{}".into(),
            service_verifying_share_hex: "55".repeat(33),
            paired_at: 1_700_000_000,
            attempt_id_hex: "aa".repeat(16),
            // Seeded finished: these tests are about the DEAL, and a pending pairing is refused a
            // deal for reasons of its own — proved in `escrow_session_test.rs`.
            service_confirmed: true,
            wallet_confirmed: true,
        }),
        session: None,
        reclaim_opened_at: None,
    })
    .expect("install escrow");
}

/// Driving `CosignerService::route` with real framed bodies, as the runtime delivers them.
///
/// A body here is written whole before the handler runs, so a test can open a stream and read
/// what the cosigner says first — but cannot answer it. A stream opened and left is cut off
/// mid-ceremony, and ends `Cancelled` with whatever went out before that.
pub mod wire {
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use bytes::Bytes;
    use http_body_util::BodyExt;

    use cosigner::grpc::framing::{frame, Deframer};
    use cosigner::session::{CosignerService, TENANT_HEADER};
    use cosigner::wallet_proto::GetServerInfoResponse;
    use cosigner::Cosigner;
    use wstd::http::{Body, Request, Response};

    /// What the runtime puts on an approved request: sixteen bytes, lowercase hex.
    pub const TENANT: &str = "0123456789abcdef0123456789abcdef";

    /// Drive a future to completion on this thread.
    ///
    /// Every body here is already in memory, so nothing genuinely parks and a busy poll is enough.
    /// The cap is what turns "this future never finishes" into a failed test rather than a hung
    /// one — which matters, because a duplex that stops making progress is exactly the bug these
    /// tests would catch.
    pub fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = Box::pin(fut);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..100_000 {
            if let Poll::Ready(value) = fut.as_mut().poll(&mut cx) {
                return value;
            }
        }
        panic!("the future never completed");
    }

    /// A gRPC request carrying `messages`, addressed at `method`, as the runtime would deliver it
    /// — or, with `tenant: None`, as it would never deliver it.
    pub fn request<M: prost::Message>(
        method: &str,
        messages: &[M],
        tenant: Option<&str>,
    ) -> Request<Body> {
        let mut buf = Vec::new();
        for message in messages {
            buf.extend_from_slice(&frame(&message.encode_to_vec()));
        }
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("http://cosigner/cosigner.v1.Cosigner/{method}"))
            .header("content-type", "application/grpc+proto");
        if let Some(tenant) = tenant {
            builder = builder.header(TENANT_HEADER, tenant);
        }
        builder
            .body(Body::from_http_body(
                http_body_util::Full::new(Bytes::from(buf))
                    .map_err(|e: std::convert::Infallible| -> wstd::http::Error { match e {} }),
            ))
            .expect("request is well formed")
    }

    /// What came back: the decoded messages, and the status a client reads from the trailers.
    pub struct Answer<M> {
        pub messages: Vec<M>,
        pub code: u32,
        pub message: String,
    }

    pub fn collect<M: prost::Message + Default>(resp: Response<Body>) -> Answer<M> {
        let collected =
            block_on(resp.into_body().into_boxed_body().collect()).expect("collect body");
        let trailers = collected.trailers().cloned().unwrap_or_default();
        let code = trailers
            .get("grpc-status")
            .expect("every gRPC response carries a grpc-status trailer")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let message = trailers
            .get("grpc-message")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();

        let mut deframer = Deframer::default();
        deframer.push(&collected.to_bytes());
        let mut messages = Vec::new();
        while let Some(bytes) = deframer.next().expect("well-framed response") {
            messages.push(M::decode(bytes).expect("decodable response"));
        }
        Answer { messages, code, message }
    }

    pub fn service(cosigner: Cosigner) -> CosignerService {
        CosignerService::new(
            Arc::new(Mutex::new(cosigner)),
            GetServerInfoResponse { bitcoin_network: "regtest".into() },
        )
    }
}

/// Records what the cosigner asked of the runtime, and holds it to the runtime's rule for task ids:
/// an id is an idempotency key, refused with different input until its record is forgotten.
#[derive(Default)]
pub struct Recorder {
    pub enqueued: Mutex<Vec<(String, Vec<u8>, u64, Option<u64>)>>,
    live: Mutex<std::collections::HashMap<String, (Vec<u8>, u64, bool)>>,
    pub cancelled: Mutex<Vec<String>>,
    pub woken: Mutex<Vec<(String, Option<String>)>>,
    registered: Mutex<Vec<String>>,
    /// Connections the cosigner asked the runtime to hold, and what it sent on them.
    pub opened: Mutex<Vec<(String, String)>>,
    pub sent: Mutex<Vec<(String, Vec<u8>)>>,
    /// Whether a connection is up. Sending on one that is not fails, as it does for real.
    pub connected: Mutex<bool>,
    /// A far side that never answers: opening still succeeds, and no send ever does.
    pub never_connects: Mutex<bool>,
}

impl Host for Recorder {
    fn enqueue(
        &self,
        id: &str,
        payload: &[u8],
        run_at_ms: u64,
        interval_ms: Option<u64>,
    ) -> Result<(), String> {
        let mut live = self.live.lock().unwrap();
        if let Some((old, old_run_at, _)) = live.get(id) {
            if old != payload || *old_run_at != run_at_ms {
                return Err("task id already used with different input".into());
            }
            return Ok(());
        }
        live.insert(id.into(), (payload.to_vec(), run_at_ms, false));
        self.enqueued
            .lock()
            .unwrap()
            .push((id.into(), payload.to_vec(), run_at_ms, interval_ms));
        Ok(())
    }
    fn status(&self, _: &str) -> Result<String, String> {
        Ok("{}".into())
    }
    fn cancel(&self, id: &str) -> Result<(), String> {
        if let Some(record) = self.live.lock().unwrap().get_mut(id) {
            record.2 = true;
        }
        self.cancelled.lock().unwrap().push(id.into());
        Ok(())
    }
    fn forget(&self, id: &str) -> Result<(), String> {
        let mut live = self.live.lock().unwrap();
        match live.get(id) {
            Some((_, _, true)) => {
                live.remove(id);
                Ok(())
            }
            Some(_) => Err("task is still active".into()),
            None => Err("no such task".into()),
        }
    }
    fn register_device(&self, token: &str) -> Result<(), String> {
        self.registered.lock().unwrap().push(token.into());
        Ok(())
    }
    fn forget_device(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn devices(&self) -> Result<u32, String> {
        Ok(self.registered.lock().unwrap().len() as u32)
    }
    fn wake(&self, category: &str, reference: Option<&str>) -> Result<(), String> {
        self.woken
            .lock()
            .unwrap()
            .push((category.into(), reference.map(Into::into)));
        Ok(())
    }
    fn stream_open(&self, id: &str, origin: &str) -> Result<(), String> {
        let mut opened = self.opened.lock().unwrap();
        // Idempotent for the same instruction, as the runtime's is: a second escrow with the same
        // service reuses the connection rather than making a second.
        match opened.iter().find(|(held, _)| held == id) {
            Some((_, held_origin)) if held_origin != origin => {
                return Err(format!("a stream with that id is already open to {held_origin}"))
            }
            Some(_) => {}
            None => opened.push((id.into(), origin.into())),
        }
        if !*self.never_connects.lock().unwrap() {
            *self.connected.lock().unwrap() = true;
        }
        Ok(())
    }

    fn stream_close(&self, id: &str) -> Result<(), String> {
        self.opened.lock().unwrap().retain(|(held, _)| held != id);
        Ok(())
    }

    fn stream_send(&self, id: &str, payload: &[u8]) -> Result<(), String> {
        if !*self.connected.lock().unwrap() {
            return Err("that stream is not connected; the message was not sent".into());
        }
        self.sent.lock().unwrap().push((id.into(), payload.to_vec()));
        Ok(())
    }

    fn stream_status(&self, _: &str) -> Result<String, String> {
        Ok(format!(
            r#"{{"connected":{}}}"#,
            *self.connected.lock().unwrap()
        ))
    }

}

impl Recorder {
    /// The connections the cosigner asked the runtime to hold, as `(id, origin)`.
    pub fn opened(&self) -> Vec<(String, String)> {
        self.opened.lock().unwrap().clone()
    }

    /// What went out on them, as `(id, payload)`.
    pub fn sent(&self) -> Vec<(String, Vec<u8>)> {
        self.sent.lock().unwrap().clone()
    }

    /// Everything the cosigner asked to have enqueued, as `(id, payload, run_at_ms, interval_ms)`.
    pub fn enqueued(&self) -> Vec<(String, Vec<u8>, u64, Option<u64>)> {
        self.enqueued.lock().unwrap().clone()
    }

    pub fn woken(&self) -> Vec<(String, Option<String>)> {
        self.woken.lock().unwrap().clone()
    }

    pub fn cancelled(&self) -> Vec<String> {
        self.cancelled.lock().unwrap().clone()
    }

    /// Pretend the far side went away: a send now fails the way it does for real.
    pub fn disconnect(&self) {
        *self.connected.lock().unwrap() = false;
    }

    /// A service the runtime never manages to reach. `stream_open` still succeeds — it only
    /// records a standing instruction — and every send afterwards fails, which is what a guest
    /// sees while the supervisor is dialling something that is not answering.
    pub fn disconnect_on_open(&self) {
        *self.never_connects.lock().unwrap() = true;
        *self.connected.lock().unwrap() = false;
    }
}
