//! The one cosigner this process serves.
//!
//! Tenancy is not here, and deliberately. In `enclave-runtime` a client's separation is the host's:
//! their data lives under `/tenants/<id>/`, `id` derived as `HKDF(master, sha256(client SPKI))`, and
//! the instance is handed that directory as its root preopen. `tenant.rs` there puts it plainly —
//! *"Where the separation actually is: not in the guest."* A guest that asks for another tenant's
//! path gets its own, which does not exist. So the cosigner is not a thing that holds tenants; it is
//! the thing that gets loaded **for** one, over a filesystem already scoped to it.
//!
//! That is also why there is no lock in the design. The host pool keeps one `tokio::Mutex` per
//! client and names this exact caller as the reason — *"a cosigner reserving a nonce must not race
//! its own second request"* — so a client is serialised against itself before a request arrives
//! here. The mutex below is scaffolding for the interim, while this is still a long-lived process
//! serving concurrent connections directly; it goes when the host owns the lifecycle.

use std::sync::Arc;

use parking_lot::Mutex as SyncMutex;
use tokio::sync::{Mutex, MutexGuard};
use tonic::Status;

use crate::cosigner::actor::CosignerActor;
use crate::cosigner::state::CosignerState;
use crate::shared::SharedServices;

pub struct Cosigner {
    actor: Mutex<CosignerActor>,
    shared: Arc<SharedServices>,
    group_key: String,
}

impl Cosigner {
    /// Load this cosigner's state, then hand back something callable.
    ///
    /// Eagerly, not on first use. A lazy restore amortises the read across a process that outlives
    /// many requests, which is the shape being removed: per-request there is no later use to
    /// amortise into. Storage is the whole of the state — read on entry, sealed on mutation.
    ///
    /// No seal yet is not an error. Before onboarding there is nothing to read, and DKG is what
    /// writes the first one.
    pub async fn open(
        shared: Arc<SharedServices>,
        state: Arc<SyncMutex<CosignerState>>,
    ) -> Result<Self, Status> {
        let group_key = state.lock().cosigner_id.clone();
        let mut actor = CosignerActor::new(shared.clone(), state.clone());
        if crate::cosigner::store::restore_actor_snapshot(&mut actor, &shared, &group_key).await {
            crate::cosigner::store::load_policy_state_from_actor(&state, &mut actor).await?;
        }
        Ok(Self {
            actor: Mutex::new(actor),
            shared,
            group_key,
        })
    }

    pub fn group_key(&self) -> &str {
        &self.group_key
    }

    pub fn shared(&self) -> &Arc<SharedServices> {
        &self.shared
    }

    /// Seal after a mutation. Every path that changes durable state must call this.
    pub async fn persist(&self, actor: &mut CosignerActor) {
        crate::cosigner::store::persist_actor_snapshot(actor, &self.shared, &self.group_key)
            .await;
    }

    pub async fn actor(&self) -> MutexGuard<'_, CosignerActor> {
        self.actor.lock().await
    }
}
