//! Where this cosigner keeps what outlives a request: an embedded SQLite key-value store.
//!
//! [`Store`] is the whole of it. It was `SharedServices`, then `Upstreams`, then a `Store` trait
//! with one implementation behind an `Arc<dyn ...>` — shared meaning shared between tenants,
//! upstreams meaning the ASP connection and the push channel alongside the store. There is one
//! cosigner now and it has no sockets, so what is left is storage, and one backend needs no trait
//! to choose between.
//!
//! A logical "tree" (namespace) + key maps to a row in one `kv` table keyed by `(tree, key)`.
//! Unlike the previous RESP backend — which flattened both into a single `"{tree}:{key}"` string
//! and recovered the tree with a `SCAN MATCH` glob — the tree is its own column here, so lookups
//! are exact-match and a key containing `:` can never be mistaken for a different namespace.
//!
//! The database is a single file on local disk (or `:memory:` for tests). It is opened in WAL mode
//! with `synchronous=FULL`, so a committed write survives OS/power loss — this store holds the
//! actor's sealed state, which includes key material, so durability wins over write throughput.
//!
//! The API is synchronous and `rusqlite` is a blocking one, so the work happens inline rather than
//! bridging to an async client. A single `Connection` behind a `Mutex` serializes
//! access; SQLite would serialize writers anyway, and the per-op cost on a local file is well under
//! the round-trip the network backend it replaces used to pay. When called from a multi-threaded
//! tokio runtime the work is wrapped in `block_in_place` so a commit's fsync doesn't stall other
//! tasks on that worker thread.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension};

use crate::cosigner::Cosigner;

/// Errors from the persistence layer.
#[derive(Debug)]
pub enum PersistenceError {
    Backend(String),
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersistenceError::Backend(msg) => write!(f, "persistence error: {msg}"),
        }
    }
}

impl std::error::Error for PersistenceError {}


/// Schema: one table, primary-keyed by `(tree, key)`. `WITHOUT ROWID` keeps the row inline with
/// the index rather than paying an extra indirection on every point lookup.
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS kv (
    tree  TEXT NOT NULL,
    key   TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (tree, key)
) WITHOUT ROWID;";

pub struct Store {
    conn: Mutex<Connection>,
    /// Submit a stored intent once `now > earliest_expires_at - auto_settle_safety_margin_secs`.
    /// Config rather than storage, but it is decided per deployment alongside the backend and one
    /// call reads it.
    pub auto_settle_safety_margin_secs: i64,
}

impl Store {
    /// Open (creating if absent) the database at `path` and apply the schema. Pass `":memory:"`
    /// for an ephemeral store. Any parent directory is created first, so a fresh deployment
    /// pointed at e.g. `/var/lib/cosigner/state.db` boots without manual setup.
    pub fn open(path: &str, auto_settle_safety_margin_secs: i64) -> Result<Self, PersistenceError> {
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        PersistenceError::Backend(format!("create {}: {e}", parent.display()))
                    })?;
                }
            }
        }
        let conn = Connection::open(path)
            .map_err(|e| PersistenceError::Backend(format!("sqlite open {path}: {e}")))?;

        // WAL lets the (rare) reader proceed against the (serialized) writer; FULL fsyncs the WAL
        // on commit so an acknowledged write survives power loss. busy_timeout covers the case of
        // a second process (a stray CLI, a leftover runtime) briefly holding the write lock.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| PersistenceError::Backend(format!("pragma journal_mode: {e}")))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| PersistenceError::Backend(format!("pragma synchronous: {e}")))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| PersistenceError::Backend(format!("busy_timeout: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| PersistenceError::Backend(format!("schema: {e}")))?;

        Ok(Self {
            conn: Mutex::new(conn),
            auto_settle_safety_margin_secs,
        })
    }

    /// Run `f` with the connection held.
    ///
    /// `block_in_place` tells tokio to hand this worker's other tasks to a sibling thread while we
    /// block on the commit's fsync — but it panics on a current-thread runtime and is meaningless
    /// outside one, so it is applied only on a multi-thread runtime. Tests calling the store
    /// directly (no runtime) take the plain path.
    ///
    /// A poisoned mutex is recovered rather than propagated: the guarded `Connection` is still a
    /// valid handle, and taking down every later persistence call because one caller panicked
    /// mid-query would turn a single failed request into a dead server.
    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        let run = || {
            let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            f(&conn)
        };
        match tokio::runtime::Handle::try_current() {
            Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(run)
            }
            _ => run(),
        }
    }
}

impl Store {
    pub fn get(&self, tree: &str, key: &str) -> Result<Option<String>, PersistenceError> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT value FROM kv WHERE tree = ?1 AND key = ?2",
                (tree, key),
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| PersistenceError::Backend(format!("sqlite get: {e}")))
        })
    }

    pub fn put(&self, tree: &str, key: &str, value: &str) -> Result<(), PersistenceError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO kv (tree, key, value) VALUES (?1, ?2, ?3)
                 ON CONFLICT (tree, key) DO UPDATE SET value = excluded.value",
                (tree, key, value),
            )
            .map(|_| ())
            .map_err(|e| PersistenceError::Backend(format!("sqlite put: {e}")))
        })
    }

    pub fn delete(&self, tree: &str, key: &str) -> Result<(), PersistenceError> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM kv WHERE tree = ?1 AND key = ?2", (tree, key))
                .map(|_| ())
                .map_err(|e| PersistenceError::Backend(format!("sqlite delete: {e}")))
        })
    }

    pub fn get_all(&self, tree: &str) -> Result<HashMap<String, String>, PersistenceError> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT key, value FROM kv WHERE tree = ?1")
                .map_err(|e| PersistenceError::Backend(format!("sqlite get_all prepare: {e}")))?;
            let rows = stmt
                .query_map((tree,), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| PersistenceError::Backend(format!("sqlite get_all: {e}")))?;
            let mut result = HashMap::new();
            for row in rows {
                let (k, v) =
                    row.map_err(|e| PersistenceError::Backend(format!("sqlite get_all row: {e}")))?;
                result.insert(k, v);
            }
            Ok(result)
        })
    }

    pub fn clear(&self, tree: &str) -> Result<(), PersistenceError> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM kv WHERE tree = ?1", (tree,))
                .map(|_| ())
                .map_err(|e| PersistenceError::Backend(format!("sqlite clear: {e}")))
        })
    }
}

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ===========================================================================
// The seal: the cosigner's durable state, written whole on every mutation.
// ===========================================================================

/// The sealed-state tree: one opaque blob per group key. Identity-sealed JSON today, enclave AEAD
/// when the guest port lands — either way the thing storing it cannot read it.
const SEALED_STATE_TREE: &str = "sealed_state";

/// Re-seal a cosigner whose state changed, using the store it already holds.
pub(crate) async fn seal_snapshot_for(
    actor: &mut Cosigner,
    group_key: &str,
) {
    let store = actor.store.clone();
    seal_snapshot(actor, &store, group_key).await;
}

pub(crate) async fn seal_snapshot(
    actor: &mut Cosigner,
    store: &Store,
    group_key: &str,
) {
    match actor.to_snapshot() {
        Ok(blob) => {
            if let Err(e) = store
                
                .put(SEALED_STATE_TREE, group_key, &hex::encode(blob))
            {
                tracing::warn!("persist sealed_state/{group_key} failed: {e}");
            }
        }
        Err(e) => tracing::warn!("snapshot failed: {e}"),
    }
}

/// Restore the actor's state from a persisted snapshot, if one exists (on spawn/reseat).
/// Returns `true` when a snapshot was restored — meaning the actor now holds its policy +
/// keys from the sealed blob, so the caller can SKIP `InstallPolicy` (no plaintext key read).
/// `false` when there's no stored blob (first run) or restore failed.
pub(crate) async fn restore_snapshot(
    actor: &mut Cosigner,
    store: &Store,
    group_key: &str,
) -> bool {
    let stored = store.get(SEALED_STATE_TREE, group_key);
    let Ok(Some(hex_blob)) = stored else {
        return false;
    };
    let Ok(blob) = hex::decode(&hex_blob) else {
        tracing::warn!("sealed_state/{group_key}: corrupt hex; ignoring");
        return false;
    };
    match actor.restore_snapshot(&blob) {
        Ok(()) => {
            tracing::info!("restored actor snapshot for {group_key}");
            true
        }
        Err(e) => {
            tracing::warn!("restore failed: {e}");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Request-to-pay. Each mutates the actor's SEALED state, so each re-persists the snapshot.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open(":memory:", 1800).expect("open in-memory store")
    }

    #[test]
    fn get_missing_is_none() {
        assert_eq!(store().get("t", "nope").unwrap(), None);
    }

    #[test]
    fn put_get_roundtrip_and_overwrite() {
        let s = store();
        s.put("t", "k", "v1").unwrap();
        assert_eq!(s.get("t", "k").unwrap().as_deref(), Some("v1"));
        // put is an upsert — the second write replaces rather than erroring on the PK conflict.
        s.put("t", "k", "v2").unwrap();
        assert_eq!(s.get("t", "k").unwrap().as_deref(), Some("v2"));
    }

    #[test]
    fn delete_removes_only_the_named_key() {
        let s = store();
        s.put("t", "a", "1").unwrap();
        s.put("t", "b", "2").unwrap();
        s.delete("t", "a").unwrap();
        assert_eq!(s.get("t", "a").unwrap(), None);
        assert_eq!(s.get("t", "b").unwrap().as_deref(), Some("2"));
        // Deleting an absent key is a no-op, not an error.
        s.delete("t", "gone").unwrap();
    }

    #[test]
    fn trees_are_isolated() {
        let s = store();
        s.put("one", "k", "a").unwrap();
        s.put("two", "k", "b").unwrap();
        assert_eq!(s.get("one", "k").unwrap().as_deref(), Some("a"));
        assert_eq!(s.get("two", "k").unwrap().as_deref(), Some("b"));
        s.clear("one").unwrap();
        assert_eq!(s.get("one", "k").unwrap(), None);
        assert_eq!(s.get("two", "k").unwrap().as_deref(), Some("b"));
    }

    #[test]
    fn get_all_returns_bare_keys_for_that_tree_only() {
        let s = store();
        s.put("t", "a", "1").unwrap();
        s.put("t", "b", "2").unwrap();
        s.put("other", "c", "3").unwrap();
        let all = s.get_all("t").unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all.get("a").map(String::as_str), Some("1"));
        assert_eq!(all.get("b").map(String::as_str), Some("2"));
        assert!(s.get_all("empty").unwrap().is_empty());
    }

    /// The RESP backend flattened `(tree, key)` into `"{tree}:{key}"`, so a key containing `:`
    /// aliased into a neighbouring namespace's `SCAN` glob. Exact-match columns must not.
    #[test]
    fn keys_containing_the_old_separator_stay_in_their_tree() {
        let s = store();
        s.put("tree", "a:b", "inner").unwrap();
        s.put("tree:a", "b", "other").unwrap();
        assert_eq!(s.get("tree", "a:b").unwrap().as_deref(), Some("inner"));
        assert_eq!(s.get("tree:a", "b").unwrap().as_deref(), Some("other"));
        assert_eq!(s.get_all("tree").unwrap().len(), 1);
        assert_eq!(s.get_all("tree:a").unwrap().len(), 1);
    }

    /// Glob metacharacters were live in the old `SCAN MATCH "{tree}:*"` pattern.
    #[test]
    fn glob_metacharacters_in_tree_names_are_literal() {
        let s = store();
        s.put("a*", "k", "star").unwrap();
        s.put("ab", "k", "plain").unwrap();
        let all = s.get_all("a*").unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all.get("k").map(String::as_str), Some("star"));
    }

    #[test]
    fn reopening_a_file_store_sees_prior_writes() {
        let dir = std::env::temp_dir().join(format!("kv_store_test_{}", std::process::id()));
        let path = dir.join("state.db");
        let path = path.to_str().unwrap();
        {
            let s = Store::open(path, 1800).unwrap();
            s.put("t", "k", "durable").unwrap();
        }
        {
            let s = Store::open(path, 1800).unwrap();
            assert_eq!(s.get("t", "k").unwrap().as_deref(), Some("durable"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
