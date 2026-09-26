//! Where this cosigner keeps what outlives a request: a key-value store over plain files.
//!
//! [`Store`] is the whole of it. It was `SharedServices`, then `Upstreams`, then a `Store` trait
//! with one implementation behind an `Arc<dyn ...>` — shared meaning shared between tenants,
//! upstreams meaning the ASP connection and the push channel alongside the store. There is one
//! cosigner now and it has no sockets, so what is left is storage, and one backend needs no trait
//! to choose between.
//!
//! # Why not SQLite
//!
//! It was an embedded SQLite database until the guest port, and SQLite does build for
//! `wasm32-wasip2` — enclave-runtime has a whole conformance suite proving it. What it does not do
//! is earn its place. This store has four call sites, no query, no join, no index worth the name
//! and no schema beyond `(tree, key) -> value`; against that it was bringing a quarter-megabyte of
//! vendored C, a wasi-sdk dependency for the build, and `SQLITE_THREADSAFE=0` to work around a
//! threading model the guest does not have. A directory is the same data structure without any of
//! that.
//!
//! # The layout
//!
//! ```text
//!   <root>/<hex tree>/<hex key>      the value, whole
//! ```
//!
//! One directory per tree, one file per key. **Both names are hex**, which is the part doing real
//! work: trees and keys are arbitrary caller strings — a group key, a contact label, `a:b`, `a*` —
//! and hex makes every one of them a legal, unambiguous, case-stable filename with no separator to
//! smuggle a path in, no `.` or `..`, and no metacharacter left live. The previous RESP backend
//! flattened `(tree, key)` into `"{tree}:{key}"` and recovered the tree with a `SCAN MATCH` glob,
//! so a key containing `:` aliased into a neighbour's namespace. Hex is what makes that
//! unrepresentable rather than merely tested for.
//!
//! Writes land through a temporary file and a rename, which `wasi:filesystem` documents as atomic:
//! one directory-entry move inside one commit. A reader therefore sees the old value or the new
//! one, never a half-written blob — which matters because the largest value here is the seal, and
//! a torn seal is a wallet that cannot open.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn backend(msg: impl fmt::Display) -> PersistenceError {
    PersistenceError::Backend(msg.to_string())
}

/// A filename is hex, so a name this long came from a key half this long. Most filesystems stop at
/// 255 bytes; refusing here names the real cause, where letting the write through would surface as
/// a bare `ENAMETOOLONG` from somewhere with no idea which key it was.
const MAX_NAME_BYTES: usize = 200;

fn encode(name: &str) -> Result<String, PersistenceError> {
    let encoded = hex::encode(name.as_bytes());
    if encoded.len() > MAX_NAME_BYTES {
        return Err(backend(format!(
            "{:?} is too long to name a file ({} bytes, limit {})",
            name,
            name.len(),
            MAX_NAME_BYTES / 2
        )));
    }
    Ok(encoded)
}

/// The key a filename came from, or `None` if this is not one of ours.
///
/// `None` covers the temporary files a write leaves behind if it dies between create and rename:
/// they carry a suffix that cannot be hex, so they are skipped by listing rather than returned as
/// a key whose value is half a blob.
fn decode(name: &str) -> Option<String> {
    let bytes = hex::decode(name).ok()?;
    String::from_utf8(bytes).ok()
}

/// The backing store. Either a directory, or a map for tests that want no filesystem at all.
enum Backend {
    Dir(PathBuf),
    Memory(Mutex<HashMap<(String, String), String>>),
}

pub struct Store {
    backend: Backend,
    /// Submit a stored intent once `now > earliest_expires_at - auto_settle_safety_margin_secs`.
    /// Config rather than storage, but it is decided per deployment alongside the backend and one
    /// call reads it.
    pub auto_settle_safety_margin_secs: i64,
}

impl Store {
    /// Open (creating if absent) the store rooted at `path`.
    ///
    /// Pass `":memory:"` for an ephemeral one. The directory is created on open, so a fresh
    /// deployment pointed at e.g. `/var/lib/cosigner` boots without manual setup.
    pub fn open(path: &str, auto_settle_safety_margin_secs: i64) -> Result<Self, PersistenceError> {
        let backend = if path == ":memory:" {
            Backend::Memory(Mutex::new(HashMap::new()))
        } else {
            std::fs::create_dir_all(path).map_err(|e| backend(format!("create {path}: {e}")))?;
            Backend::Dir(PathBuf::from(path))
        };
        Ok(Self {
            backend,
            auto_settle_safety_margin_secs,
        })
    }

    /// A poisoned mutex is recovered rather than propagated: the guarded map is still valid, and
    /// taking down every later persistence call because one caller panicked mid-write would turn a
    /// single failed request into a dead instance.
    fn memory(
        map: &Mutex<HashMap<(String, String), String>>,
    ) -> std::sync::MutexGuard<'_, HashMap<(String, String), String>> {
        map.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn tree_dir(root: &Path, tree: &str) -> Result<PathBuf, PersistenceError> {
        Ok(root.join(encode(tree)?))
    }

    pub fn get(&self, tree: &str, key: &str) -> Result<Option<String>, PersistenceError> {
        match &self.backend {
            Backend::Memory(map) => {
                Ok(Self::memory(map).get(&(tree.to_string(), key.to_string())).cloned())
            }
            Backend::Dir(root) => {
                let path = Self::tree_dir(root, tree)?.join(encode(key)?);
                match std::fs::read_to_string(&path) {
                    Ok(value) => Ok(Some(value)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(backend(format!("read {}: {e}", path.display()))),
                }
            }
        }
    }

    /// Write `value`, replacing whatever was there.
    ///
    /// Through a temporary file and a rename, so a reader sees the old value or the new one and
    /// never a partial write. The temporary is synced before the rename: `wasi:filesystem` loses
    /// unsynced writes on a crash, and a rename that published unsynced bytes would leave a name
    /// pointing at nothing durable.
    pub fn put(&self, tree: &str, key: &str, value: &str) -> Result<(), PersistenceError> {
        match &self.backend {
            Backend::Memory(map) => {
                Self::memory(map).insert((tree.to_string(), key.to_string()), value.to_string());
                Ok(())
            }
            Backend::Dir(root) => {
                let dir = Self::tree_dir(root, tree)?;
                std::fs::create_dir_all(&dir)
                    .map_err(|e| backend(format!("create {}: {e}", dir.display())))?;

                let name = encode(key)?;
                // `.writing` cannot be hex, so a temporary left by a crash is invisible to
                // `get_all` rather than being read back as a truncated value.
                let tmp = dir.join(format!("{name}.writing"));
                {
                    use std::io::Write as _;
                    let mut file = std::fs::File::create(&tmp)
                        .map_err(|e| backend(format!("create {}: {e}", tmp.display())))?;
                    file.write_all(value.as_bytes())
                        .map_err(|e| backend(format!("write {}: {e}", tmp.display())))?;
                    file.sync_all()
                        .map_err(|e| backend(format!("sync {}: {e}", tmp.display())))?;
                }
                let final_path = dir.join(&name);
                std::fs::rename(&tmp, &final_path).map_err(|e| {
                    // Leaving the temporary behind would be a file that never gets cleaned up.
                    let _ = std::fs::remove_file(&tmp);
                    backend(format!("rename into {}: {e}", final_path.display()))
                })
            }
        }
    }

    /// Remove `key`. Deleting an absent key is a no-op, not an error.
    pub fn delete(&self, tree: &str, key: &str) -> Result<(), PersistenceError> {
        match &self.backend {
            Backend::Memory(map) => {
                Self::memory(map).remove(&(tree.to_string(), key.to_string()));
                Ok(())
            }
            Backend::Dir(root) => {
                let path = Self::tree_dir(root, tree)?.join(encode(key)?);
                match std::fs::remove_file(&path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(backend(format!("remove {}: {e}", path.display()))),
                }
            }
        }
    }

    /// Everything in `tree`, by bare key. An absent tree is empty, not an error.
    pub fn get_all(&self, tree: &str) -> Result<HashMap<String, String>, PersistenceError> {
        match &self.backend {
            Backend::Memory(map) => Ok(Self::memory(map)
                .iter()
                .filter(|((t, _), _)| t == tree)
                .map(|((_, k), v)| (k.clone(), v.clone()))
                .collect()),
            Backend::Dir(root) => {
                let dir = Self::tree_dir(root, tree)?;
                let entries = match std::fs::read_dir(&dir) {
                    Ok(entries) => entries,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
                    Err(e) => return Err(backend(format!("read {}: {e}", dir.display()))),
                };
                let mut out = HashMap::new();
                for entry in entries {
                    let entry =
                        entry.map_err(|e| backend(format!("read {}: {e}", dir.display())))?;
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else { continue };
                    // Not one of ours: a crashed write's temporary, or something a human left here.
                    let Some(key) = decode(name) else { continue };
                    match std::fs::read_to_string(entry.path()) {
                        Ok(value) => {
                            out.insert(key, value);
                        }
                        // Deleted between the listing and the read. Absent is the right answer.
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            return Err(backend(format!("read {}: {e}", entry.path().display())))
                        }
                    }
                }
                Ok(out)
            }
        }
    }

    /// Drop the whole tree.
    pub fn clear(&self, tree: &str) -> Result<(), PersistenceError> {
        match &self.backend {
            Backend::Memory(map) => {
                Self::memory(map).retain(|(t, _), _| t != tree);
                Ok(())
            }
            Backend::Dir(root) => {
                let dir = Self::tree_dir(root, tree)?;
                match std::fs::remove_dir_all(&dir) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(backend(format!("remove {}: {e}", dir.display()))),
                }
            }
        }
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
pub(crate) fn seal_snapshot_for(
    actor: &mut Cosigner,
    group_key: &str,
) {
    let store = actor.store.clone();
    if let Err(e) = seal_snapshot(actor, &store, group_key) {
        tracing::warn!("{e}");
    }
}

pub(crate) fn seal_snapshot(
    actor: &mut Cosigner,
    store: &Store,
    group_key: &str,
) -> Result<(), String> {
    let blob = actor.to_snapshot().map_err(|e| format!("snapshot failed: {e}"))?;
    store
        .put(SEALED_STATE_TREE, group_key, &hex::encode(blob))
        .map_err(|e| format!("persist sealed_state/{group_key} failed: {e}"))
}

/// Restore the actor's state from a persisted snapshot, if one exists (on spawn/reseat).
/// Returns `true` when a snapshot was restored — meaning the actor now holds its policy +
/// keys from the sealed blob, so the caller can SKIP `InstallPolicy` (no plaintext key read).
/// `false` when there's no stored blob (first run) or restore failed.
/// `Ok(false)` is a wallet that has never sealed anything. `Err` is a seal that is there and
/// cannot be read — which is not that, and must not be treated as it: see `Cosigner::open_with_host`.
pub(crate) fn restore_snapshot(
    actor: &mut Cosigner,
    store: &Store,
    group_key: &str,
) -> Result<bool, String> {
    let stored = store
        .get(SEALED_STATE_TREE, group_key)
        .map_err(|e| format!("sealed_state/{group_key}: {e}"))?;
    let Some(hex_blob) = stored else {
        return Ok(false);
    };
    let blob =
        hex::decode(&hex_blob).map_err(|e| format!("sealed_state/{group_key}: corrupt hex: {e}"))?;
    actor
        .restore_snapshot(&blob)
        .map_err(|e| format!("sealed_state/{group_key}: {e}"))?;
    tracing::info!("restored actor snapshot for {group_key}");
    Ok(true)
}

// ---------------------------------------------------------------------------
// Request-to-pay. Each mutates the actor's SEALED state, so each re-persists the snapshot.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `check` against both backends.
    ///
    /// Not a convenience: every case below is about namespace isolation, and isolation is a
    /// property of the *filename encoding*. A map keyed by `(tree, key)` passes all of them for
    /// free and proves nothing about the store that actually runs. The directory backend is the
    /// one under test; the map is along to keep the two from drifting.
    fn both(check: impl Fn(&Store)) {
        let dir = tempfile::tempdir().expect("tempdir");
        check(&Store::open(dir.path().to_str().unwrap(), 1800).expect("open dir store"));
        check(&Store::open(":memory:", 1800).expect("open memory store"));
    }

    #[test]
    fn get_missing_is_none() {
        both(|s| assert_eq!(s.get("t", "nope").unwrap(), None));
    }

    #[test]
    fn put_get_roundtrip_and_overwrite() {
        both(|s| {
            s.put("t", "k", "v1").unwrap();
            assert_eq!(s.get("t", "k").unwrap().as_deref(), Some("v1"));
            // put is an upsert — the second write replaces rather than erroring.
            s.put("t", "k", "v2").unwrap();
            assert_eq!(s.get("t", "k").unwrap().as_deref(), Some("v2"));
        });
    }

    #[test]
    fn delete_removes_only_the_named_key() {
        both(|s| {
            s.put("t", "a", "1").unwrap();
            s.put("t", "b", "2").unwrap();
            s.delete("t", "a").unwrap();
            assert_eq!(s.get("t", "a").unwrap(), None);
            assert_eq!(s.get("t", "b").unwrap().as_deref(), Some("2"));
            // Deleting an absent key is a no-op, not an error.
            s.delete("t", "gone").unwrap();
        });
    }

    #[test]
    fn trees_are_isolated() {
        both(|s| {
            s.put("one", "k", "a").unwrap();
            s.put("two", "k", "b").unwrap();
            assert_eq!(s.get("one", "k").unwrap().as_deref(), Some("a"));
            assert_eq!(s.get("two", "k").unwrap().as_deref(), Some("b"));
            s.clear("one").unwrap();
            assert_eq!(s.get("one", "k").unwrap(), None);
            assert_eq!(s.get("two", "k").unwrap().as_deref(), Some("b"));
        });
    }

    #[test]
    fn get_all_returns_bare_keys_for_that_tree_only() {
        both(|s| {
            s.put("t", "a", "1").unwrap();
            s.put("t", "b", "2").unwrap();
            s.put("other", "c", "3").unwrap();
            let all = s.get_all("t").unwrap();
            assert_eq!(all.len(), 2);
            assert_eq!(all.get("a").map(String::as_str), Some("1"));
            assert_eq!(all.get("b").map(String::as_str), Some("2"));
            assert!(s.get_all("empty").unwrap().is_empty());
        });
    }

    /// The RESP backend flattened `(tree, key)` into `"{tree}:{key}"`, so a key containing `:`
    /// aliased into a neighbouring namespace's `SCAN` glob. Hex names cannot.
    #[test]
    fn keys_containing_the_old_separator_stay_in_their_tree() {
        both(|s| {
            s.put("tree", "a:b", "inner").unwrap();
            s.put("tree:a", "b", "other").unwrap();
            assert_eq!(s.get("tree", "a:b").unwrap().as_deref(), Some("inner"));
            assert_eq!(s.get("tree:a", "b").unwrap().as_deref(), Some("other"));
            assert_eq!(s.get_all("tree").unwrap().len(), 1);
            assert_eq!(s.get_all("tree:a").unwrap().len(), 1);
        });
    }

    /// Glob metacharacters were live in the old `SCAN MATCH "{tree}:*"` pattern.
    #[test]
    fn glob_metacharacters_in_tree_names_are_literal() {
        both(|s| {
            s.put("a*", "k", "star").unwrap();
            s.put("ab", "k", "plain").unwrap();
            let all = s.get_all("a*").unwrap();
            assert_eq!(all.len(), 1);
            assert_eq!(all.get("k").map(String::as_str), Some("star"));
        });
    }

    /// A key that is a path is a key, not a path.
    ///
    /// This is the case hex exists for. Under any encoding that leaves `/` or `.` alone, these
    /// escape the tree — the first into a sibling namespace, the second out of the store
    /// altogether — and both would be a write landing somewhere nobody asked for.
    #[test]
    fn keys_that_look_like_paths_cannot_escape_their_tree() {
        both(|s| {
            s.put("t", "../../etc/passwd", "nope").unwrap();
            s.put("t", "a/b", "slash").unwrap();
            s.put("t", "..", "dotdot").unwrap();
            assert_eq!(s.get("t", "../../etc/passwd").unwrap().as_deref(), Some("nope"));
            assert_eq!(s.get("t", "a/b").unwrap().as_deref(), Some("slash"));
            assert_eq!(s.get("t", "..").unwrap().as_deref(), Some("dotdot"));
            assert_eq!(s.get_all("t").unwrap().len(), 3);
        });
    }

    #[test]
    fn reopening_a_file_store_sees_prior_writes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_str().unwrap();
        {
            let s = Store::open(path, 1800).unwrap();
            s.put("t", "k", "durable").unwrap();
        }
        {
            let s = Store::open(path, 1800).unwrap();
            assert_eq!(s.get("t", "k").unwrap().as_deref(), Some("durable"));
        }
    }

    /// A write that died between the temporary and the rename must not come back as a value.
    #[test]
    fn a_half_written_temporary_is_not_a_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = Store::open(dir.path().to_str().unwrap(), 1800).unwrap();
        s.put("t", "real", "value").unwrap();

        let tree = dir.path().join(hex::encode("t"));
        std::fs::write(tree.join(format!("{}.writing", hex::encode("ghost"))), "half").unwrap();

        let all = s.get_all("t").unwrap();
        assert_eq!(all.len(), 1, "the temporary must not be listed: {all:?}");
        assert_eq!(all.get("real").map(String::as_str), Some("value"));
        assert_eq!(s.get("t", "ghost").unwrap(), None);
    }

    /// A key too long to name a file fails with something that says which key.
    #[test]
    fn an_overlong_key_is_refused_by_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = Store::open(dir.path().to_str().unwrap(), 1800).unwrap();
        let err = s.put("t", &"k".repeat(MAX_NAME_BYTES), "v").unwrap_err();
        assert!(
            err.to_string().contains("too long to name a file"),
            "got: {err}"
        );
    }
}
