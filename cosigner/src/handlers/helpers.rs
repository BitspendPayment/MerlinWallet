//! Small helpers shared by the handlers.
//!
//! This was the multi-tenant toolkit: `verify_auth` checked a Schnorr signature on every request,
//! and a set of `*_user_*` helpers keyed per-user rows in a shared store by group key, resolved
//! through `policy_owner_idx`. None of it has a job now. Authentication is the runtime's — a request
//! reaches this instance only with the tenant a passkey resolved to — and one instance is one wallet
//! over its own filesystem, so there are no per-user rows to key. Most of those helpers had no
//! callers left well before this; the two that did deleted store trees nothing wrote.

/// Seconds since the Unix epoch.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Drive a future that never actually waits.
///
/// What the tests drive the async paths with when nothing under them waits — a service's message
/// with no ASP, say. A `Pending` here is a bug, not a slow call, so it panics rather than
/// spinning: there is no reactor under it to make progress.
pub fn block_on_ready<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("this future was driven with no reactor under it, and it waited"),
    }
}
