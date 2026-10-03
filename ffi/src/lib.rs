//! Merged C-ABI FFI surface for the MPC wallet.
//!
//! Each sub-module owns its own `#[no_mangle] extern "C"` symbols and its own
//! result/response struct. The C-ABI is symbol-name based, so the disjoint
//! `ark_*`, `threshold_*`, `enclave_*` prefixes guarantee no link-time
//! collision between modules.

mod ark;
mod enclave;
mod threshold;

/// Hex as it crosses the FFI: bytes, or a fixed-size array, with the reason as text. The `hex` crate
/// never panics on what it is given — non-ASCII included — where the hand-sliced decoders this
/// replaces could, and a panic in an `extern "C"` function is an abort.
pub(crate) fn from_hex<T: hex::FromHex>(s: &str) -> Result<T, String>
where
    T::Error: std::fmt::Display,
{
    T::from_hex(s).map_err(|e| format!("invalid hex: {e}"))
}
