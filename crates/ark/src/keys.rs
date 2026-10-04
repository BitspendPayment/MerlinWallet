//! Keys as they arrive: hex, x-only or compressed.

use std::str::FromStr;

use bitcoin::XOnlyPublicKey;

/// An x-only public key from hex: 64 characters, or 66 with the `02`/`03` prefix of the compressed
/// form. The ASP publishes its signer key compressed and a wallet's own key is usually x-only, so
/// both arrive.
pub fn parse_xonly(hex: &str) -> Result<XOnlyPublicKey, String> {
    let x_only = match hex.strip_prefix("02").or_else(|| hex.strip_prefix("03")) {
        Some(rest) if hex.len() == 66 => rest,
        _ => hex,
    };
    XOnlyPublicKey::from_str(x_only).map_err(|e| format!("invalid x-only pubkey: {e}"))
}
