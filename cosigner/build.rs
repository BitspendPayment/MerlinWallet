fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The message shapes. Serde derives because several are serialized into the seal.
    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["proto/mpc_wallet.proto"], &["proto"])?;

    // The service. It imports `mpc_wallet.proto` for the shapes its single-round RPCs carry, so
    // `extern_path` points those at the module generated above rather than generating them twice —
    // prost would otherwise emit a relative path assuming both live in one module tree.
    tonic_build::configure()
        .extern_path(".mpc_wallet", "crate::wallet_proto")
        .compile_protos(&["proto/cosign_session.proto"], &["proto"])?;
    Ok(())
}
