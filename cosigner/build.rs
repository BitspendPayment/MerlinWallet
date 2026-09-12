fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Client-facing wallet API
    // Add serde derives so protobuf types can be used with axum JSON handlers.
    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["proto/mpc_wallet.proto"], &["proto"])?;

    // The streaming signing session. Kept in its own file and its own package so the unary API can
    // be retired independently of it, and without serde derives — nothing serves it over JSON.
    tonic_build::configure().compile_protos(&["proto/cosign_session.proto"], &["proto"])?;
    Ok(())
}
