fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The message shapes. Serde derives because several are serialized into the seal.
    //
    // Server and client generation are OFF throughout, so nothing tonic emits ends up in the
    // crate: the guest targets wasm32-wasip2, which tonic does not build for. What is left is
    // prost, which does — and the framing tonic would have provided is five bytes, written out in
    // `src/grpc/framing.rs`. The build script itself still runs on the host, so needing `protoc`
    // here costs the wasm build nothing.
    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["proto/mpc_wallet.proto"], &["proto"])?;

    // The service. It imports `mpc_wallet.proto` for the shapes its single-round RPCs carry, so
    // `extern_path` points those at the module generated above rather than generating them twice —
    // prost would otherwise emit a relative path assuming both live in one module tree.
    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .extern_path(".mpc_wallet", "crate::wallet_proto")
        .compile_protos(&["proto/cosign_session.proto"], &["proto"])?;
    Ok(())
}
