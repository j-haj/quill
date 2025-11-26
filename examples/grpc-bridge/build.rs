fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile the echo proto for both gRPC (tonic) and Quill
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &["../../proto/echo/v1/echo.proto"],
            &["../../proto"],
        )?;

    Ok(())
}
