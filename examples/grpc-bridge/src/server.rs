//! gRPC Bridge Server Example
//!
//! This binary demonstrates running both a Quill server and a gRPC bridge
//! that forwards requests to it.
//!
//! ## Usage
//!
//! ```bash
//! cargo run -p grpc-bridge-example --bin grpc-bridge-server
//! ```
//!
//! ## Architecture
//!
//! The server runs two services:
//! 1. A Quill HTTP/2 server on port 8080 (handles echo requests)
//! 2. A gRPC server on port 50051 (bridges to Quill)
//!
//! gRPC clients can connect to port 50051, and their requests will be
//! automatically bridged to the Quill server on port 8080.

use grpc_bridge_example::{handle_echo, EchoServiceBridge, EchoServiceServer};
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::{info, Level};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("Starting gRPC Bridge Example");

    // Start Quill server in background
    let quill_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    tokio::spawn(async move {
        info!("Starting Quill server on {}", quill_addr);
        if let Err(e) = run_quill_server(quill_addr).await {
            eprintln!("Quill server error: {}", e);
        }
    });

    // Give Quill server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Start gRPC bridge server
    let grpc_addr: SocketAddr = "127.0.0.1:50051".parse()?;
    info!("Starting gRPC bridge server on {}", grpc_addr);

    let bridge_service = EchoServiceBridge::new("http://127.0.0.1:8080")
        .map_err(|e| format!("Failed to create bridge: {}", e))?;

    Server::builder()
        .add_service(EchoServiceServer::new(bridge_service))
        .serve(grpc_addr)
        .await?;

    Ok(())
}

/// Run the Quill server that handles echo requests
async fn run_quill_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use quill_server::QuillServer;

    let server = QuillServer::builder()
        .turbo_profile() // HTTP/2 only for Quill
        .register("echo.v1.EchoService/Echo", handle_echo)
        .build();

    server
        .serve(addr)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    Ok(())
}
