//! File upload service example demonstrating client streaming
//!
//! This example shows how to implement a file upload service where:
//! - Client streams file chunks to the server
//! - Server receives and processes chunks
//! - Server returns upload result with checksum

use bytes::{Bytes, BytesMut};
use quill_core::QuillError;
use sha2::{Digest, Sha256};
use std::pin::Pin;
use tokio_stream::{Stream, StreamExt};

/// Chunk size for file uploads (1MB)
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Maximum file size (100MB)
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

/// File chunk metadata
#[derive(Debug, Clone)]
pub struct FileChunk {
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub data: Bytes,
}

impl FileChunk {
    /// Encode chunk to bytes (simplified - in production use protobuf)
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        // Simple binary format: [index:4][total:4][data_len:4][data]
        buf.extend_from_slice(&self.chunk_index.to_be_bytes());
        buf.extend_from_slice(&self.total_chunks.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.data);

        buf.freeze()
    }

    /// Decode chunk from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, QuillError> {
        if bytes.len() < 12 {
            return Err(QuillError::Framing("Chunk too small".to_string()));
        }

        let chunk_index = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let total_chunks = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;

        if bytes.len() < 12 + data_len {
            return Err(QuillError::Framing("Invalid chunk data length".to_string()));
        }

        let data = Bytes::copy_from_slice(&bytes[12..12 + data_len]);

        Ok(FileChunk {
            chunk_index,
            total_chunks,
            data,
        })
    }
}

/// Upload result containing checksum and metadata
#[derive(Debug, Clone)]
pub struct UploadResult {
    pub total_bytes: u64,
    pub chunks_received: u32,
    pub checksum: String,
}

impl UploadResult {
    /// Encode result to bytes
    pub fn encode(&self) -> Bytes {
        let json = format!(
            r#"{{"total_bytes":{},"chunks_received":{},"checksum":"{}"}}"#,
            self.total_bytes, self.chunks_received, self.checksum
        );
        Bytes::from(json)
    }

    /// Decode result from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, QuillError> {
        let json = String::from_utf8_lossy(bytes);

        let total_bytes = json
            .split(r#""total_bytes":"#)
            .nth(1)
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let chunks_received = json
            .split(r#""chunks_received":"#)
            .nth(1)
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let checksum = json
            .split(r#""checksum":""#)
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or("")
            .to_string();

        Ok(UploadResult {
            total_bytes,
            chunks_received,
            checksum,
        })
    }
}

/// Handle file upload (client streaming)
///
/// Receives file chunks from client stream and returns upload result
pub async fn handle_upload(
    mut chunk_stream: Pin<Box<dyn Stream<Item = Result<Bytes, QuillError>> + Send>>,
) -> Result<Bytes, QuillError> {
    let mut total_bytes = 0u64;
    let mut chunks_received = 0u32;
    let mut hasher = Sha256::new();
    let mut file_data = BytesMut::new();

    tracing::info!("Starting file upload");

    while let Some(result) = chunk_stream.next().await {
        let chunk_bytes = result?;
        let chunk = FileChunk::decode(&chunk_bytes)?;

        tracing::debug!(
            "Received chunk {}/{} ({} bytes)",
            chunk.chunk_index + 1,
            chunk.total_chunks,
            chunk.data.len()
        );

        // Validate chunk index
        if chunk.chunk_index != chunks_received {
            return Err(QuillError::Rpc(format!(
                "Expected chunk {}, got {}",
                chunks_received, chunk.chunk_index
            )));
        }

        // Check file size limit
        if total_bytes + chunk.data.len() as u64 > MAX_FILE_SIZE as u64 {
            return Err(QuillError::Rpc(format!(
                "File size exceeds maximum of {} bytes",
                MAX_FILE_SIZE
            )));
        }

        // Update hash and accumulate data
        hasher.update(&chunk.data);
        file_data.extend_from_slice(&chunk.data);

        total_bytes += chunk.data.len() as u64;
        chunks_received += 1;

        // Check if this was the last chunk
        if chunk.chunk_index + 1 == chunk.total_chunks {
            tracing::info!(
                "Upload complete: {} bytes in {} chunks",
                total_bytes,
                chunks_received
            );
            break;
        }
    }

    // Compute final checksum
    let checksum = format!("{:x}", hasher.finalize());

    tracing::info!("Checksum: {}", checksum);

    let result = UploadResult {
        total_bytes,
        chunks_received,
        checksum,
    };

    Ok(result.encode())
}

/// Split data into chunks for uploading
pub fn create_chunks(data: &[u8], chunk_size: usize) -> Vec<FileChunk> {
    let total_chunks = (data.len() + chunk_size - 1) / chunk_size;
    let mut chunks = Vec::new();

    for (index, chunk_data) in data.chunks(chunk_size).enumerate() {
        chunks.push(FileChunk {
            chunk_index: index as u32,
            total_chunks: total_chunks as u32,
            data: Bytes::copy_from_slice(chunk_data),
        });
    }

    chunks
}

/// Calculate SHA-256 checksum of data
pub fn calculate_checksum(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_encode_decode() {
        let chunk = FileChunk {
            chunk_index: 5,
            total_chunks: 10,
            data: Bytes::from("test data"),
        };

        let encoded = chunk.encode();
        let decoded = FileChunk::decode(&encoded).unwrap();

        assert_eq!(decoded.chunk_index, chunk.chunk_index);
        assert_eq!(decoded.total_chunks, chunk.total_chunks);
        assert_eq!(decoded.data, chunk.data);
    }

    #[test]
    fn test_create_chunks() {
        let data = vec![0u8; 2500]; // 2.5KB
        let chunks = create_chunks(&data, 1024); // 1KB chunks

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[0].total_chunks, 3);
        assert_eq!(chunks[0].data.len(), 1024);
        assert_eq!(chunks[1].data.len(), 1024);
        assert_eq!(chunks[2].data.len(), 452); // Remaining bytes
    }

    #[test]
    fn test_checksum() {
        let data = b"Hello, world!";
        let checksum = calculate_checksum(data);

        // Known SHA-256 hash of "Hello, world!"
        assert_eq!(
            checksum,
            "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
        );
    }

    #[test]
    fn test_upload_result_encode_decode() {
        let result = UploadResult {
            total_bytes: 1024,
            chunks_received: 5,
            checksum: "abcd1234".to_string(),
        };

        let encoded = result.encode();
        let decoded = UploadResult::decode(&encoded).unwrap();

        assert_eq!(decoded.total_bytes, result.total_bytes);
        assert_eq!(decoded.chunks_received, result.chunks_received);
        assert_eq!(decoded.checksum, result.checksum);
    }
}
