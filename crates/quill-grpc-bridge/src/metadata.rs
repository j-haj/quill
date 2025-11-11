//! Metadata and header translation between gRPC and HTTP

use http::HeaderMap;
use tonic::metadata::{MetadataMap, MetadataValue};

/// Convert gRPC metadata to HTTP headers
///
/// Translates gRPC metadata (similar to HTTP/2 headers) to standard HTTP headers.
/// Handles special gRPC headers appropriately.
pub fn grpc_metadata_to_http_headers(metadata: &MetadataMap) -> HeaderMap {
    let mut headers = HeaderMap::new();

    for key_and_value in metadata.iter() {
        match key_and_value {
            tonic::metadata::KeyAndValueRef::Ascii(key, value) => {
                let key_str = key.as_str();

                // Skip gRPC-specific headers that shouldn't be forwarded
                if should_forward_header(key_str) {
                    if let Ok(header_name) = http::header::HeaderName::from_bytes(key_str.as_bytes()) {
                        if let Ok(header_value) = http::header::HeaderValue::from_bytes(value.as_bytes()) {
                            headers.insert(header_name, header_value);
                        }
                    }
                }
            }
            tonic::metadata::KeyAndValueRef::Binary(key, value) => {
                // Binary headers in gRPC end with "-bin"
                // Base64 encode for HTTP transport
                let key_str = key.as_str();
                if should_forward_header(key_str) {
                    let encoded = base64::encode(value.as_ref());
                    if let Ok(header_name) = http::header::HeaderName::from_bytes(key_str.as_bytes()) {
                        if let Ok(header_value) = http::header::HeaderValue::from_str(&encoded) {
                            headers.insert(header_name, header_value);
                        }
                    }
                }
            }
        }
    }

    // Add special headers
    headers.insert(
        http::header::HeaderName::from_static("x-grpc-bridge"),
        http::header::HeaderValue::from_static("quill")
    );

    headers
}

/// Convert HTTP headers to gRPC metadata
///
/// Translates HTTP headers to gRPC metadata format.
pub fn http_headers_to_grpc_metadata(headers: &HeaderMap) -> MetadataMap {
    let mut metadata = MetadataMap::new();

    for (name, value) in headers.iter() {
        let name_str = name.as_str();

        // Skip HTTP-specific headers that shouldn't be forwarded
        if should_forward_to_grpc(name_str) {
            // Binary headers (end with -bin)
            if name_str.ends_with("-bin") {
                if let Ok(decoded) = base64::decode(value.as_bytes()) {
                    if let Ok(key) = tonic::metadata::MetadataKey::from_bytes(name_str.as_bytes()) {
                        let metadata_value = MetadataValue::from_bytes(&decoded);
                        metadata.insert_bin(key, metadata_value);
                    }
                }
            } else {
                // ASCII headers
                if let Ok(key) = tonic::metadata::MetadataKey::from_bytes(name_str.as_bytes()) {
                    if let Ok(value_str) = value.to_str() {
                        if let Ok(metadata_value) = MetadataValue::try_from(value_str) {
                            metadata.insert(key, metadata_value);
                        }
                    }
                }
            }
        }
    }

    metadata
}

/// Check if a gRPC header should be forwarded to HTTP
fn should_forward_header(key: &str) -> bool {
    // Skip gRPC internal headers
    !key.starts_with("grpc-") &&
    !key.starts_with(":") && // HTTP/2 pseudo-headers
    key != "content-type" &&
    key != "te" &&
    key != "user-agent"
}

/// Check if an HTTP header should be forwarded to gRPC
fn should_forward_to_grpc(key: &str) -> bool {
    // Skip HTTP-specific headers
    key != "host" &&
    key != "connection" &&
    key != "keep-alive" &&
    key != "transfer-encoding" &&
    key != "upgrade" &&
    key != "x-grpc-bridge" &&
    !key.starts_with(":")
}

// Add base64 encoding/decoding using a simple implementation
mod base64 {
    pub fn encode(data: &[u8]) -> String {
        base64_simd::STANDARD.encode_to_string(data)
    }

    pub fn decode(data: &[u8]) -> Result<Vec<u8>, String> {
        base64_simd::STANDARD
            .decode_to_vec(data)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_metadata_to_http_headers() {
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", "Bearer token123".parse().unwrap());
        metadata.insert("custom-header", "value".parse().unwrap());

        let headers = grpc_metadata_to_http_headers(&metadata);

        assert!(headers.contains_key("authorization"));
        assert!(headers.contains_key("custom-header"));
        assert!(headers.contains_key("x-grpc-bridge"));
    }

    #[test]
    fn test_http_headers_to_grpc_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer token123".parse().unwrap()
        );
        headers.insert(
            http::header::HeaderName::from_static("custom-header"),
            "value".parse().unwrap()
        );

        let metadata = http_headers_to_grpc_metadata(&headers);

        assert!(metadata.contains_key("authorization"));
        assert!(metadata.contains_key("custom-header"));
    }

    #[test]
    fn test_filters_grpc_internal_headers() {
        assert!(!should_forward_header("grpc-status"));
        assert!(!should_forward_header("grpc-message"));
        assert!(!should_forward_header(":authority"));
        assert!(should_forward_header("custom-header"));
    }

    #[test]
    fn test_filters_http_specific_headers() {
        assert!(!should_forward_to_grpc("host"));
        assert!(!should_forward_to_grpc("connection"));
        assert!(should_forward_to_grpc("authorization"));
        assert!(should_forward_to_grpc("custom-header"));
    }
}
