//! Security utilities for Quill RPC server
//!
//! This module provides security checks for:
//! - 0-RTT replay attack prevention
//! - Compression side-channel mitigation
//! - Request validation

use http::StatusCode;
use quill_core::ProblemDetails;
use std::collections::HashSet;

/// Header name for indicating 0-RTT/early data
pub const EARLY_DATA_HEADER: &str = "Early-Data";

/// HTTP status code for "Too Early" (425)
/// Used to reject 0-RTT requests for non-idempotent methods
pub const STATUS_TOO_EARLY: u16 = 425;

/// Idempotency check for RPC methods
///
/// Methods are considered idempotent if they can be safely retried
/// without side effects. This is critical for 0-RTT security.
#[derive(Debug, Clone)]
pub struct IdempotencyChecker {
    /// Set of idempotent method paths
    idempotent_methods: HashSet<String>,
}

impl IdempotencyChecker {
    /// Create a new idempotency checker
    pub fn new() -> Self {
        Self {
            idempotent_methods: HashSet::new(),
        }
    }

    /// Register a method as idempotent
    pub fn register_idempotent(&mut self, path: impl Into<String>) {
        self.idempotent_methods.insert(path.into());
    }

    /// Check if a method is idempotent
    pub fn is_idempotent(&self, path: &str) -> bool {
        self.idempotent_methods.contains(path)
    }

    /// Validate a 0-RTT request
    ///
    /// Returns Ok(()) if the request is allowed, or Err with a ProblemDetails
    /// if the request should be rejected (non-idempotent method on 0-RTT).
    pub fn validate_early_data(&self, path: &str, is_early_data: bool) -> Result<(), ProblemDetails> {
        if is_early_data && !self.is_idempotent(path) {
            return Err(ProblemDetails::new(
                StatusCode::from_u16(STATUS_TOO_EARLY).unwrap_or(StatusCode::BAD_REQUEST),
                "Request rejected due to early data",
            )
            .with_detail(format!(
                "Method '{}' is not idempotent and cannot be sent with 0-RTT data. \
                 Please retry without early data.",
                path
            )));
        }
        Ok(())
    }
}

impl Default for IdempotencyChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a request contains early data (0-RTT)
///
/// This checks for the Early-Data header which proxies/load balancers
/// set when the request arrived on 0-RTT data.
pub fn is_early_data_request(headers: &http::HeaderMap) -> bool {
    headers
        .get(EARLY_DATA_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Compression side-channel protection
///
/// Certain secrets should never be compressed to prevent CRIME/BREACH-style attacks.
#[derive(Debug, Clone)]
pub struct CompressionExclusions {
    /// Headers that should never be compressed
    excluded_headers: HashSet<String>,
}

impl CompressionExclusions {
    /// Create with default exclusions (authentication headers)
    pub fn default_exclusions() -> Self {
        let mut excluded = HashSet::new();
        excluded.insert("authorization".to_string());
        excluded.insert("cookie".to_string());
        excluded.insert("set-cookie".to_string());
        excluded.insert("x-api-key".to_string());
        excluded.insert("x-auth-token".to_string());
        Self {
            excluded_headers: excluded,
        }
    }

    /// Add a header to the exclusion list
    pub fn add_exclusion(&mut self, header: impl Into<String>) {
        self.excluded_headers.insert(header.into().to_lowercase());
    }

    /// Check if a header should be excluded from compression
    pub fn should_exclude(&self, header_name: &str) -> bool {
        self.excluded_headers.contains(&header_name.to_lowercase())
    }
}

impl Default for CompressionExclusions {
    fn default() -> Self {
        Self::default_exclusions()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idempotency_checker() {
        let mut checker = IdempotencyChecker::new();
        checker.register_idempotent("image.v1.ImageService/GetMetadata");

        assert!(checker.is_idempotent("image.v1.ImageService/GetMetadata"));
        assert!(!checker.is_idempotent("image.v1.ImageService/Upload"));
    }

    #[test]
    fn test_validate_early_data_idempotent() {
        let mut checker = IdempotencyChecker::new();
        checker.register_idempotent("image.v1.ImageService/GetMetadata");

        // Idempotent method with early data should be allowed
        assert!(checker
            .validate_early_data("image.v1.ImageService/GetMetadata", true)
            .is_ok());
    }

    #[test]
    fn test_validate_early_data_non_idempotent() {
        let checker = IdempotencyChecker::new();

        // Non-idempotent method with early data should be rejected
        let result = checker.validate_early_data("image.v1.ImageService/Upload", true);
        assert!(result.is_err());

        let pd = result.unwrap_err();
        assert_eq!(pd.status, STATUS_TOO_EARLY);
    }

    #[test]
    fn test_validate_non_early_data() {
        let checker = IdempotencyChecker::new();

        // Non-early data requests should always be allowed
        assert!(checker
            .validate_early_data("image.v1.ImageService/Upload", false)
            .is_ok());
    }

    #[test]
    fn test_is_early_data_request() {
        let mut headers = http::HeaderMap::new();
        assert!(!is_early_data_request(&headers));

        headers.insert(EARLY_DATA_HEADER, "1".parse().unwrap());
        assert!(is_early_data_request(&headers));

        headers.insert(EARLY_DATA_HEADER, "0".parse().unwrap());
        assert!(!is_early_data_request(&headers));
    }

    #[test]
    fn test_compression_exclusions() {
        let exclusions = CompressionExclusions::default_exclusions();

        assert!(exclusions.should_exclude("Authorization"));
        assert!(exclusions.should_exclude("AUTHORIZATION")); // case insensitive
        assert!(exclusions.should_exclude("cookie"));
        assert!(exclusions.should_exclude("x-api-key"));
        assert!(!exclusions.should_exclude("content-type"));
    }

    #[test]
    fn test_add_compression_exclusion() {
        let mut exclusions = CompressionExclusions::default_exclusions();
        exclusions.add_exclusion("X-Custom-Secret");

        assert!(exclusions.should_exclude("x-custom-secret"));
    }
}
