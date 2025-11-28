//! REST gateway for Quill RPC services with OpenAPI support.
//!
//! This crate provides a REST gateway that maps HTTP REST requests to Quill RPC calls.
//! It supports:
//! - Clean REST URLs (e.g., `/api/v1/users/123`)
//! - HTTP method routing (GET/POST/PUT/PATCH/DELETE)
//! - JSON request/response conversion
//! - OpenAPI 3.0 specification generation
//! - Problem Details error responses
//! - Authentication, CORS, and rate limiting middleware

pub mod converter;
pub mod error;
pub mod mapping;
pub mod middleware;
pub mod openapi;
pub mod router;

pub use converter::MessageConverter;
pub use error::{GatewayError, GatewayResult};
pub use mapping::{HttpMethodMapping, RouteMapping, UrlTemplate};
pub use middleware::{AuthConfig, AuthMiddleware, CorsConfig, CorsMiddleware, RateLimitConfig, RateLimitMiddleware};
pub use openapi::OpenApiSpec;
pub use router::{RestGateway, RestGatewayBuilder};
