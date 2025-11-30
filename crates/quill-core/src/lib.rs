//! Core types and utilities for the Quill RPC framework.
//!
//! This crate provides the foundation types used across all Quill components:
//! - Stream framing (varint encoding, frame parsing)
//! - Problem Details error model
//! - Prism transport profiles
//! - Flow control primitives
//! - Streaming utilities

pub mod error;
pub mod flow_control;
pub mod framing;
pub mod profile;
pub mod stream;

pub use error::{ProblemDetails, QuillError};
pub use flow_control::{CreditTracker, DEFAULT_CREDIT_REFILL, DEFAULT_INITIAL_CREDITS};
pub use framing::{decode_varint, encode_varint, Frame, FrameFlags, FrameParser};
pub use profile::{PrismProfile, ProfilePreference};
pub use stream::{FrameStream, StreamWriter};
