#![no_main]
//! Fuzz target for Problem Details JSON parsing.
//!
//! This fuzzer tests the robustness of Problem Details deserialization
//! against arbitrary JSON input, ensuring it handles malformed JSON gracefully.

use libfuzzer_sys::fuzz_target;
use quill_core::ProblemDetails;

fuzz_target!(|data: &[u8]| {
    // Try to parse as UTF-8 string first
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Attempt to deserialize as ProblemDetails
        match serde_json::from_str::<ProblemDetails>(json_str) {
            Ok(pd) => {
                // Successfully parsed - verify we can serialize it back
                let serialized = pd.to_json();
                assert!(serialized.is_ok(), "Serialization should succeed");

                // Verify Display trait works
                let _ = format!("{}", pd);

                // Verify status is preserved
                assert!(pd.status <= 599, "HTTP status should be valid");
            }
            Err(_) => {
                // Invalid JSON or missing required fields - expected for most input
            }
        }

        // Also try deserializing with serde_json::Value first to catch edge cases
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
            // If it's valid JSON, try converting to ProblemDetails
            let _ = serde_json::from_value::<ProblemDetails>(value);
        }
    }

    // Also try direct byte parsing (may produce different errors)
    let _ = serde_json::from_slice::<ProblemDetails>(data);
});
