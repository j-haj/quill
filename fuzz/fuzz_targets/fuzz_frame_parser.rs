#![no_main]
//! Fuzz target for the Quill frame parser.
//!
//! This fuzzer tests the robustness of the frame parser against arbitrary input,
//! ensuring it handles malformed frames gracefully without panicking.

use libfuzzer_sys::fuzz_target;
use quill_core::FrameParser;

fuzz_target!(|data: &[u8]| {
    // Create a parser and feed it arbitrary data
    let mut parser = FrameParser::new();
    parser.feed(data);

    // Try to parse frames until we can't extract any more
    loop {
        match parser.parse_frame() {
            Ok(Some(frame)) => {
                // Successfully parsed a frame - verify invariants
                // 1. Flags should always be valid (any u8 is valid as flags)
                let _ = frame.flags.is_data();
                let _ = frame.flags.is_end_stream();
                let _ = frame.flags.is_cancel();
                let _ = frame.flags.is_credit();

                // 2. If it's a credit frame, decode should work
                if frame.flags.is_credit() {
                    let _ = frame.decode_credit();
                }

                // 3. Encoding the frame should not panic
                let _ = frame.encode();
            }
            Ok(None) => {
                // Not enough data for a complete frame - this is expected
                break;
            }
            Err(_) => {
                // Frame error (too large, etc.) - this is expected for malformed input
                break;
            }
        }
    }
});
