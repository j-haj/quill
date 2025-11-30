#![no_main]
//! Fuzz target for varint encoding/decoding.
//!
//! This fuzzer tests the robustness of varint operations against arbitrary input,
//! ensuring proper handling of malformed varints and roundtrip consistency.

use arbitrary::Arbitrary;
use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use quill_core::{decode_varint, encode_varint};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // A value to encode and verify roundtrip
    value: u64,
    // Raw bytes to try decoding
    raw: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    // Test 1: Roundtrip encoding/decoding of arbitrary values
    {
        let mut buf = BytesMut::new();
        encode_varint(input.value, &mut buf);

        let mut cursor = std::io::Cursor::new(&buf[..]);
        match decode_varint(&mut cursor) {
            Some(decoded) => {
                assert_eq!(
                    decoded, input.value,
                    "Varint roundtrip failed: {} != {}",
                    decoded, input.value
                );
            }
            None => {
                panic!("Failed to decode varint that was just encoded");
            }
        }
    }

    // Test 2: Decoding arbitrary bytes should not panic
    {
        let mut cursor = std::io::Cursor::new(&input.raw[..]);
        match decode_varint(&mut cursor) {
            Some(value) => {
                // If we successfully decoded, verify the value is sensible
                // (no overflow checks needed, decode_varint handles this)
                let _ = value;
            }
            None => {
                // Invalid varint or incomplete - expected for most random input
            }
        }
    }

    // Test 3: Test edge cases for varint encoding size
    {
        let test_values = [
            0u64,
            1,
            127,
            128,
            16383,
            16384,
            u32::MAX as u64,
            u64::MAX,
        ];

        for &val in &test_values {
            let mut buf = BytesMut::new();
            encode_varint(val, &mut buf);

            let mut cursor = std::io::Cursor::new(&buf[..]);
            let decoded = decode_varint(&mut cursor).expect("Should decode edge case");
            assert_eq!(decoded, val);
        }
    }
});
