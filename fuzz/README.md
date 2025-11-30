# Quill Fuzz Testing

This directory contains fuzz testing targets for Quill's critical parsing components.

## Prerequisites

Fuzz testing requires:
- Rust nightly toolchain
- `cargo-fuzz`

```bash
# Install nightly
rustup toolchain install nightly

# Install cargo-fuzz
cargo +nightly install cargo-fuzz
```

## Fuzz Targets

### fuzz_frame_parser

Tests the stream frame parser against arbitrary binary input.

**What it tests:**
- Varint decoding robustness
- Frame header parsing
- Payload extraction
- Flag handling (DATA, END_STREAM, CANCEL, CREDIT)
- Oversized frame rejection (> 4MB max)

**Run:**
```bash
cargo +nightly fuzz run fuzz_frame_parser
```

### fuzz_problem_details

Tests Problem Details (RFC 7807) JSON deserialization.

**What it tests:**
- JSON parsing robustness
- Required field validation
- Optional field handling
- Re-serialization consistency
- Display trait formatting

**Run:**
```bash
cargo +nightly fuzz run fuzz_problem_details
```

### fuzz_varint

Tests protobuf varint encoding and decoding.

**What it tests:**
- Encoding/decoding roundtrip consistency
- Overflow handling (values > 64 bits)
- Edge cases (0, u64::MAX, boundaries)
- Incomplete varint handling

**Run:**
```bash
cargo +nightly fuzz run fuzz_varint
```

## Running Fuzz Tests

### Basic Usage

```bash
# Run a specific target
cargo +nightly fuzz run fuzz_frame_parser

# Run for a specific duration
cargo +nightly fuzz run fuzz_frame_parser -- -max_total_time=60

# Run with specific number of jobs
cargo +nightly fuzz run fuzz_frame_parser -- -jobs=4
```

### Adding Corpus Seeds

Better coverage can be achieved by providing seed inputs:

```bash
# Create corpus directories
mkdir -p corpus/fuzz_frame_parser
mkdir -p corpus/fuzz_problem_details
mkdir -p corpus/fuzz_varint

# Add valid frame (5-byte payload, DATA flag)
echo -ne '\x05\x01hello' > corpus/fuzz_frame_parser/valid_data_frame

# Add end-of-stream frame
echo -ne '\x00\x02' > corpus/fuzz_frame_parser/end_stream

# Add valid Problem Details
echo '{"type":"urn:quill:error:404","title":"Not Found","status":404}' > corpus/fuzz_problem_details/404.json

# Add valid varint (value: 150)
echo -ne '\x96\x01' > corpus/fuzz_varint/varint_150
```

### Viewing Results

```bash
# Show coverage
cargo +nightly fuzz coverage fuzz_frame_parser

# List crashes
ls fuzz/artifacts/fuzz_frame_parser/
```

### Reproducing Crashes

```bash
# Run with a specific crash input
cargo +nightly fuzz run fuzz_frame_parser fuzz/artifacts/fuzz_frame_parser/crash-xxxxx
```

## Continuous Fuzzing

For CI/CD integration, run fuzz tests for a fixed duration:

```bash
#!/bin/bash
set -e

FUZZ_TIME=300  # 5 minutes per target

for target in fuzz_frame_parser fuzz_problem_details fuzz_varint; do
    echo "Fuzzing $target for ${FUZZ_TIME}s..."
    cargo +nightly fuzz run $target -- -max_total_time=$FUZZ_TIME
done

echo "All fuzz targets completed without crashes"
```

## Frame Format Reference

The Quill frame format being tested:

```
[length varint][flags byte][payload bytes]
```

Flags:
- `0x01` - DATA: Contains payload data
- `0x02` - END_STREAM: Last frame in stream
- `0x04` - CANCEL: Cancel the stream
- `0x08` - CREDIT: Flow control credit grant

Max frame size: 4MB (4,194,304 bytes)
