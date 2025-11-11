use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use quill_core::{Frame, FrameParser};
use bytes::Bytes;

fn bench_frame_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_encoding");

    // Benchmark small payload (100 bytes)
    let small_payload = Bytes::from(vec![0u8; 100]);
    group.throughput(Throughput::Bytes(100));
    group.bench_function("encode_100b", |b| {
        b.iter(|| {
            let frame = Frame::data(black_box(small_payload.clone()));
            black_box(frame.encode())
        })
    });

    // Benchmark medium payload (1KB)
    let medium_payload = Bytes::from(vec![0u8; 1024]);
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("encode_1kb", |b| {
        b.iter(|| {
            let frame = Frame::data(black_box(medium_payload.clone()));
            black_box(frame.encode())
        })
    });

    // Benchmark large payload (1MB)
    let large_payload = Bytes::from(vec![0u8; 1024 * 1024]);
    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("encode_1mb", |b| {
        b.iter(|| {
            let frame = Frame::data(black_box(large_payload.clone()));
            black_box(frame.encode())
        })
    });

    group.finish();
}

fn bench_frame_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_decoding");

    // Prepare encoded frames
    let small_frame = Frame::data(Bytes::from(vec![0u8; 100])).encode();
    let medium_frame = Frame::data(Bytes::from(vec![0u8; 1024])).encode();
    let large_frame = Frame::data(Bytes::from(vec![0u8; 1024 * 1024])).encode();

    // Benchmark small frame (100 bytes)
    group.throughput(Throughput::Bytes(100));
    group.bench_function("decode_100b", |b| {
        b.iter(|| {
            let mut parser = FrameParser::new();
            parser.feed(&black_box(small_frame.clone()));
            black_box(parser.parse_frame().unwrap())
        })
    });

    // Benchmark medium frame (1KB)
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("decode_1kb", |b| {
        b.iter(|| {
            let mut parser = FrameParser::new();
            parser.feed(&black_box(medium_frame.clone()));
            black_box(parser.parse_frame().unwrap())
        })
    });

    // Benchmark large frame (1MB)
    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("decode_1mb", |b| {
        b.iter(|| {
            let mut parser = FrameParser::new();
            parser.feed(&black_box(large_frame.clone()));
            black_box(parser.parse_frame().unwrap())
        })
    });

    group.finish();
}

fn bench_frame_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_roundtrip");

    let payloads = vec![
        ("100b", Bytes::from(vec![0u8; 100])),
        ("1kb", Bytes::from(vec![0u8; 1024])),
        ("10kb", Bytes::from(vec![0u8; 10 * 1024])),
    ];

    for (name, payload) in payloads {
        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_function(name, |b| {
            b.iter(|| {
                // Encode
                let frame = Frame::data(black_box(payload.clone()));
                let encoded = frame.encode();

                // Decode
                let mut parser = FrameParser::new();
                parser.feed(&encoded);
                black_box(parser.parse_frame().unwrap())
            })
        });
    }

    group.finish();
}

fn bench_varint_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("varint_encoding");

    // Different size varints
    group.bench_function("1_byte", |b| {
        b.iter(|| {
            let frame = Frame::data(black_box(Bytes::from(vec![0u8; 10])));
            black_box(frame.encode())
        })
    });

    group.bench_function("2_byte", |b| {
        b.iter(|| {
            let frame = Frame::data(black_box(Bytes::from(vec![0u8; 200])));
            black_box(frame.encode())
        })
    });

    group.bench_function("3_byte", |b| {
        b.iter(|| {
            let frame = Frame::data(black_box(Bytes::from(vec![0u8; 20000])));
            black_box(frame.encode())
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_frame_encoding,
    bench_frame_decoding,
    bench_frame_roundtrip,
    bench_varint_encoding
);
criterion_main!(benches);
