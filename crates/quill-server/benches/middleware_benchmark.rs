use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use quill_server::middleware::*;
use std::sync::Arc;
use bytes::Bytes;

fn bench_rate_limiter(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter");

    // Single token acquisition
    let limiter = RateLimiter::new(1000.0, 100.0);
    group.bench_function("single_acquire", |b| {
        b.iter(|| {
            black_box(limiter.try_acquire())
        })
    });

    // Bulk token acquisition
    group.bench_function("bulk_acquire_10", |b| {
        b.iter(|| {
            black_box(limiter.try_acquire_n(10.0))
        })
    });

    // Check available tokens
    group.bench_function("available", |b| {
        b.iter(|| {
            black_box(limiter.available())
        })
    });

    group.finish();
}

fn bench_auth_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_validation");

    // API key validation
    let mut validator = ApiKeyValidator::new();
    for i in 0..100 {
        validator.add_key(format!("key{}", i), format!("user{}", i));
    }

    group.bench_function("valid_key", |b| {
        b.iter(|| {
            black_box(validator.validate(black_box("key50")))
        })
    });

    group.bench_function("invalid_key", |b| {
        b.iter(|| {
            black_box(validator.validate(black_box("invalid")))
        })
    });

    group.finish();
}

fn bench_metrics_collection(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_collection");

    let metrics = Arc::new(MetricsCollector::new());

    // Record operations
    group.bench_function("record_request", |b| {
        let m = metrics.clone();
        b.iter(|| {
            black_box(m.record_request())
        })
    });

    group.bench_function("record_success", |b| {
        let m = metrics.clone();
        b.iter(|| {
            black_box(m.record_success())
        })
    });

    group.bench_function("record_failure", |b| {
        let m = metrics.clone();
        b.iter(|| {
            black_box(m.record_failure())
        })
    });

    group.bench_function("record_bytes", |b| {
        let m = metrics.clone();
        b.iter(|| {
            black_box(m.record_bytes_sent(1024));
            black_box(m.record_bytes_received(512))
        })
    });

    // Get metrics snapshot
    group.bench_function("get_snapshot", |b| {
        let m = metrics.clone();
        b.iter(|| {
            black_box(m.get_metrics())
        })
    });

    group.finish();
}

fn bench_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression");

    // Compression benchmarks
    let small_data = Bytes::from(vec![0u8; 100]);
    group.throughput(Throughput::Bytes(100));
    group.bench_function("compress_100b", |b| {
        b.iter(|| {
            black_box(compress_zstd(&black_box(small_data.clone()), 3).unwrap())
        })
    });

    let medium_data = Bytes::from(vec![0u8; 10 * 1024]);
    group.throughput(Throughput::Bytes(10 * 1024));
    group.bench_function("compress_10kb", |b| {
        b.iter(|| {
            black_box(compress_zstd(&black_box(medium_data.clone()), 3).unwrap())
        })
    });

    let large_data = Bytes::from(vec![0u8; 1024 * 1024]);
    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("compress_1mb", |b| {
        b.iter(|| {
            black_box(compress_zstd(&black_box(large_data.clone()), 3).unwrap())
        })
    });

    // Decompression benchmarks
    let compressed_small = compress_zstd(&small_data, 3).unwrap();
    group.throughput(Throughput::Bytes(100));
    group.bench_function("decompress_100b", |b| {
        b.iter(|| {
            black_box(decompress_zstd(&black_box(compressed_small.clone())).unwrap())
        })
    });

    let compressed_medium = compress_zstd(&medium_data, 3).unwrap();
    group.throughput(Throughput::Bytes(10 * 1024));
    group.bench_function("decompress_10kb", |b| {
        b.iter(|| {
            black_box(decompress_zstd(&black_box(compressed_medium.clone())).unwrap())
        })
    });

    let compressed_large = compress_zstd(&large_data, 3).unwrap();
    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("decompress_1mb", |b| {
        b.iter(|| {
            black_box(decompress_zstd(&black_box(compressed_large.clone())).unwrap())
        })
    });

    group.finish();
}

fn bench_compression_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_levels");

    let data = Bytes::from(vec![0u8; 10 * 1024]);
    group.throughput(Throughput::Bytes(10 * 1024));

    for level in [1, 3, 6, 9, 15, 22] {
        group.bench_function(format!("level_{}", level), |b| {
            b.iter(|| {
                black_box(compress_zstd(&black_box(data.clone()), level).unwrap())
            })
        });
    }

    group.finish();
}

fn bench_middleware_stack(c: &mut Criterion) {
    let mut group = c.benchmark_group("middleware_stack");

    // Simulate a full middleware stack
    let auth = Arc::new({
        let mut validator = ApiKeyValidator::new();
        validator.add_key("test_key".to_string(), "test_user".to_string());
        validator
    });
    let rate_limiter = Arc::new(RateLimiter::new(10000.0, 1000.0));
    let metrics = Arc::new(MetricsCollector::new());

    let data = Bytes::from(vec![0u8; 1024]);

    group.bench_function("full_stack", |b| {
        b.iter(|| {
            // Auth
            let _ = black_box(auth.validate("test_key"));

            // Rate limiting
            let _ = black_box(rate_limiter.try_acquire());

            // Metrics
            metrics.record_request();
            metrics.record_bytes_received(1024);

            // Compression
            let compressed = compress_zstd(&data, 3).unwrap();

            // More metrics
            metrics.record_bytes_sent(compressed.len() as u64);
            metrics.record_success();

            black_box(compressed)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_rate_limiter,
    bench_auth_validation,
    bench_metrics_collection,
    bench_compression,
    bench_compression_levels,
    bench_middleware_stack
);
criterion_main!(benches);
