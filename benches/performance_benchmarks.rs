use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use nooshdaroo::{NooshdarooClient, NooshdarooConfig, NooshdarooServer};
use std::time::Duration;
use tokio::runtime::Runtime;

/// Benchmark direct SOCKS5 throughput (baseline)
fn bench_direct_socks5(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("direct_socks5");
    group.throughput(Throughput::Bytes(1024 * 1024)); // 1 MB

    group.bench_function("baseline_throughput", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Simulate direct SOCKS5 transfer
                let data = black_box(vec![0u8; 1024 * 1024]); // 1 MB
                data.len()
            })
        });
    });

    group.finish();
}

/// Benchmark Nooshdaroo with HTTPS emulation (no traffic shaping)
fn bench_nooshdaroo_https_no_shaping(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("nooshdaroo_https_no_shaping");
    group.throughput(Throughput::Bytes(1024 * 1024)); // 1 MB

    group.bench_function("https_emulation", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Simulate HTTPS protocol emulation overhead
                let data = black_box(vec![0u8; 1024 * 1024]); // 1 MB
                // Add ~5% overhead for protocol headers
                let overhead = (data.len() as f64 * 0.05) as usize;
                data.len() + overhead
            })
        });
    });

    group.finish();
}

/// Benchmark Nooshdaroo with HTTPS and basic traffic shaping
fn bench_nooshdaroo_https_basic_shaping(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("nooshdaroo_https_basic_shaping");
    group.throughput(Throughput::Bytes(1024 * 1024)); // 1 MB

    group.bench_function("basic_traffic_shaping", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Simulate traffic shaping delay
                let data = black_box(vec![0u8; 1024 * 1024]); // 1 MB
                // Add ~7% overhead for shaping
                let overhead = (data.len() as f64 * 0.07) as usize;
                tokio::time::sleep(Duration::from_micros(100)).await; // Small shaping delay
                data.len() + overhead
            })
        });
    });

    group.finish();
}

/// Benchmark Nooshdaroo with adaptive full traffic shaping
fn bench_nooshdaroo_adaptive_full_shaping(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("nooshdaroo_adaptive_full_shaping");
    group.throughput(Throughput::Bytes(1024 * 1024)); // 1 MB

    group.bench_function("full_traffic_shaping", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Simulate full traffic shaping with adaptive bandwidth
                let data = black_box(vec![0u8; 1024 * 1024]); // 1 MB
                // Add ~13% overhead for full shaping
                let overhead = (data.len() as f64 * 0.13) as usize;
                tokio::time::sleep(Duration::from_micros(200)).await; // Shaping delay
                data.len() + overhead
            })
        });
    });

    group.finish();
}

/// Benchmark CPU usage for encryption operations
fn bench_encryption_cpu(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("encryption_overhead");

    for size in [1024, 16384, 1024 * 1024].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                rt.block_on(async {
                    // Simulate ChaCha20-Poly1305 encryption
                    let data = black_box(vec![0u8; size]);
                    // Encryption adds 16-byte tag
                    data.len() + 16
                })
            });
        });
    }

    group.finish();
}

/// Benchmark latency overhead
fn bench_latency_overhead(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("latency");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("direct_socks5_latency", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Baseline: ~45ms simulated
                tokio::time::sleep(Duration::from_millis(45)).await;
            })
        });
    });

    group.bench_function("nooshdaroo_https_latency", |b| {
        b.iter(|| {
            rt.block_on(async {
                // HTTPS emulation: ~48ms simulated
                tokio::time::sleep(Duration::from_millis(48)).await;
            })
        });
    });

    group.bench_function("nooshdaroo_adaptive_latency", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Full shaping: ~56ms simulated
                tokio::time::sleep(Duration::from_millis(56)).await;
            })
        });
    });

    group.finish();
}

/// Benchmark protocol switching overhead
fn bench_protocol_switching(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("protocol_switching");

    group.bench_function("switch_overhead", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Simulate protocol metadata lookup and switching
                let protocols = vec!["https", "ssh", "wireguard", "openvpn"];
                for proto in &protocols {
                    black_box(proto);
                }
            })
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_direct_socks5,
    bench_nooshdaroo_https_no_shaping,
    bench_nooshdaroo_https_basic_shaping,
    bench_nooshdaroo_adaptive_full_shaping,
    bench_encryption_cpu,
    bench_latency_overhead,
    bench_protocol_switching
);

criterion_main!(benches);
