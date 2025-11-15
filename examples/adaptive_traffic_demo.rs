//! Demo of advanced traffic shaping and adaptive bandwidth features
//!
//! This example demonstrates how to use application profiles and
//! adaptive bandwidth optimization in your code.

use nooshdaroo::{
    AdaptiveRateLimiter, ApplicationEmulator, ApplicationProfile, BandwidthController, QualityTier,
};
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("=== Nooshdaroo Advanced Traffic Shaping Demo ===\n");

    // Demo 1: Application Profiles
    demo_application_profiles();

    // Demo 2: Bandwidth Optimization
    demo_bandwidth_optimization();

    // Demo 3: Adaptive Rate Limiting
    demo_adaptive_rate_limiting().await;

    println!("\n=== Demo Complete ===");
}

fn demo_application_profiles() {
    println!("--- Demo 1: Application Traffic Profiles ---\n");

    // Available profiles
    println!("Available profiles: {:?}\n", ApplicationProfile::available());

    // Load Zoom profile
    let zoom_profile = ApplicationProfile::zoom();
    println!("Loaded: {} ({:?})", zoom_profile.name, zoom_profile.category);
    println!("  Burst patterns: {}", zoom_profile.burst_patterns.len());
    println!("  Connection states: {}", zoom_profile.states.len());
    println!(
        "  Session duration: {:?}\n",
        zoom_profile.session_duration
    );

    // Create emulator
    let mut emulator = ApplicationEmulator::new(zoom_profile);

    // Generate some packets
    println!("Generating 10 packets:");
    for i in 1..=10 {
        let size = emulator.generate_upstream_size();
        let delay = emulator.generate_delay(true);

        print!("  Packet {}: {} bytes", i, size);

        // Check for bursts
        if let Some(burst) = emulator.should_burst() {
            println!(
                " [BURST: {} × {} bytes]",
                burst.packet_count, burst.packet_size
            );
        } else {
            println!(" (delay: {:?})", delay);
        }
    }

    println!();
}

fn demo_bandwidth_optimization() {
    println!("--- Demo 2: Adaptive Bandwidth Optimization ---\n");

    let mut controller = BandwidthController::new();

    // Simulate network conditions over time
    let scenarios = vec![
        ("Good network", Duration::from_millis(30), false, 10_000_000),
        ("Decent network", Duration::from_millis(120), false, 5_000_000),
        ("Poor network", Duration::from_millis(400), true, 800_000),
        (
            "Very poor network",
            Duration::from_millis(800),
            true,
            200_000,
        ),
        ("Recovering", Duration::from_millis(150), false, 4_000_000),
    ];

    for (desc, rtt, has_loss, _throughput) in scenarios {
        println!("{}", desc);

        // Record measurements
        for _ in 0..15 {
            controller.record_rtt(rtt);
            controller.record_packet(1400, has_loss);
        }

        // Update quality
        controller.update();

        let metrics = controller.metrics();
        let profile = controller.current_profile();

        println!("  RTT: {:?}", metrics.rtt);
        println!("  Packet Loss: {:.2}%", metrics.packet_loss * 100.0);
        println!("  Quality Tier: {:?}", profile.tier);
        println!("  Packet Size: {} bytes", profile.max_packet_size);
        println!(
            "  Compression: {}",
            if profile.enable_compression {
                format!("Level {}", profile.compression_level)
            } else {
                "None".to_string()
            }
        );
        println!();

        // Sleep to allow cooldown
        std::thread::sleep(Duration::from_millis(100));
    }
}

async fn demo_adaptive_rate_limiting() {
    println!("--- Demo 3: Adaptive Rate Limiting ---\n");

    let mut limiter = AdaptiveRateLimiter::new(5_000_000); // 5 Mbps

    println!("Initial rate: {} Mbps", limiter.current_rate() / 125_000);

    // Simulate good network
    println!("\nSimulating good network conditions...");
    for _ in 0..10 {
        limiter.record_rtt(Duration::from_millis(40));
        limiter.record_packet(1400, false);
    }

    // Try to send data
    if limiter.try_send(100_000) {
        println!("  ✓ Sent 100 KB immediately");
    }

    // Wait for larger amount
    println!("  Waiting for 500 KB quota...");
    limiter.wait_for(500_000).await;
    println!("  ✓ Sent 500 KB");

    let metrics = limiter.metrics();
    println!("\nFinal metrics:");
    println!("  RTT: {:?}", metrics.rtt);
    println!("  Throughput: {} Mbps", metrics.throughput / 125_000);
    println!("  Current rate: {} Mbps", limiter.current_rate() / 125_000);
}
