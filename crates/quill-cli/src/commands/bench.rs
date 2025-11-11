//! Benchmarking command

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Args;
use futures::stream::{self, StreamExt};
use hdrhistogram::Histogram;
use quill_client::QuillClient;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Args, Debug)]
pub struct BenchArgs {
    /// Path to benchmarks.yaml configuration
    #[arg(short, long, default_value = "benchmarks.yaml")]
    pub config: PathBuf,

    /// Number of concurrent requests
    #[arg(short, long, default_value = "50")]
    pub concurrency: usize,

    /// Duration of the benchmark in seconds
    #[arg(short, long, default_value = "10")]
    pub duration: u64,

    /// Target RPS (requests per second)
    #[arg(short, long)]
    pub rps: Option<u64>,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    pub output: String,
}

#[derive(Debug, Deserialize)]
struct BenchmarkConfig {
    benchmarks: Vec<BenchmarkScenario>,
}

#[derive(Debug, Deserialize)]
struct BenchmarkScenario {
    name: String,
    url: String,
    service: String,
    method: String,
    payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct BenchmarkResults {
    scenario: String,
    duration_secs: u64,
    total_requests: u64,
    successful: u64,
    failed: u64,
    rps: f64,
    latency: LatencyStats,
}

#[derive(Debug, Serialize)]
struct LatencyStats {
    min_us: u64,
    p50_us: u64,
    p90_us: u64,
    p95_us: u64,
    p99_us: u64,
    p999_us: u64,
    max_us: u64,
    mean_us: f64,
}

pub async fn run(args: BenchArgs) -> Result<()> {
    // Check if config file exists
    if !args.config.exists() {
        // If no config file, run adhoc benchmark
        return run_adhoc_benchmark(args).await;
    }

    // Parse configuration
    let config_str = std::fs::read_to_string(&args.config)
        .context("Failed to read benchmarks.yaml")?;
    let config: BenchmarkConfig = serde_yaml::from_str(&config_str)
        .context("Failed to parse benchmarks.yaml")?;

    let mut all_results = Vec::new();

    // Run each scenario
    for scenario in config.benchmarks {
        println!("\nRunning scenario: {}", scenario.name);
        println!("  URL: {}", scenario.url);
        println!("  Service: {}", scenario.service);
        println!  ("  Method: {}", scenario.method);
        println!("  Concurrency: {}", args.concurrency);
        println!("  Duration: {}s", args.duration);

        let results = run_scenario(&scenario, &args).await?;
        all_results.push(results);
    }

    // Output results
    match args.output.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&all_results)?;
            println!("\n{}", json);
        }
        _ => {
            for result in &all_results {
                print_results(result);
            }
        }
    }

    Ok(())
}

async fn run_adhoc_benchmark(_args: BenchArgs) -> Result<()> {
    println!("No benchmarks.yaml found. Example configuration:");
    println!(r#"
benchmarks:
  - name: "Echo Service"
    url: "http://localhost:8080"
    service: "echo.v1.EchoService"
    method: "Echo"
    payload:
      message: "Hello, World!"
"#);

    anyhow::bail!("Please create a benchmarks.yaml configuration file");
}

async fn run_scenario(scenario: &BenchmarkScenario, args: &BenchArgs) -> Result<BenchmarkResults> {
    // Create client
    let client = Arc::new(
        QuillClient::builder()
            .base_url(&scenario.url)
            .build()
            .map_err(|e| anyhow::anyhow!(e))?
    );

    // Serialize payload
    let payload_bytes = serde_json::to_vec(&scenario.payload)?;

    // Create histogram for latency tracking
    let histogram = Arc::new(Mutex::new(
        Histogram::<u64>::new_with_max(60_000_000, 3)
            .context("Failed to create histogram")?,
    ));

    let total_requests = Arc::new(Mutex::new(0u64));
    let successful = Arc::new(Mutex::new(0u64));
    let failed = Arc::new(Mutex::new(0u64));

    let start = Instant::now();
    let duration = Duration::from_secs(args.duration);

    // Calculate delay between requests if RPS is specified
    let delay_per_request = args.rps.map(|rps| {
        Duration::from_micros((1_000_000.0 / rps as f64) as u64)
    });

    // Run concurrent requests
    stream::iter(0..args.concurrency)
        .for_each_concurrent(args.concurrency, |_| {
            let client = Arc::clone(&client);
            let service = scenario.service.clone();
            let method = scenario.method.clone();
            let payload = Bytes::from(payload_bytes.clone());
            let histogram = histogram.clone();
            let total = total_requests.clone();
            let success = successful.clone();
            let fail = failed.clone();

            async move {
                let mut last_request = Instant::now();

                while start.elapsed() < duration {
                    // Rate limiting
                    if let Some(delay) = delay_per_request {
                        let elapsed = last_request.elapsed();
                        if elapsed < delay {
                            tokio::time::sleep(delay - elapsed).await;
                        }
                    }

                    last_request = Instant::now();
                    let req_start = Instant::now();

                    // Make request
                    let result = client
                        .call(&service, &method, payload.clone())
                        .await;

                    let latency_us = req_start.elapsed().as_micros() as u64;

                    // Record results
                    {
                        let mut hist = histogram.lock().await;
                        let _ = hist.record(latency_us);
                    }

                    {
                        let mut total = total.lock().await;
                        *total += 1;
                    }

                    match result {
                        Ok(_) => {
                            let mut success = success.lock().await;
                            *success += 1;
                        }
                        Err(_) => {
                            let mut fail = fail.lock().await;
                            *fail += 1;
                        }
                    }
                }
            }
        })
        .await;

    let elapsed = start.elapsed();
    let total = *total_requests.lock().await;
    let success = *successful.lock().await;
    let fail = *failed.lock().await;

    // Calculate statistics
    let histogram = histogram.lock().await;
    let latency = LatencyStats {
        min_us: histogram.min(),
        p50_us: histogram.value_at_quantile(0.50),
        p90_us: histogram.value_at_quantile(0.90),
        p95_us: histogram.value_at_quantile(0.95),
        p99_us: histogram.value_at_quantile(0.99),
        p999_us: histogram.value_at_quantile(0.999),
        max_us: histogram.max(),
        mean_us: histogram.mean(),
    };

    let rps = total as f64 / elapsed.as_secs_f64();

    Ok(BenchmarkResults {
        scenario: scenario.name.clone(),
        duration_secs: elapsed.as_secs(),
        total_requests: total,
        successful: success,
        failed: fail,
        rps,
        latency,
    })
}

fn print_results(results: &BenchmarkResults) {
    println!("\n========================================");
    println!("Scenario: {}", results.scenario);
    println!("========================================");
    println!("Duration:        {}s", results.duration_secs);
    println!("Total Requests:  {}", results.total_requests);
    println!("Successful:      {}", results.successful);
    println!("Failed:          {}", results.failed);
    println!("RPS:             {:.2}", results.rps);
    println!();
    println!("Latency Statistics (microseconds):");
    println!("  Min:     {:>10}", results.latency.min_us);
    println!("  p50:     {:>10}", results.latency.p50_us);
    println!("  p90:     {:>10}", results.latency.p90_us);
    println!("  p95:     {:>10}", results.latency.p95_us);
    println!("  p99:     {:>10}", results.latency.p99_us);
    println!("  p999:    {:>10}", results.latency.p999_us);
    println!("  Max:     {:>10}", results.latency.max_us);
    println!("  Mean:    {:>10.2}", results.latency.mean_us);
    println!();
    println!("Latency Statistics (milliseconds):");
    println!("  p50:     {:>10.2}", results.latency.p50_us as f64 / 1000.0);
    println!("  p95:     {:>10.2}", results.latency.p95_us as f64 / 1000.0);
    println!("  p99:     {:>10.2}", results.latency.p99_us as f64 / 1000.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bench_args() {
        let args = BenchArgs {
            config: PathBuf::from("test.yaml"),
            concurrency: 100,
            duration: 30,
            rps: Some(1000),
            output: "json".to_string(),
        };

        assert_eq!(args.concurrency, 100);
        assert_eq!(args.duration, 30);
        assert_eq!(args.rps, Some(1000));
    }

    #[test]
    fn test_latency_stats_serialization() {
        let stats = LatencyStats {
            min_us: 100,
            p50_us: 500,
            p90_us: 900,
            p95_us: 950,
            p99_us: 990,
            p999_us: 999,
            max_us: 1000,
            mean_us: 550.0,
        };

        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"min_us\":100"));
        assert!(json.contains("\"p99_us\":990"));
    }

    #[test]
    fn test_benchmark_results_serialization() {
        let results = BenchmarkResults {
            scenario: "Test".to_string(),
            duration_secs: 10,
            total_requests: 1000,
            successful: 990,
            failed: 10,
            rps: 100.0,
            latency: LatencyStats {
                min_us: 100,
                p50_us: 500,
                p90_us: 900,
                p95_us: 950,
                p99_us: 990,
                p999_us: 999,
                max_us: 1000,
                mean_us: 550.0,
            },
        };

        let json = serde_json::to_string(&results).unwrap();
        assert!(json.contains("\"scenario\":\"Test\""));
        assert!(json.contains("\"rps\":100.0"));
    }
}
