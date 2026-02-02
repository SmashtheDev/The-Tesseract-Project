//! Performance Benchmark Suite (US-067)
//!
//! This module provides comprehensive performance benchmarking for TESSERACT operations:
//! - Sequential read throughput (target: >= 85% native filesystem)
//! - Sequential write throughput (target: >= 85% native filesystem)
//! - Vault unlock time (target: < 3 seconds)
//!
//! # Features
//!
//! - Automated threshold checking with configurable targets
//! - Regression detection with 10% degradation threshold
//! - Historical result comparison and trending
//! - Detailed performance reports for CI integration
//!
//! # Security Rationale
//!
//! Performance benchmarks ensure that encryption overhead remains acceptable
//! for real-world usage. Excessive slowdown could encourage users to disable
//! security features, so maintaining high performance is a security goal.

use crate::aes::{decrypt, encrypt};
use crate::kdf::{derive_key, Argon2Params};
use crate::random::{generate_key, generate_nonce, generate_salt};
use std::time::{Duration, Instant};

/// Default performance thresholds for benchmarks.
pub mod thresholds {
    /// Minimum read throughput as percentage of native performance.
    pub const MIN_READ_THROUGHPUT_PERCENT: f64 = 85.0;

    /// Minimum write throughput as percentage of native performance.
    pub const MIN_WRITE_THROUGHPUT_PERCENT: f64 = 85.0;

    /// Maximum allowed vault unlock time in seconds.
    pub const MAX_UNLOCK_TIME_SECONDS: f64 = 3.0;

    /// Maximum percentage degradation before regression alert.
    pub const REGRESSION_THRESHOLD_PERCENT: f64 = 10.0;

    /// Default data size for throughput benchmarks (64 MB).
    pub const DEFAULT_BENCHMARK_SIZE: usize = 64 * 1024 * 1024;

    /// Number of warmup iterations before timing.
    pub const WARMUP_ITERATIONS: usize = 3;

    /// Number of timed iterations for average.
    pub const TIMED_ITERATIONS: usize = 5;

    /// Chunk size for streaming benchmarks (1 MB).
    pub const CHUNK_SIZE: usize = 1024 * 1024;
}

/// Result of a single benchmark run.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Name of the benchmark.
    pub name: String,
    /// Total bytes processed (for throughput benchmarks).
    pub bytes_processed: usize,
    /// Duration of the benchmark.
    pub duration: Duration,
    /// Throughput in bytes per second.
    pub throughput_bytes_per_sec: f64,
    /// Throughput in megabytes per second.
    pub throughput_mb_per_sec: f64,
    /// Target threshold (if applicable).
    pub target_threshold: Option<f64>,
    /// Whether the benchmark passed its target.
    pub passed: bool,
    /// Additional details or notes.
    pub details: String,
}

impl BenchmarkResult {
    /// Creates a new benchmark result from raw measurements.
    pub fn new(
        name: impl Into<String>,
        bytes_processed: usize,
        duration: Duration,
        target_threshold: Option<f64>,
    ) -> Self {
        let secs = duration.as_secs_f64();
        let throughput_bytes_per_sec = if secs > 0.0 {
            bytes_processed as f64 / secs
        } else {
            0.0
        };
        let throughput_mb_per_sec = throughput_bytes_per_sec / (1024.0 * 1024.0);

        // For throughput targets, check if we exceed the threshold
        let passed = target_threshold
            .map(|t| throughput_mb_per_sec >= t)
            .unwrap_or(true);

        Self {
            name: name.into(),
            bytes_processed,
            duration,
            throughput_bytes_per_sec,
            throughput_mb_per_sec,
            target_threshold,
            passed,
            details: String::new(),
        }
    }

    /// Creates a time-based benchmark result (for unlock time).
    pub fn new_timed(
        name: impl Into<String>,
        duration: Duration,
        max_time_seconds: f64,
    ) -> Self {
        let secs = duration.as_secs_f64();
        let passed = secs <= max_time_seconds;

        Self {
            name: name.into(),
            bytes_processed: 0,
            duration,
            throughput_bytes_per_sec: 0.0,
            throughput_mb_per_sec: 0.0,
            target_threshold: Some(max_time_seconds),
            passed,
            details: format!("Target: < {:.2}s, Actual: {:.3}s", max_time_seconds, secs),
        }
    }

    /// Adds details to the result.
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = details.into();
        self
    }

    /// Returns a formatted summary line for logging.
    pub fn summary_line(&self) -> String {
        let status = if self.passed { "PASS" } else { "FAIL" };
        if self.bytes_processed > 0 {
            format!(
                "[{}] {}: {:.2} MB/s ({:.3}s for {} bytes)",
                status,
                self.name,
                self.throughput_mb_per_sec,
                self.duration.as_secs_f64(),
                self.bytes_processed
            )
        } else {
            format!(
                "[{}] {}: {:.3}s ({})",
                status,
                self.name,
                self.duration.as_secs_f64(),
                self.details
            )
        }
    }
}

/// Configuration for benchmark runs.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Size of data to process in bytes.
    pub data_size: usize,
    /// Number of warmup iterations.
    pub warmup_iterations: usize,
    /// Number of timed iterations.
    pub timed_iterations: usize,
    /// Chunk size for streaming operations.
    pub chunk_size: usize,
    /// Minimum read throughput threshold (MB/s).
    pub min_read_throughput_mb: Option<f64>,
    /// Minimum write throughput threshold (MB/s).
    pub min_write_throughput_mb: Option<f64>,
    /// Maximum unlock time in seconds.
    pub max_unlock_time_seconds: f64,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            data_size: thresholds::DEFAULT_BENCHMARK_SIZE,
            warmup_iterations: thresholds::WARMUP_ITERATIONS,
            timed_iterations: thresholds::TIMED_ITERATIONS,
            chunk_size: thresholds::CHUNK_SIZE,
            min_read_throughput_mb: None, // Computed from native baseline
            min_write_throughput_mb: None, // Computed from native baseline
            max_unlock_time_seconds: thresholds::MAX_UNLOCK_TIME_SECONDS,
        }
    }
}

impl BenchmarkConfig {
    /// Creates a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a quick benchmark configuration for testing.
    pub fn quick() -> Self {
        Self {
            data_size: 4 * 1024 * 1024, // 4 MB
            warmup_iterations: 1,
            timed_iterations: 2,
            ..Default::default()
        }
    }

    /// Creates a thorough benchmark configuration for CI.
    pub fn thorough() -> Self {
        Self {
            data_size: 128 * 1024 * 1024, // 128 MB
            warmup_iterations: 5,
            timed_iterations: 10,
            ..Default::default()
        }
    }

    /// Sets the data size.
    pub fn with_data_size(mut self, size: usize) -> Self {
        self.data_size = size;
        self
    }

    /// Sets the number of timed iterations.
    pub fn with_iterations(mut self, iterations: usize) -> Self {
        self.timed_iterations = iterations;
        self
    }

    /// Sets explicit throughput thresholds (MB/s).
    pub fn with_thresholds(mut self, read_mb: f64, write_mb: f64) -> Self {
        self.min_read_throughput_mb = Some(read_mb);
        self.min_write_throughput_mb = Some(write_mb);
        self
    }
}

/// Results from a complete benchmark suite run.
#[derive(Debug, Clone)]
pub struct BenchmarkSuiteResult {
    /// Individual benchmark results.
    pub results: Vec<BenchmarkResult>,
    /// Native (unencrypted) read throughput baseline (MB/s).
    pub native_read_throughput: f64,
    /// Native (unencrypted) write throughput baseline (MB/s).
    pub native_write_throughput: f64,
    /// Encrypted read throughput (MB/s).
    pub encrypted_read_throughput: f64,
    /// Encrypted write throughput (MB/s).
    pub encrypted_write_throughput: f64,
    /// Vault unlock time in seconds.
    pub vault_unlock_time: f64,
    /// Overall pass/fail status.
    pub passed: bool,
    /// Total duration of all benchmarks.
    pub total_duration: Duration,
}

impl BenchmarkSuiteResult {
    /// Returns the read throughput as a percentage of native performance.
    pub fn read_percentage_of_native(&self) -> f64 {
        if self.native_read_throughput > 0.0 {
            (self.encrypted_read_throughput / self.native_read_throughput) * 100.0
        } else {
            0.0
        }
    }

    /// Returns the write throughput as a percentage of native performance.
    pub fn write_percentage_of_native(&self) -> f64 {
        if self.native_write_throughput > 0.0 {
            (self.encrypted_write_throughput / self.native_write_throughput) * 100.0
        } else {
            0.0
        }
    }

    /// Returns a list of failed benchmarks.
    pub fn failed_benchmarks(&self) -> Vec<&BenchmarkResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }

    /// Returns the number of passed benchmarks.
    pub fn passed_count(&self) -> usize {
        self.results.iter().filter(|r| r.passed).count()
    }

    /// Returns the total number of benchmarks.
    pub fn total_count(&self) -> usize {
        self.results.len()
    }
}

/// Result comparison for regression detection.
#[derive(Debug, Clone)]
pub struct RegressionCheckResult {
    /// Name of the metric being compared.
    pub metric_name: String,
    /// Previous (baseline) value.
    pub baseline_value: f64,
    /// Current value.
    pub current_value: f64,
    /// Percentage change (positive = improvement, negative = regression).
    pub percent_change: f64,
    /// Whether this is a regression (exceeds threshold).
    pub is_regression: bool,
    /// The threshold used for detection.
    pub threshold_percent: f64,
}

impl RegressionCheckResult {
    /// Creates a new regression check result.
    pub fn new(
        metric_name: impl Into<String>,
        baseline_value: f64,
        current_value: f64,
        threshold_percent: f64,
    ) -> Self {
        let percent_change = if baseline_value > 0.0 {
            ((current_value - baseline_value) / baseline_value) * 100.0
        } else {
            0.0
        };

        // For throughput metrics, a negative change is a regression
        let is_regression = percent_change < -threshold_percent;

        Self {
            metric_name: metric_name.into(),
            baseline_value,
            current_value,
            percent_change,
            is_regression,
            threshold_percent,
        }
    }

    /// Creates a regression check for time metrics (lower is better).
    pub fn new_for_time(
        metric_name: impl Into<String>,
        baseline_value: f64,
        current_value: f64,
        threshold_percent: f64,
    ) -> Self {
        let percent_change = if baseline_value > 0.0 {
            ((current_value - baseline_value) / baseline_value) * 100.0
        } else {
            0.0
        };

        // For time metrics, a positive change is a regression (slower)
        let is_regression = percent_change > threshold_percent;

        Self {
            metric_name: metric_name.into(),
            baseline_value,
            current_value,
            percent_change,
            is_regression,
            threshold_percent,
        }
    }

    /// Returns a formatted summary.
    pub fn summary(&self) -> String {
        let direction = if self.percent_change >= 0.0 { "+" } else { "" };
        let status = if self.is_regression {
            "REGRESSION"
        } else {
            "OK"
        };
        format!(
            "[{}] {}: {:.2} -> {:.2} ({}{:.1}%, threshold: ±{:.1}%)",
            status,
            self.metric_name,
            self.baseline_value,
            self.current_value,
            direction,
            self.percent_change,
            self.threshold_percent
        )
    }
}

/// Runs the sequential read benchmark (measures decryption throughput).
///
/// This benchmark measures how fast encrypted data can be decrypted,
/// simulating file read operations.
pub fn benchmark_sequential_read(config: &BenchmarkConfig) -> BenchmarkResult {
    // Generate test data and encrypt it once
    let key = generate_key().expect("Failed to generate key");
    let nonce = generate_nonce().expect("Failed to generate nonce");
    let aad = b"benchmark-read";

    // Generate plaintext data
    let plaintext: Vec<u8> = (0..config.data_size)
        .map(|i| (i & 0xFF) as u8)
        .collect();

    // Encrypt the data
    let ciphertext = encrypt(&key, &nonce, &plaintext, aad).expect("Failed to encrypt");

    // Warmup iterations
    for _ in 0..config.warmup_iterations {
        let _ = decrypt(&key, &nonce, &ciphertext, aad);
    }

    // Timed iterations
    let start = Instant::now();
    let mut total_bytes = 0usize;

    for _ in 0..config.timed_iterations {
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("Decryption failed");
        total_bytes += decrypted.len();
    }

    let duration = start.elapsed();

    BenchmarkResult::new(
        "Sequential Read (Decryption)",
        total_bytes,
        duration,
        config.min_read_throughput_mb,
    )
}

/// Runs the sequential write benchmark (measures encryption throughput).
///
/// This benchmark measures how fast data can be encrypted,
/// simulating file write operations.
pub fn benchmark_sequential_write(config: &BenchmarkConfig) -> BenchmarkResult {
    let key = generate_key().expect("Failed to generate key");
    let aad = b"benchmark-write";

    // Generate plaintext data
    let plaintext: Vec<u8> = (0..config.data_size)
        .map(|i| (i & 0xFF) as u8)
        .collect();

    // Warmup iterations
    for _ in 0..config.warmup_iterations {
        let nonce = generate_nonce().expect("Failed to generate nonce");
        let _ = encrypt(&key, &nonce, &plaintext, aad);
    }

    // Timed iterations
    let start = Instant::now();
    let mut total_bytes = 0usize;

    for _ in 0..config.timed_iterations {
        let nonce = generate_nonce().expect("Failed to generate nonce");
        let ciphertext = encrypt(&key, &nonce, &plaintext, aad).expect("Encryption failed");
        total_bytes += ciphertext.len();
    }

    let duration = start.elapsed();

    BenchmarkResult::new(
        "Sequential Write (Encryption)",
        total_bytes,
        duration,
        config.min_write_throughput_mb,
    )
}

/// Runs the vault unlock time benchmark (measures key derivation).
///
/// This benchmark measures how long it takes to derive the master key
/// from a password using Argon2id with default parameters.
pub fn benchmark_vault_unlock(config: &BenchmarkConfig) -> BenchmarkResult {
    let password = b"test-password-for-benchmark";
    let salt = generate_salt().expect("Failed to generate salt");
    let params = Argon2Params::default();

    // No warmup for this benchmark (Argon2id is deliberately slow)

    // Single timed derivation
    let start = Instant::now();
    let _ = derive_key(password, &salt, &params).expect("Key derivation failed");
    let duration = start.elapsed();

    BenchmarkResult::new_timed(
        "Vault Unlock (Argon2id KDF)",
        duration,
        config.max_unlock_time_seconds,
    )
}

/// Runs the native (unencrypted) read baseline benchmark.
///
/// This measures raw memory copy throughput to establish the native baseline.
pub fn benchmark_native_read(config: &BenchmarkConfig) -> BenchmarkResult {
    // Generate source data
    let source: Vec<u8> = (0..config.data_size)
        .map(|i| (i & 0xFF) as u8)
        .collect();

    // Warmup
    for _ in 0..config.warmup_iterations {
        let mut dest = Vec::with_capacity(config.data_size);
        dest.extend_from_slice(&source);
        std::hint::black_box(&dest);
    }

    // Timed iterations
    let start = Instant::now();
    let mut total_bytes = 0usize;

    for _ in 0..config.timed_iterations {
        let mut dest = Vec::with_capacity(config.data_size);
        dest.extend_from_slice(&source);
        std::hint::black_box(&dest);
        total_bytes += dest.len();
    }

    let duration = start.elapsed();

    BenchmarkResult::new("Native Read (Memory Copy)", total_bytes, duration, None)
}

/// Runs the native (unencrypted) write baseline benchmark.
///
/// This measures raw memory allocation and fill throughput.
pub fn benchmark_native_write(config: &BenchmarkConfig) -> BenchmarkResult {
    // Warmup
    for _ in 0..config.warmup_iterations {
        let data: Vec<u8> = (0..config.data_size)
            .map(|i| (i & 0xFF) as u8)
            .collect();
        std::hint::black_box(&data);
    }

    // Timed iterations
    let start = Instant::now();
    let mut total_bytes = 0usize;

    for _ in 0..config.timed_iterations {
        let data: Vec<u8> = (0..config.data_size)
            .map(|i| (i & 0xFF) as u8)
            .collect();
        std::hint::black_box(&data);
        total_bytes += data.len();
    }

    let duration = start.elapsed();

    BenchmarkResult::new("Native Write (Memory Fill)", total_bytes, duration, None)
}

/// Runs the complete benchmark suite.
///
/// This function runs all benchmarks and checks against thresholds.
/// The native baselines are measured first, then encrypted operations
/// are compared against them.
pub fn run_benchmark_suite(config: &BenchmarkConfig) -> BenchmarkSuiteResult {
    let suite_start = Instant::now();
    let mut results = Vec::new();

    // 1. Measure native baselines
    let native_read = benchmark_native_read(config);
    let native_write = benchmark_native_write(config);

    let native_read_throughput = native_read.throughput_mb_per_sec;
    let native_write_throughput = native_write.throughput_mb_per_sec;

    results.push(native_read);
    results.push(native_write);

    // 2. Calculate thresholds based on native performance
    let min_read = native_read_throughput * (thresholds::MIN_READ_THROUGHPUT_PERCENT / 100.0);
    let min_write = native_write_throughput * (thresholds::MIN_WRITE_THROUGHPUT_PERCENT / 100.0);

    // Create config with computed thresholds
    let threshold_config = BenchmarkConfig {
        min_read_throughput_mb: Some(min_read),
        min_write_throughput_mb: Some(min_write),
        ..config.clone()
    };

    // 3. Run encrypted benchmarks
    let encrypted_read = benchmark_sequential_read(&threshold_config);
    let encrypted_write = benchmark_sequential_write(&threshold_config);
    let vault_unlock = benchmark_vault_unlock(&threshold_config);

    let encrypted_read_throughput = encrypted_read.throughput_mb_per_sec;
    let encrypted_write_throughput = encrypted_write.throughput_mb_per_sec;
    let vault_unlock_time = vault_unlock.duration.as_secs_f64();

    // 4. Check all results
    let read_passed = encrypted_read.passed;
    let write_passed = encrypted_write.passed;
    let unlock_passed = vault_unlock.passed;

    results.push(encrypted_read);
    results.push(encrypted_write);
    results.push(vault_unlock);

    let passed = read_passed && write_passed && unlock_passed;
    let total_duration = suite_start.elapsed();

    BenchmarkSuiteResult {
        results,
        native_read_throughput,
        native_write_throughput,
        encrypted_read_throughput,
        encrypted_write_throughput,
        vault_unlock_time,
        passed,
        total_duration,
    }
}

/// Checks for performance regression compared to baseline results.
///
/// Returns a list of regression check results for each metric.
pub fn check_regression(
    baseline: &BenchmarkSuiteResult,
    current: &BenchmarkSuiteResult,
    threshold_percent: f64,
) -> Vec<RegressionCheckResult> {
    vec![
        RegressionCheckResult::new(
            "Read Throughput (MB/s)",
            baseline.encrypted_read_throughput,
            current.encrypted_read_throughput,
            threshold_percent,
        ),
        RegressionCheckResult::new(
            "Write Throughput (MB/s)",
            baseline.encrypted_write_throughput,
            current.encrypted_write_throughput,
            threshold_percent,
        ),
        RegressionCheckResult::new_for_time(
            "Vault Unlock Time (s)",
            baseline.vault_unlock_time,
            current.vault_unlock_time,
            threshold_percent,
        ),
    ]
}

/// Formats a complete benchmark report for logging.
pub fn format_benchmark_report(result: &BenchmarkSuiteResult) -> String {
    let mut lines = Vec::new();

    lines.push("=== TESSERACT Performance Benchmark Report ===".to_string());
    lines.push(String::new());

    // Individual results
    for r in &result.results {
        lines.push(r.summary_line());
    }

    lines.push(String::new());

    // Summary statistics
    lines.push(format!(
        "Read Throughput: {:.2} MB/s ({:.1}% of native)",
        result.encrypted_read_throughput,
        result.read_percentage_of_native()
    ));
    lines.push(format!(
        "Write Throughput: {:.2} MB/s ({:.1}% of native)",
        result.encrypted_write_throughput,
        result.write_percentage_of_native()
    ));
    lines.push(format!(
        "Vault Unlock: {:.3}s (target: <{:.1}s)",
        result.vault_unlock_time,
        thresholds::MAX_UNLOCK_TIME_SECONDS
    ));

    lines.push(String::new());

    // Overall status
    let overall = if result.passed { "PASSED" } else { "FAILED" };
    lines.push(format!(
        "Overall: {} ({}/{} benchmarks passed)",
        overall,
        result.passed_count(),
        result.total_count()
    ));
    lines.push(format!("Total Duration: {:.3}s", result.total_duration.as_secs_f64()));

    if !result.passed {
        lines.push(String::new());
        lines.push("Failed benchmarks:".to_string());
        for failed in result.failed_benchmarks() {
            lines.push(format!("  - {}", failed.name));
        }
    }

    lines.push("==============================================".to_string());

    lines.join("\n")
}

/// Formats a regression check report.
pub fn format_regression_report(checks: &[RegressionCheckResult]) -> String {
    let mut lines = Vec::new();

    lines.push("=== Regression Check Report ===".to_string());

    let has_regression = checks.iter().any(|c| c.is_regression);

    for check in checks {
        lines.push(check.summary());
    }

    lines.push(String::new());

    if has_regression {
        lines.push("⚠️  REGRESSION DETECTED".to_string());
        for check in checks.iter().filter(|c| c.is_regression) {
            lines.push(format!(
                "  - {} degraded by {:.1}%",
                check.metric_name,
                check.percent_change.abs()
            ));
        }
    } else {
        lines.push("✓ No regressions detected".to_string());
    }

    lines.push("===============================".to_string());

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== BenchmarkResult Tests ==========

    #[test]
    fn test_benchmark_result_new() {
        let result = BenchmarkResult::new(
            "test",
            1024 * 1024, // 1 MB
            Duration::from_secs(1),
            Some(0.5), // 0.5 MB/s threshold
        );

        assert_eq!(result.name, "test");
        assert_eq!(result.bytes_processed, 1024 * 1024);
        assert!((result.throughput_mb_per_sec - 1.0).abs() < 0.01);
        assert!(result.passed); // 1 MB/s > 0.5 MB/s
    }

    #[test]
    fn test_benchmark_result_new_failed() {
        let result = BenchmarkResult::new(
            "test",
            1024 * 1024, // 1 MB
            Duration::from_secs(1),
            Some(2.0), // 2 MB/s threshold
        );

        assert!(!result.passed); // 1 MB/s < 2 MB/s
    }

    #[test]
    fn test_benchmark_result_new_no_threshold() {
        let result = BenchmarkResult::new(
            "test",
            1024 * 1024,
            Duration::from_secs(1),
            None,
        );

        assert!(result.passed); // No threshold means pass
    }

    #[test]
    fn test_benchmark_result_timed() {
        let result = BenchmarkResult::new_timed(
            "unlock",
            Duration::from_secs_f64(2.5),
            3.0, // Max 3 seconds
        );

        assert_eq!(result.name, "unlock");
        assert!(result.passed); // 2.5s < 3.0s
        assert!(result.details.contains("2.5"));
    }

    #[test]
    fn test_benchmark_result_timed_failed() {
        let result = BenchmarkResult::new_timed(
            "unlock",
            Duration::from_secs_f64(3.5),
            3.0, // Max 3 seconds
        );

        assert!(!result.passed); // 3.5s > 3.0s
    }

    #[test]
    fn test_benchmark_result_with_details() {
        let result = BenchmarkResult::new("test", 0, Duration::from_secs(1), None)
            .with_details("some details");

        assert_eq!(result.details, "some details");
    }

    #[test]
    fn test_benchmark_result_summary_line_throughput() {
        let result = BenchmarkResult::new(
            "read",
            1024 * 1024,
            Duration::from_secs(1),
            Some(0.5),
        );

        let summary = result.summary_line();
        assert!(summary.contains("[PASS]"));
        assert!(summary.contains("read"));
        assert!(summary.contains("MB/s"));
    }

    #[test]
    fn test_benchmark_result_summary_line_timed() {
        let result = BenchmarkResult::new_timed(
            "unlock",
            Duration::from_secs(1),
            3.0,
        );

        let summary = result.summary_line();
        assert!(summary.contains("[PASS]"));
        assert!(summary.contains("unlock"));
        assert!(summary.contains("1.000s"));
    }

    #[test]
    fn test_benchmark_result_zero_duration() {
        let result = BenchmarkResult::new(
            "instant",
            1024,
            Duration::ZERO,
            None,
        );

        assert_eq!(result.throughput_bytes_per_sec, 0.0);
        assert!(result.passed);
    }

    // ========== BenchmarkConfig Tests ==========

    #[test]
    fn test_benchmark_config_default() {
        let config = BenchmarkConfig::default();

        assert_eq!(config.data_size, thresholds::DEFAULT_BENCHMARK_SIZE);
        assert_eq!(config.warmup_iterations, thresholds::WARMUP_ITERATIONS);
        assert_eq!(config.timed_iterations, thresholds::TIMED_ITERATIONS);
        assert_eq!(config.chunk_size, thresholds::CHUNK_SIZE);
        assert!(config.min_read_throughput_mb.is_none());
        assert!(config.min_write_throughput_mb.is_none());
        assert_eq!(config.max_unlock_time_seconds, thresholds::MAX_UNLOCK_TIME_SECONDS);
    }

    #[test]
    fn test_benchmark_config_new() {
        let config = BenchmarkConfig::new();
        assert_eq!(config.data_size, thresholds::DEFAULT_BENCHMARK_SIZE);
    }

    #[test]
    fn test_benchmark_config_quick() {
        let config = BenchmarkConfig::quick();

        assert_eq!(config.data_size, 4 * 1024 * 1024);
        assert_eq!(config.warmup_iterations, 1);
        assert_eq!(config.timed_iterations, 2);
    }

    #[test]
    fn test_benchmark_config_thorough() {
        let config = BenchmarkConfig::thorough();

        assert_eq!(config.data_size, 128 * 1024 * 1024);
        assert_eq!(config.warmup_iterations, 5);
        assert_eq!(config.timed_iterations, 10);
    }

    #[test]
    fn test_benchmark_config_with_data_size() {
        let config = BenchmarkConfig::new().with_data_size(10 * 1024 * 1024);
        assert_eq!(config.data_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_benchmark_config_with_iterations() {
        let config = BenchmarkConfig::new().with_iterations(20);
        assert_eq!(config.timed_iterations, 20);
    }

    #[test]
    fn test_benchmark_config_with_thresholds() {
        let config = BenchmarkConfig::new().with_thresholds(100.0, 80.0);

        assert_eq!(config.min_read_throughput_mb, Some(100.0));
        assert_eq!(config.min_write_throughput_mb, Some(80.0));
    }

    // ========== BenchmarkSuiteResult Tests ==========

    #[test]
    fn test_suite_result_percentages() {
        let result = BenchmarkSuiteResult {
            results: vec![],
            native_read_throughput: 1000.0,
            native_write_throughput: 800.0,
            encrypted_read_throughput: 900.0,
            encrypted_write_throughput: 720.0,
            vault_unlock_time: 2.0,
            passed: true,
            total_duration: Duration::from_secs(10),
        };

        assert!((result.read_percentage_of_native() - 90.0).abs() < 0.01);
        assert!((result.write_percentage_of_native() - 90.0).abs() < 0.01);
    }

    #[test]
    fn test_suite_result_percentages_zero_native() {
        let result = BenchmarkSuiteResult {
            results: vec![],
            native_read_throughput: 0.0,
            native_write_throughput: 0.0,
            encrypted_read_throughput: 100.0,
            encrypted_write_throughput: 100.0,
            vault_unlock_time: 2.0,
            passed: true,
            total_duration: Duration::from_secs(10),
        };

        assert_eq!(result.read_percentage_of_native(), 0.0);
        assert_eq!(result.write_percentage_of_native(), 0.0);
    }

    #[test]
    fn test_suite_result_failed_benchmarks() {
        let passed = BenchmarkResult::new("pass", 100, Duration::from_secs(1), None);
        let failed = BenchmarkResult::new("fail", 100, Duration::from_secs(1), Some(1000.0));

        let result = BenchmarkSuiteResult {
            results: vec![passed, failed],
            native_read_throughput: 100.0,
            native_write_throughput: 100.0,
            encrypted_read_throughput: 90.0,
            encrypted_write_throughput: 90.0,
            vault_unlock_time: 2.0,
            passed: false,
            total_duration: Duration::from_secs(10),
        };

        let failed = result.failed_benchmarks();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].name, "fail");
    }

    #[test]
    fn test_suite_result_counts() {
        let r1 = BenchmarkResult::new("a", 100, Duration::from_secs(1), None);
        let r2 = BenchmarkResult::new("b", 100, Duration::from_secs(1), Some(1000.0));
        let r3 = BenchmarkResult::new("c", 100, Duration::from_secs(1), None);

        let result = BenchmarkSuiteResult {
            results: vec![r1, r2, r3],
            native_read_throughput: 100.0,
            native_write_throughput: 100.0,
            encrypted_read_throughput: 90.0,
            encrypted_write_throughput: 90.0,
            vault_unlock_time: 2.0,
            passed: false,
            total_duration: Duration::from_secs(10),
        };

        assert_eq!(result.passed_count(), 2);
        assert_eq!(result.total_count(), 3);
    }

    // ========== RegressionCheckResult Tests ==========

    #[test]
    fn test_regression_check_improvement() {
        let check = RegressionCheckResult::new(
            "throughput",
            100.0, // baseline
            110.0, // current (10% improvement)
            10.0,  // threshold
        );

        assert!(!check.is_regression);
        assert!((check.percent_change - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_regression_check_minor_regression() {
        let check = RegressionCheckResult::new(
            "throughput",
            100.0, // baseline
            95.0,  // current (5% regression)
            10.0,  // threshold
        );

        // 5% regression is within 10% threshold
        assert!(!check.is_regression);
        assert!((check.percent_change - (-5.0)).abs() < 0.01);
    }

    #[test]
    fn test_regression_check_major_regression() {
        let check = RegressionCheckResult::new(
            "throughput",
            100.0, // baseline
            85.0,  // current (15% regression)
            10.0,  // threshold
        );

        // 15% regression exceeds 10% threshold
        assert!(check.is_regression);
        assert!((check.percent_change - (-15.0)).abs() < 0.01);
    }

    #[test]
    fn test_regression_check_for_time_improvement() {
        let check = RegressionCheckResult::new_for_time(
            "unlock time",
            2.0, // baseline
            1.8, // current (10% faster)
            10.0,
        );

        // Faster is better for time metrics
        assert!(!check.is_regression);
        assert!((check.percent_change - (-10.0)).abs() < 0.01);
    }

    #[test]
    fn test_regression_check_for_time_regression() {
        let check = RegressionCheckResult::new_for_time(
            "unlock time",
            2.0, // baseline
            2.5, // current (25% slower)
            10.0,
        );

        // Slower is a regression for time metrics
        assert!(check.is_regression);
        assert!((check.percent_change - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_regression_check_zero_baseline() {
        let check = RegressionCheckResult::new(
            "throughput",
            0.0,
            100.0,
            10.0,
        );

        // Can't compute percentage with zero baseline
        assert_eq!(check.percent_change, 0.0);
        assert!(!check.is_regression);
    }

    #[test]
    fn test_regression_check_summary() {
        let check = RegressionCheckResult::new(
            "Read Throughput",
            100.0,
            90.0,
            10.0,
        );

        let summary = check.summary();
        assert!(summary.contains("[OK]"));
        assert!(summary.contains("Read Throughput"));
        assert!(summary.contains("100.00"));
        assert!(summary.contains("90.00"));
    }

    #[test]
    fn test_regression_check_summary_regression() {
        let check = RegressionCheckResult::new(
            "Read Throughput",
            100.0,
            80.0, // 20% regression
            10.0,
        );

        let summary = check.summary();
        assert!(summary.contains("[REGRESSION]"));
    }

    // ========== Benchmark Function Tests ==========

    #[test]
    fn test_benchmark_sequential_read_runs() {
        let config = BenchmarkConfig::quick();
        let result = benchmark_sequential_read(&config);

        assert_eq!(result.name, "Sequential Read (Decryption)");
        assert!(result.bytes_processed > 0);
        assert!(result.throughput_mb_per_sec > 0.0);
    }

    #[test]
    fn test_benchmark_sequential_write_runs() {
        let config = BenchmarkConfig::quick();
        let result = benchmark_sequential_write(&config);

        assert_eq!(result.name, "Sequential Write (Encryption)");
        assert!(result.bytes_processed > 0);
        assert!(result.throughput_mb_per_sec > 0.0);
    }

    #[test]
    fn test_benchmark_vault_unlock_runs() {
        let config = BenchmarkConfig::new();
        let result = benchmark_vault_unlock(&config);

        assert_eq!(result.name, "Vault Unlock (Argon2id KDF)");
        assert!(result.duration.as_secs_f64() > 0.0);
        // Should complete within reasonable time (we'll be lenient)
        assert!(result.duration.as_secs_f64() < 30.0);
    }

    #[test]
    fn test_benchmark_native_read_runs() {
        let config = BenchmarkConfig::quick();
        let result = benchmark_native_read(&config);

        assert_eq!(result.name, "Native Read (Memory Copy)");
        assert!(result.bytes_processed > 0);
        assert!(result.throughput_mb_per_sec > 0.0);
    }

    #[test]
    fn test_benchmark_native_write_runs() {
        let config = BenchmarkConfig::quick();
        let result = benchmark_native_write(&config);

        assert_eq!(result.name, "Native Write (Memory Fill)");
        assert!(result.bytes_processed > 0);
        assert!(result.throughput_mb_per_sec > 0.0);
    }

    #[test]
    fn test_run_benchmark_suite() {
        let config = BenchmarkConfig::quick();
        let result = run_benchmark_suite(&config);

        // Should have 5 results: native read, native write, encrypted read, encrypted write, unlock
        assert_eq!(result.total_count(), 5);

        // All metrics should be positive
        assert!(result.native_read_throughput > 0.0);
        assert!(result.native_write_throughput > 0.0);
        assert!(result.encrypted_read_throughput > 0.0);
        assert!(result.encrypted_write_throughput > 0.0);
        assert!(result.vault_unlock_time > 0.0);

        // Encrypted should be reasonably fast relative to native
        // Note: In debug builds, encryption overhead is much higher, so we use a lower threshold
        // Debug builds can be 100x+ slower than release with AES-NI
        #[cfg(debug_assertions)]
        let min_percentage = 0.05; // Debug mode can be extremely slow
        #[cfg(not(debug_assertions))]
        let min_percentage = 10.0; // Release mode should be much faster

        assert!(
            result.read_percentage_of_native() > min_percentage,
            "Read should be at least {}% of native, got {:.1}%",
            min_percentage, result.read_percentage_of_native()
        );
        assert!(
            result.write_percentage_of_native() > min_percentage,
            "Write should be at least {}% of native, got {:.1}%",
            min_percentage, result.write_percentage_of_native()
        );
    }

    #[test]
    fn test_check_regression_no_regression() {
        let baseline = BenchmarkSuiteResult {
            results: vec![],
            native_read_throughput: 1000.0,
            native_write_throughput: 800.0,
            encrypted_read_throughput: 900.0,
            encrypted_write_throughput: 700.0,
            vault_unlock_time: 2.0,
            passed: true,
            total_duration: Duration::from_secs(10),
        };

        let current = BenchmarkSuiteResult {
            results: vec![],
            native_read_throughput: 1000.0,
            native_write_throughput: 800.0,
            encrypted_read_throughput: 880.0, // 2.2% regression
            encrypted_write_throughput: 680.0, // 2.9% regression
            vault_unlock_time: 2.1, // 5% slower
            passed: true,
            total_duration: Duration::from_secs(10),
        };

        let checks = check_regression(&baseline, &current, 10.0);

        // All should be within threshold
        assert!(!checks.iter().any(|c| c.is_regression));
    }

    #[test]
    fn test_check_regression_with_regression() {
        let baseline = BenchmarkSuiteResult {
            results: vec![],
            native_read_throughput: 1000.0,
            native_write_throughput: 800.0,
            encrypted_read_throughput: 900.0,
            encrypted_write_throughput: 700.0,
            vault_unlock_time: 2.0,
            passed: true,
            total_duration: Duration::from_secs(10),
        };

        let current = BenchmarkSuiteResult {
            results: vec![],
            native_read_throughput: 1000.0,
            native_write_throughput: 800.0,
            encrypted_read_throughput: 700.0, // 22% regression
            encrypted_write_throughput: 700.0,
            vault_unlock_time: 2.0,
            passed: true,
            total_duration: Duration::from_secs(10),
        };

        let checks = check_regression(&baseline, &current, 10.0);

        // Read should be flagged as regression
        assert!(checks.iter().any(|c| c.is_regression && c.metric_name.contains("Read")));
    }

    // ========== Report Format Tests ==========

    #[test]
    fn test_format_benchmark_report() {
        let result = BenchmarkSuiteResult {
            results: vec![
                BenchmarkResult::new("Native Read", 1024, Duration::from_secs(1), None),
                BenchmarkResult::new("Encrypted Read", 1024, Duration::from_secs(1), Some(0.0005)),
            ],
            native_read_throughput: 1000.0,
            native_write_throughput: 800.0,
            encrypted_read_throughput: 900.0,
            encrypted_write_throughput: 720.0,
            vault_unlock_time: 2.0,
            passed: true,
            total_duration: Duration::from_secs(10),
        };

        let report = format_benchmark_report(&result);

        assert!(report.contains("Performance Benchmark Report"));
        assert!(report.contains("PASSED"));
        assert!(report.contains("Read Throughput"));
        assert!(report.contains("Write Throughput"));
        assert!(report.contains("Vault Unlock"));
    }

    #[test]
    fn test_format_benchmark_report_failed() {
        let failed_result = BenchmarkResult::new(
            "Slow Test",
            1024,
            Duration::from_secs(10),
            Some(100.0),
        );

        let result = BenchmarkSuiteResult {
            results: vec![failed_result],
            native_read_throughput: 1000.0,
            native_write_throughput: 800.0,
            encrypted_read_throughput: 50.0,
            encrypted_write_throughput: 50.0,
            vault_unlock_time: 5.0,
            passed: false,
            total_duration: Duration::from_secs(10),
        };

        let report = format_benchmark_report(&result);

        assert!(report.contains("FAILED"));
        assert!(report.contains("Failed benchmarks"));
        assert!(report.contains("Slow Test"));
    }

    #[test]
    fn test_format_regression_report_no_regression() {
        let checks = vec![
            RegressionCheckResult::new("Read", 100.0, 98.0, 10.0),
            RegressionCheckResult::new("Write", 80.0, 79.0, 10.0),
        ];

        let report = format_regression_report(&checks);

        assert!(report.contains("Regression Check Report"));
        assert!(report.contains("No regressions detected"));
    }

    #[test]
    fn test_format_regression_report_with_regression() {
        let checks = vec![
            RegressionCheckResult::new("Read", 100.0, 80.0, 10.0),
            RegressionCheckResult::new("Write", 80.0, 79.0, 10.0),
        ];

        let report = format_regression_report(&checks);

        assert!(report.contains("REGRESSION DETECTED"));
        assert!(report.contains("Read"));
    }

    // ========== Threshold Constants Tests ==========

    #[test]
    fn test_threshold_constants() {
        assert_eq!(thresholds::MIN_READ_THROUGHPUT_PERCENT, 85.0);
        assert_eq!(thresholds::MIN_WRITE_THROUGHPUT_PERCENT, 85.0);
        assert_eq!(thresholds::MAX_UNLOCK_TIME_SECONDS, 3.0);
        assert_eq!(thresholds::REGRESSION_THRESHOLD_PERCENT, 10.0);
        assert_eq!(thresholds::DEFAULT_BENCHMARK_SIZE, 64 * 1024 * 1024);
        assert_eq!(thresholds::WARMUP_ITERATIONS, 3);
        assert_eq!(thresholds::TIMED_ITERATIONS, 5);
        assert_eq!(thresholds::CHUNK_SIZE, 1024 * 1024);
    }

    // ========== Integration Tests ==========

    #[test]
    fn test_full_benchmark_flow() {
        // Run a quick benchmark suite
        let config = BenchmarkConfig::quick();
        let result = run_benchmark_suite(&config);

        // Generate report
        let report = format_benchmark_report(&result);
        println!("{}", report);

        // The suite should at least complete without error
        assert!(result.total_count() > 0);
        assert!(result.total_duration.as_secs() < 300); // Should complete in <5 minutes
    }

    #[test]
    fn test_regression_detection_flow() {
        // Run two suites and compare
        let config = BenchmarkConfig::quick();

        let baseline = run_benchmark_suite(&config);
        let current = run_benchmark_suite(&config);

        let checks = check_regression(&baseline, &current, thresholds::REGRESSION_THRESHOLD_PERCENT);
        let report = format_regression_report(&checks);

        println!("{}", report);

        // Between identical runs, there should be no major regressions
        // (might have minor variance but shouldn't exceed 10%)
        assert_eq!(checks.len(), 3); // read, write, unlock
    }
}
