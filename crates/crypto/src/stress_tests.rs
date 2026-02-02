//! Nonce Uniqueness Stress Test Suite
//!
//! This module provides comprehensive stress tests for nonce generation
//! to verify zero collisions under high-volume usage conditions.
//!
//! # Test Coverage
//!
//! - **US-064 Acceptance Criteria**:
//!   - Generate 1 million nonces
//!   - Verify zero collisions
//!   - Test completes in < 60 seconds
//!   - Runs as part of CI pipeline
//!
//! # Security Rationale
//!
//! With 96-bit random nonces:
//! - Birthday bound: ~2^48 nonces for 50% collision probability
//! - 1 million nonces: ~2^20, which is well below the birthday bound
//! - Expected collisions: (2^20)^2 / (2 * 2^96) ≈ 2^-57 (virtually impossible)
//!
//! This test provides defense-in-depth verification that our CSPRNG
//! implementation produces properly distributed random values.

use crate::nonce::{NonceRegistry, NONCE_SIZE};
use crate::random::generate_nonce;
use crate::CryptoError;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Result of a nonce stress test.
#[derive(Debug, Clone)]
pub struct StressTestResult {
    /// Total number of nonces generated.
    pub total_generated: usize,
    /// Number of collisions detected.
    pub collisions: usize,
    /// Total time taken for the test.
    pub duration: Duration,
    /// Average time per nonce generation in nanoseconds.
    pub avg_nanos_per_nonce: u64,
    /// Whether the test passed (zero collisions).
    pub passed: bool,
}

impl StressTestResult {
    /// Returns true if the test passed (zero collisions).
    pub fn is_success(&self) -> bool {
        self.passed && self.collisions == 0
    }

    /// Returns the throughput in nonces per second.
    pub fn nonces_per_second(&self) -> f64 {
        if self.duration.as_secs_f64() > 0.0 {
            self.total_generated as f64 / self.duration.as_secs_f64()
        } else {
            0.0
        }
    }
}

/// Configuration for stress tests.
#[derive(Debug, Clone)]
pub struct StressTestConfig {
    /// Number of nonces to generate.
    pub count: usize,
    /// Maximum allowed duration for the test.
    pub max_duration: Duration,
    /// Whether to use the NonceRegistry for collision detection.
    pub use_registry: bool,
    /// Progress callback interval (0 = no callbacks).
    pub progress_interval: usize,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        Self {
            count: 1_000_000,
            max_duration: Duration::from_secs(60),
            use_registry: true,
            progress_interval: 0,
        }
    }
}

impl StressTestConfig {
    /// Creates a configuration for 1 million nonces with 60 second timeout.
    pub fn one_million() -> Self {
        Self::default()
    }

    /// Creates a configuration with a custom count.
    pub fn with_count(count: usize) -> Self {
        Self {
            count,
            ..Default::default()
        }
    }

    /// Sets the maximum duration for the test.
    pub fn max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = duration;
        self
    }

    /// Sets whether to use the NonceRegistry.
    pub fn use_registry(mut self, use_it: bool) -> Self {
        self.use_registry = use_it;
        self
    }

    /// Sets the progress callback interval.
    pub fn progress_interval(mut self, interval: usize) -> Self {
        self.progress_interval = interval;
        self
    }
}

/// Runs the nonce uniqueness stress test.
///
/// This test generates a large number of nonces and verifies that no
/// collisions occur. It is the primary verification for US-064.
///
/// # Arguments
///
/// * `config` - The test configuration.
///
/// # Returns
///
/// A `StressTestResult` containing the test metrics.
///
/// # Example
///
/// ```
/// use tesseract_crypto::stress_tests::{run_nonce_stress_test, StressTestConfig};
///
/// let config = StressTestConfig::with_count(10_000); // Use smaller count for example
/// let result = run_nonce_stress_test(&config);
/// assert!(result.is_success(), "Nonce stress test should pass");
/// ```
pub fn run_nonce_stress_test(config: &StressTestConfig) -> StressTestResult {
    let start = Instant::now();

    if config.use_registry {
        run_with_registry(config, start)
    } else {
        run_with_hashset(config, start)
    }
}

/// Runs the stress test using NonceRegistry for collision detection.
fn run_with_registry(config: &StressTestConfig, start: Instant) -> StressTestResult {
    let registry = NonceRegistry::with_capacity(config.count);
    let mut collisions = 0;
    let mut generated = 0;

    for i in 0..config.count {
        // Check timeout
        if start.elapsed() > config.max_duration {
            return StressTestResult {
                total_generated: generated,
                collisions,
                duration: start.elapsed(),
                avg_nanos_per_nonce: if generated > 0 {
                    start.elapsed().as_nanos() as u64 / generated as u64
                } else {
                    0
                },
                passed: false, // Timeout
            };
        }

        match generate_nonce() {
            Ok(nonce) => {
                generated += 1;
                if let Err(CryptoError::NonceCollision) = registry.register_nonce(&nonce) {
                    collisions += 1;
                }
            }
            Err(_) => {
                // RNG failure, continue but note it
            }
        }

        // Progress callback (if configured)
        if config.progress_interval > 0 && (i + 1) % config.progress_interval == 0 {
            let elapsed = start.elapsed();
            let rate = (i + 1) as f64 / elapsed.as_secs_f64();
            eprintln!("[StressTest] Progress: {}/{} ({:.0} nonces/sec)", i + 1, config.count, rate);
        }
    }

    let duration = start.elapsed();
    StressTestResult {
        total_generated: generated,
        collisions,
        duration,
        avg_nanos_per_nonce: if generated > 0 {
            duration.as_nanos() as u64 / generated as u64
        } else {
            0
        },
        passed: collisions == 0 && generated == config.count,
    }
}

/// Runs the stress test using a simple HashSet for collision detection.
fn run_with_hashset(config: &StressTestConfig, start: Instant) -> StressTestResult {
    let mut seen: HashSet<[u8; NONCE_SIZE]> = HashSet::with_capacity(config.count);
    let mut collisions = 0;
    let mut generated = 0;

    for i in 0..config.count {
        // Check timeout
        if start.elapsed() > config.max_duration {
            return StressTestResult {
                total_generated: generated,
                collisions,
                duration: start.elapsed(),
                avg_nanos_per_nonce: if generated > 0 {
                    start.elapsed().as_nanos() as u64 / generated as u64
                } else {
                    0
                },
                passed: false, // Timeout
            };
        }

        match generate_nonce() {
            Ok(nonce) => {
                generated += 1;
                if !seen.insert(nonce) {
                    collisions += 1;
                }
            }
            Err(_) => {
                // RNG failure, continue but note it
            }
        }

        // Progress callback (if configured)
        if config.progress_interval > 0 && (i + 1) % config.progress_interval == 0 {
            let elapsed = start.elapsed();
            let rate = (i + 1) as f64 / elapsed.as_secs_f64();
            eprintln!("[StressTest] Progress: {}/{} ({:.0} nonces/sec)", i + 1, config.count, rate);
        }
    }

    let duration = start.elapsed();
    StressTestResult {
        total_generated: generated,
        collisions,
        duration,
        avg_nanos_per_nonce: if generated > 0 {
            duration.as_nanos() as u64 / generated as u64
        } else {
            0
        },
        passed: collisions == 0 && generated == config.count,
    }
}

/// Runs the 1 million nonce stress test (US-064 primary test).
///
/// This is a convenience function that runs the full stress test with
/// default configuration: 1 million nonces, 60 second timeout.
///
/// # Returns
///
/// A `StressTestResult` containing the test metrics.
///
/// # Panics
///
/// This function panics if any collisions are detected or if the test
/// exceeds the 60 second timeout.
///
/// # Example
///
/// ```no_run
/// use tesseract_crypto::stress_tests::run_one_million_nonce_test;
///
/// let result = run_one_million_nonce_test();
/// assert!(result.is_success());
/// println!("Generated {} nonces in {:?}", result.total_generated, result.duration);
/// ```
pub fn run_one_million_nonce_test() -> StressTestResult {
    run_nonce_stress_test(&StressTestConfig::one_million())
}

/// Validates the result of a stress test and returns a detailed report.
///
/// # Arguments
///
/// * `result` - The stress test result to validate.
///
/// # Returns
///
/// A string containing a detailed report of the test results.
pub fn format_stress_test_report(result: &StressTestResult) -> String {
    let status = if result.is_success() { "PASSED" } else { "FAILED" };

    format!(
        "=== Nonce Uniqueness Stress Test Report ===\n\
         Status: {}\n\
         Total Generated: {}\n\
         Collisions: {}\n\
         Duration: {:.3}s\n\
         Throughput: {:.0} nonces/sec\n\
         Average Time: {} ns/nonce\n\
         ==========================================",
        status,
        result.total_generated,
        result.collisions,
        result.duration.as_secs_f64(),
        result.nonces_per_second(),
        result.avg_nanos_per_nonce
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Primary acceptance test for US-064: 1 million nonces, zero collisions, <60 seconds.
    #[test]
    fn test_one_million_nonces_zero_collisions() {
        let config = StressTestConfig::one_million();
        let start = Instant::now();
        let result = run_nonce_stress_test(&config);
        let elapsed = start.elapsed();

        // Print detailed report for CI visibility
        println!("{}", format_stress_test_report(&result));

        // Acceptance criteria checks
        assert_eq!(
            result.total_generated, 1_000_000,
            "Should generate exactly 1 million nonces"
        );
        assert_eq!(
            result.collisions, 0,
            "Should have zero collisions"
        );
        assert!(
            elapsed < Duration::from_secs(60),
            "Test should complete in less than 60 seconds (took {:?})",
            elapsed
        );
        assert!(
            result.passed,
            "Test should pass"
        );
    }

    /// Test that HashSet-based detection also works correctly.
    #[test]
    fn test_hashset_collision_detection() {
        let config = StressTestConfig::with_count(100_000).use_registry(false);
        let result = run_nonce_stress_test(&config);

        assert_eq!(result.total_generated, 100_000);
        assert_eq!(result.collisions, 0);
        assert!(result.passed);
    }

    /// Test that registry-based detection works correctly.
    #[test]
    fn test_registry_collision_detection() {
        let config = StressTestConfig::with_count(100_000).use_registry(true);
        let result = run_nonce_stress_test(&config);

        assert_eq!(result.total_generated, 100_000);
        assert_eq!(result.collisions, 0);
        assert!(result.passed);
    }

    /// Test timeout handling.
    #[test]
    fn test_timeout_handling() {
        // Create a config with an impossibly short timeout
        let config = StressTestConfig::with_count(10_000_000)
            .max_duration(Duration::from_millis(1));

        let result = run_nonce_stress_test(&config);

        // Should fail due to timeout (not complete all nonces)
        assert!(result.total_generated < 10_000_000);
        assert!(!result.passed);
    }

    /// Test stress test result metrics.
    #[test]
    fn test_result_metrics() {
        let config = StressTestConfig::with_count(10_000);
        let result = run_nonce_stress_test(&config);

        assert!(result.nonces_per_second() > 0.0);
        assert!(result.avg_nanos_per_nonce > 0);
        assert!(result.is_success());
    }

    /// Test the report formatting.
    #[test]
    fn test_report_format() {
        let result = StressTestResult {
            total_generated: 1_000_000,
            collisions: 0,
            duration: Duration::from_secs(30),
            avg_nanos_per_nonce: 30_000,
            passed: true,
        };

        let report = format_stress_test_report(&result);
        assert!(report.contains("PASSED"));
        assert!(report.contains("1000000"));
        assert!(report.contains("Collisions: 0"));
    }

    /// Test the config builder pattern.
    #[test]
    fn test_config_builder() {
        let config = StressTestConfig::with_count(50_000)
            .max_duration(Duration::from_secs(30))
            .use_registry(true)
            .progress_interval(10_000);

        assert_eq!(config.count, 50_000);
        assert_eq!(config.max_duration, Duration::from_secs(30));
        assert!(config.use_registry);
        assert_eq!(config.progress_interval, 10_000);
    }

    /// Test default configuration values.
    #[test]
    fn test_default_config() {
        let config = StressTestConfig::default();

        assert_eq!(config.count, 1_000_000);
        assert_eq!(config.max_duration, Duration::from_secs(60));
        assert!(config.use_registry);
        assert_eq!(config.progress_interval, 0);
    }

    /// Test convenience function.
    #[test]
    fn test_one_million_convenience_function() {
        let config = StressTestConfig::one_million();
        assert_eq!(config.count, 1_000_000);
        assert_eq!(config.max_duration, Duration::from_secs(60));
    }

    /// Verify collision detection actually works by simulating a collision.
    #[test]
    fn test_collision_detection_works() {
        let registry = NonceRegistry::new();
        let nonce = [42u8; NONCE_SIZE];

        // First registration should succeed
        assert!(registry.register_nonce(&nonce).is_ok());

        // Second registration should detect collision
        match registry.register_nonce(&nonce) {
            Err(CryptoError::NonceCollision) => { /* expected */ }
            _ => panic!("Should detect collision"),
        }
    }

    /// Statistical test: verify uniform distribution of generated nonces.
    #[test]
    fn test_nonce_distribution() {
        const SAMPLE_SIZE: usize = 100_000;
        let mut byte_counts: [[usize; 256]; NONCE_SIZE] = [[0; 256]; NONCE_SIZE];

        for _ in 0..SAMPLE_SIZE {
            let nonce = generate_nonce().expect("Failed to generate nonce");
            for (pos, &byte) in nonce.iter().enumerate() {
                byte_counts[pos][byte as usize] += 1;
            }
        }

        // Check that each byte position has reasonable distribution
        // Expected count per byte value: SAMPLE_SIZE / 256 ≈ 390
        let expected = SAMPLE_SIZE as f64 / 256.0;

        for pos in 0..NONCE_SIZE {
            let min_count = byte_counts[pos].iter().min().copied().unwrap_or(0);
            let max_count = byte_counts[pos].iter().max().copied().unwrap_or(0);

            // Very loose bounds to avoid flaky tests
            // (min should be at least 10% of expected, max at most 500% of expected)
            assert!(
                min_count as f64 >= expected * 0.1,
                "Position {} has too few of some byte value (min: {}, expected: {})",
                pos, min_count, expected as usize
            );
            assert!(
                max_count as f64 <= expected * 5.0,
                "Position {} has too many of some byte value (max: {}, expected: {})",
                pos, max_count, expected as usize
            );
        }
    }

    /// Concurrent stress test with multiple threads.
    #[test]
    fn test_concurrent_nonce_generation() {
        use std::sync::Arc;
        use std::thread;

        const NONCES_PER_THREAD: usize = 25_000;
        const NUM_THREADS: usize = 4;

        let registry = Arc::new(NonceRegistry::with_capacity(NONCES_PER_THREAD * NUM_THREADS));
        let start = Instant::now();

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let registry = Arc::clone(&registry);
                thread::spawn(move || {
                    let mut generated = 0;
                    let mut collisions = 0;

                    for _ in 0..NONCES_PER_THREAD {
                        if let Ok(nonce) = generate_nonce() {
                            generated += 1;
                            if registry.register_nonce(&nonce).is_err() {
                                collisions += 1;
                            }
                        }
                    }

                    (generated, collisions)
                })
            })
            .collect();

        let mut total_generated = 0;
        let mut total_collisions = 0;

        for handle in handles {
            let (gen, col) = handle.join().expect("Thread panicked");
            total_generated += gen;
            total_collisions += col;
        }

        let duration = start.elapsed();

        println!("Concurrent test: {} nonces, {} collisions, {:?}",
                 total_generated, total_collisions, duration);

        assert_eq!(total_generated, NONCES_PER_THREAD * NUM_THREADS);
        assert_eq!(total_collisions, 0, "Should have zero collisions");
    }

    /// Memory usage estimation test.
    #[test]
    fn test_memory_estimation() {
        // Each nonce is 12 bytes, HashSet has ~8 bytes overhead per entry
        // So 1 million nonces should use approximately:
        // 1,000,000 * (12 + 8) = 20 MB + HashSet overhead

        // This test just verifies we can allocate enough memory
        let registry = NonceRegistry::with_capacity(1_000_000);
        assert!(registry.is_empty());

        // Generate a smaller sample to verify memory works
        for _ in 0..10_000 {
            let nonce = generate_nonce().expect("Failed to generate");
            registry.register_nonce(&nonce).expect("Should register");
        }

        assert_eq!(registry.len(), 10_000);
    }
}
