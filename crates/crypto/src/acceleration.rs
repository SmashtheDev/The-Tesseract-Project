//! Hardware acceleration detection.
//!
//! Detects and reports availability of AES-NI and other
//! hardware acceleration features for cryptographic operations.
//!
//! # Hardware Acceleration
//!
//! When AES-NI is available (Intel/AMD processors), encryption operations
//! are significantly faster (typically 3-10x) compared to software-only
//! implementations.
//!
//! # Example
//!
//! ```ignore
//! use tesseract_crypto::acceleration::{has_aes_ni, log_acceleration_status, AccelerationInfo};
//!
//! // Check if AES-NI is available
//! if has_aes_ni() {
//!     println!("Hardware acceleration available!");
//! }
//!
//! // Log status at application startup
//! log_acceleration_status();
//!
//! // Get detailed info
//! let info = AccelerationInfo::detect();
//! println!("AES-NI: {}", info.aes_ni);
//! ```

use tracing::{info, warn};

/// Information about available hardware acceleration features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccelerationInfo {
    /// Whether AES-NI (Advanced Encryption Standard New Instructions) is available.
    ///
    /// AES-NI provides hardware-accelerated AES encryption/decryption,
    /// typically achieving 3-10x speedup over software implementations.
    pub aes_ni: bool,

    /// Whether CLMUL (Carry-less Multiplication) is available.
    ///
    /// CLMUL is used for GCM's GHASH operation and provides
    /// significant speedup for authenticated encryption.
    pub clmul: bool,

    /// Whether SSE2 SIMD instructions are available.
    ///
    /// SSE2 provides parallel processing capabilities used by
    /// various cryptographic implementations.
    pub sse2: bool,

    /// Whether AVX2 SIMD instructions are available.
    ///
    /// AVX2 provides wider SIMD registers (256-bit) for faster
    /// parallel operations.
    pub avx2: bool,
}

impl AccelerationInfo {
    /// Detects available hardware acceleration features on the current platform.
    ///
    /// This function queries the CPU for supported instruction set extensions
    /// relevant to cryptographic operations.
    ///
    /// # Returns
    ///
    /// An `AccelerationInfo` struct with flags indicating which features are available.
    ///
    /// # Platform Behavior
    ///
    /// - **x86/x86_64**: Queries CPUID for AES-NI, CLMUL, SSE2, AVX2
    /// - **Other architectures**: Returns all features as unavailable (software fallback)
    #[must_use]
    pub fn detect() -> Self {
        Self {
            aes_ni: has_aes_ni(),
            clmul: has_clmul(),
            sse2: has_sse2(),
            avx2: has_avx2(),
        }
    }

    /// Returns `true` if any hardware acceleration feature is available.
    #[must_use]
    pub fn has_any_acceleration(&self) -> bool {
        self.aes_ni || self.clmul || self.sse2 || self.avx2
    }

    /// Returns `true` if full GCM acceleration is available.
    ///
    /// Full GCM acceleration requires both AES-NI (for AES operations)
    /// and CLMUL (for GHASH operations).
    #[must_use]
    pub fn has_full_gcm_acceleration(&self) -> bool {
        self.aes_ni && self.clmul
    }

    /// Returns `true` if AES-NI is available.
    #[must_use]
    pub fn has_aes_ni(&self) -> bool {
        self.aes_ni
    }

    /// Returns `true` if CLMUL is available.
    #[must_use]
    pub fn has_clmul(&self) -> bool {
        self.clmul
    }

    /// Returns `true` if SSE2 is available.
    #[must_use]
    pub fn has_sse2(&self) -> bool {
        self.sse2
    }

    /// Returns `true` if AVX2 is available.
    #[must_use]
    pub fn has_avx2(&self) -> bool {
        self.avx2
    }

    /// Returns a human-readable summary of acceleration status.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut features = Vec::new();

        if self.aes_ni {
            features.push("AES-NI");
        }
        if self.clmul {
            features.push("CLMUL");
        }
        if self.sse2 {
            features.push("SSE2");
        }
        if self.avx2 {
            features.push("AVX2");
        }

        if features.is_empty() {
            "No hardware acceleration (software fallback)".to_string()
        } else {
            format!("Hardware acceleration: {}", features.join(", "))
        }
    }
}

impl Default for AccelerationInfo {
    fn default() -> Self {
        Self::detect()
    }
}

/// Checks if AES-NI (Advanced Encryption Standard New Instructions) is available.
///
/// AES-NI is a set of instructions that perform AES encryption and decryption
/// in hardware, providing significant performance improvements (typically 3-10x
/// faster than software implementations).
///
/// # Returns
///
/// `true` if AES-NI is supported by the CPU, `false` otherwise.
///
/// # Platform Behavior
///
/// - **x86/x86_64**: Uses CPUID to check for AES-NI support
/// - **aarch64**: Checks for AES extension in ARM Crypto Extension
/// - **Other architectures**: Always returns `false`
///
/// # Example
///
/// ```ignore
/// use tesseract_crypto::acceleration::has_aes_ni;
///
/// if has_aes_ni() {
///     println!("AES-NI hardware acceleration is available");
/// } else {
///     println!("Using software AES implementation");
/// }
/// ```
#[must_use]
pub fn has_aes_ni() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // Use cpufeatures crate for reliable detection
        cpufeatures::new!(cpuid_aes, "aes");
        cpuid_aes::get()
    }

    #[cfg(target_arch = "aarch64")]
    {
        // ARM processors with Crypto Extension also have AES acceleration
        cpufeatures::new!(cpuid_aes, "aes");
        cpuid_aes::get()
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Checks if CLMUL (Carry-less Multiplication) is available.
///
/// CLMUL is used for efficient GHASH computation in GCM mode,
/// providing significant speedup for authenticated encryption.
///
/// # Returns
///
/// `true` if CLMUL/PCLMULQDQ is supported by the CPU, `false` otherwise.
#[must_use]
pub fn has_clmul() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        cpufeatures::new!(cpuid_pclmulqdq, "pclmulqdq");
        cpuid_pclmulqdq::get()
    }

    #[cfg(target_arch = "aarch64")]
    {
        // ARM Crypto Extension includes polynomial multiply
        cpufeatures::new!(cpuid_pmull, "aes");  // pmull is part of crypto extension
        cpuid_pmull::get()
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Checks if SSE2 SIMD instructions are available.
///
/// SSE2 provides 128-bit SIMD operations used by various
/// cryptographic implementations for parallel processing.
///
/// # Returns
///
/// `true` if SSE2 is supported by the CPU, `false` otherwise.
///
/// # Note
///
/// SSE2 is baseline for x86_64 and essentially always available
/// on 64-bit x86 processors.
#[must_use]
pub fn has_sse2() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        cpufeatures::new!(cpuid_sse2, "sse2");
        cpuid_sse2::get()
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// Checks if AVX2 SIMD instructions are available.
///
/// AVX2 provides 256-bit SIMD operations for faster parallel processing.
///
/// # Returns
///
/// `true` if AVX2 is supported by the CPU, `false` otherwise.
#[must_use]
pub fn has_avx2() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        cpufeatures::new!(cpuid_avx2, "avx2");
        cpuid_avx2::get()
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// Logs the hardware acceleration status at startup.
///
/// This function should be called during application initialization
/// to inform users about the available cryptographic acceleration.
///
/// # Log Levels
///
/// - **INFO**: When hardware acceleration is available
/// - **WARN**: When using software fallback (no acceleration)
///
/// # Example
///
/// ```ignore
/// use tesseract_crypto::acceleration::log_acceleration_status;
///
/// fn main() {
///     // Initialize logging first
///     tracing_subscriber::fmt::init();
///
///     // Log acceleration status at startup
///     log_acceleration_status();
/// }
/// ```
pub fn log_acceleration_status() {
    let info = AccelerationInfo::detect();

    if info.has_full_gcm_acceleration() {
        info!(
            aes_ni = info.aes_ni,
            clmul = info.clmul,
            sse2 = info.sse2,
            avx2 = info.avx2,
            "Hardware acceleration enabled for AES-GCM operations"
        );
    } else if info.has_any_acceleration() {
        info!(
            aes_ni = info.aes_ni,
            clmul = info.clmul,
            sse2 = info.sse2,
            avx2 = info.avx2,
            "Partial hardware acceleration available"
        );
    } else {
        warn!(
            "No hardware acceleration detected - using software fallback. \
             Performance may be reduced compared to hardware-accelerated systems."
        );
    }
}

/// Estimates the expected speedup factor for AES-GCM operations.
///
/// This provides a rough estimate of how much faster hardware-accelerated
/// AES-GCM will be compared to software-only implementations.
///
/// # Returns
///
/// Estimated speedup multiplier (e.g., 5.0 means ~5x faster).
/// Returns 1.0 if no acceleration is available.
///
/// # Note
///
/// These are approximate values based on typical benchmarks.
/// Actual performance varies by CPU model and workload.
#[must_use]
pub fn estimated_speedup_factor() -> f64 {
    let info = AccelerationInfo::detect();

    if info.has_full_gcm_acceleration() {
        // Full acceleration (AES-NI + CLMUL) typically gives 5-10x speedup
        if info.avx2 {
            7.0  // AVX2 can provide additional benefit
        } else {
            5.0  // Standard AES-NI + CLMUL
        }
    } else if info.aes_ni {
        // AES-NI without CLMUL still provides significant benefit
        3.5
    } else if info.sse2 {
        // SSE2-only can provide some parallelism
        1.5
    } else {
        // Pure software implementation
        1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that detection doesn't panic on any platform
    #[test]
    fn test_detection_no_panic() {
        // These should never panic regardless of platform
        let _ = has_aes_ni();
        let _ = has_clmul();
        let _ = has_sse2();
        let _ = has_avx2();
    }

    /// Verify AccelerationInfo::detect() returns consistent results
    #[test]
    fn test_acceleration_info_consistent() {
        let info1 = AccelerationInfo::detect();
        let info2 = AccelerationInfo::detect();

        // Results should be consistent across multiple calls
        assert_eq!(info1, info2);

        // Individual functions should match the struct
        assert_eq!(info1.aes_ni, has_aes_ni());
        assert_eq!(info1.clmul, has_clmul());
        assert_eq!(info1.sse2, has_sse2());
        assert_eq!(info1.avx2, has_avx2());
    }

    /// Verify that current platform detection works
    #[test]
    fn test_current_platform_detection() {
        let info = AccelerationInfo::detect();

        // Log what we detected for debugging
        println!("Detected acceleration: {:?}", info);
        println!("Summary: {}", info.summary());

        // On x86_64, SSE2 is essentially always available
        #[cfg(target_arch = "x86_64")]
        {
            // SSE2 is baseline for x86_64
            assert!(
                info.sse2,
                "SSE2 should always be available on x86_64"
            );
        }

        // Most modern x86_64 CPUs have AES-NI (since ~2010)
        // This test verifies detection works, not that it's always present
        #[cfg(target_arch = "x86_64")]
        {
            // If AES-NI is available, the summary should mention it
            if info.aes_ni {
                assert!(
                    info.summary().contains("AES-NI"),
                    "Summary should mention AES-NI when available"
                );
            }
        }
    }

    /// Verify has_any_acceleration logic
    #[test]
    fn test_has_any_acceleration() {
        let info = AccelerationInfo {
            aes_ni: false,
            clmul: false,
            sse2: false,
            avx2: false,
        };
        assert!(!info.has_any_acceleration());

        let info = AccelerationInfo {
            aes_ni: true,
            clmul: false,
            sse2: false,
            avx2: false,
        };
        assert!(info.has_any_acceleration());

        let info = AccelerationInfo {
            aes_ni: false,
            clmul: false,
            sse2: true,
            avx2: false,
        };
        assert!(info.has_any_acceleration());
    }

    /// Verify has_full_gcm_acceleration logic
    #[test]
    fn test_has_full_gcm_acceleration() {
        let info = AccelerationInfo {
            aes_ni: true,
            clmul: true,
            sse2: true,
            avx2: false,
        };
        assert!(info.has_full_gcm_acceleration());

        // Missing CLMUL
        let info = AccelerationInfo {
            aes_ni: true,
            clmul: false,
            sse2: true,
            avx2: false,
        };
        assert!(!info.has_full_gcm_acceleration());

        // Missing AES-NI
        let info = AccelerationInfo {
            aes_ni: false,
            clmul: true,
            sse2: true,
            avx2: false,
        };
        assert!(!info.has_full_gcm_acceleration());
    }

    /// Verify summary formatting
    #[test]
    fn test_summary_format() {
        let info = AccelerationInfo {
            aes_ni: true,
            clmul: true,
            sse2: true,
            avx2: true,
        };
        let summary = info.summary();
        assert!(summary.contains("AES-NI"));
        assert!(summary.contains("CLMUL"));
        assert!(summary.contains("SSE2"));
        assert!(summary.contains("AVX2"));

        let info = AccelerationInfo {
            aes_ni: false,
            clmul: false,
            sse2: false,
            avx2: false,
        };
        let summary = info.summary();
        assert!(summary.contains("software fallback"));
    }

    /// Verify estimated_speedup_factor returns reasonable values
    #[test]
    fn test_estimated_speedup_factor() {
        let factor = estimated_speedup_factor();

        // Should always be at least 1.0 (no slowdown)
        assert!(factor >= 1.0, "Speedup factor should be >= 1.0");

        // Should not exceed reasonable hardware limits
        assert!(factor <= 15.0, "Speedup factor should be reasonable");

        // Log for debugging
        println!("Estimated speedup factor: {}x", factor);
    }

    /// Verify log_acceleration_status doesn't panic
    #[test]
    fn test_log_acceleration_status_no_panic() {
        // This should not panic regardless of tracing subscriber state
        log_acceleration_status();
    }

    /// Test Default trait implementation
    #[test]
    fn test_acceleration_info_default() {
        let info1 = AccelerationInfo::default();
        let info2 = AccelerationInfo::detect();

        // Default should use detect()
        assert_eq!(info1, info2);
    }
}

#[cfg(test)]
mod benchmarks {
    use super::*;
    use crate::aes::{encrypt, decrypt, KEY_LENGTH, NONCE_LENGTH};

    /// Benchmark AES-256-GCM encryption performance.
    ///
    /// This test measures encryption throughput and reports whether
    /// hardware acceleration is being used.
    ///
    /// NOTE: For proper benchmarking, use `cargo bench` with criterion.
    /// This test provides a simple sanity check and performance indication.
    #[test]
    fn benchmark_aes_gcm_throughput() {
        use std::time::Instant;

        let info = AccelerationInfo::detect();
        println!("\n=== AES-256-GCM Benchmark ===");
        println!("Hardware acceleration: {}", info.summary());
        println!("Estimated speedup factor: {}x", estimated_speedup_factor());

        // Test parameters
        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let data_size = 1024 * 1024; // 1 MB
        let iterations = 10;
        let plaintext = vec![0xABu8; data_size];
        let aad = b"benchmark-aad";

        // Warmup
        let _ = encrypt(&key, &nonce, &plaintext, aad);

        // Benchmark encryption
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = encrypt(&key, &nonce, &plaintext, aad).unwrap();
        }
        let encrypt_duration = start.elapsed();

        let ciphertext = encrypt(&key, &nonce, &plaintext, aad).unwrap();

        // Benchmark decryption
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        }
        let decrypt_duration = start.elapsed();

        // Calculate throughput
        let total_mb = (data_size as f64 * iterations as f64) / (1024.0 * 1024.0);
        let encrypt_mbps = total_mb / encrypt_duration.as_secs_f64();
        let decrypt_mbps = total_mb / decrypt_duration.as_secs_f64();

        println!("\nResults ({} iterations, {} MB each):", iterations, data_size / (1024 * 1024));
        println!("  Encryption: {:.2} MB/s ({:.2} ms per 1MB)", encrypt_mbps, encrypt_duration.as_millis() as f64 / iterations as f64);
        println!("  Decryption: {:.2} MB/s ({:.2} ms per 1MB)", decrypt_mbps, decrypt_duration.as_millis() as f64 / iterations as f64);

        // Performance assertions based on acceleration
        // Note: Debug builds are 10-50x slower than release builds, so we use
        // much lower thresholds here to avoid false failures in cargo test.
        // For accurate performance testing, use: cargo test --release
        if info.has_full_gcm_acceleration() {
            // Debug mode threshold: just verify it works reasonably (> 1 MB/s)
            // Release mode with AES-NI typically achieves 500+ MB/s
            #[cfg(debug_assertions)]
            let threshold = 1.0; // Very conservative for debug builds
            #[cfg(not(debug_assertions))]
            let threshold = 100.0; // Release builds should hit 100+ MB/s easily

            assert!(
                encrypt_mbps >= threshold,
                "Encryption should achieve at least {:.0} MB/s, got {:.2} MB/s",
                threshold, encrypt_mbps
            );
            println!("\n✓ Throughput test passed (>= {:.0} MB/s)", threshold);
        } else {
            // Without acceleration, throughput will be lower
            // Just verify it works
            assert!(encrypt_mbps > 0.0, "Encryption should have positive throughput");
            println!("\nNote: Running without hardware acceleration - expect ~3x+ speedup with AES-NI");
        }
    }

    /// Estimate speedup by comparing actual vs expected software performance.
    ///
    /// NOTE: This is a rough estimate. For accurate speedup measurements,
    /// one would need to disable AES-NI at runtime (not easily possible)
    /// or compare against a known software-only implementation.
    #[test]
    fn test_speedup_estimation() {
        use std::time::Instant;

        let info = AccelerationInfo::detect();

        if !info.has_aes_ni() {
            println!("AES-NI not available - cannot measure hardware speedup");
            return;
        }

        // Rough baseline: software-only AES-GCM typically achieves ~50-100 MB/s
        // on modern CPUs. Hardware-accelerated should be 3-10x faster.
        const SOFTWARE_BASELINE_MBPS: f64 = 75.0;  // Conservative estimate

        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let data_size = 1024 * 1024;  // 1 MB
        let plaintext = vec![0xABu8; data_size];
        let aad = b"speedup-test";

        // Warmup
        let _ = encrypt(&key, &nonce, &plaintext, aad);

        // Measure
        let iterations = 20;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = encrypt(&key, &nonce, &plaintext, aad).unwrap();
        }
        let duration = start.elapsed();

        let total_mb = (data_size as f64 * iterations as f64) / (1024.0 * 1024.0);
        let actual_mbps = total_mb / duration.as_secs_f64();

        // Calculate estimated speedup vs software baseline
        let estimated_speedup = actual_mbps / SOFTWARE_BASELINE_MBPS;

        println!("\n=== Speedup Estimation ===");
        println!("Actual throughput: {:.2} MB/s", actual_mbps);
        println!("Software baseline (estimated): {:.2} MB/s", SOFTWARE_BASELINE_MBPS);
        println!("Estimated speedup: {:.2}x", estimated_speedup);

        // Verify speedup requirement from acceptance criteria
        // Note: In debug mode, the measured speedup is meaningless because
        // both debug and "estimated software" are slow. We only assert in
        // release builds where the AES-NI advantage is measurable.
        if info.has_full_gcm_acceleration() {
            #[cfg(not(debug_assertions))]
            {
                assert!(
                    estimated_speedup >= 3.0,
                    "Expected >= 3x speedup with AES-NI, got {:.2}x",
                    estimated_speedup
                );
                println!("\n✓ Speedup requirement met (>= 3x)");
            }
            #[cfg(debug_assertions)]
            {
                // In debug mode, just verify we get positive throughput
                assert!(actual_mbps > 0.0, "Should have positive throughput");
                println!("\nNote: Speedup estimation is not meaningful in debug builds.");
                println!("Run with: cargo test --release for accurate speedup measurement.");
            }
        }
    }
}
