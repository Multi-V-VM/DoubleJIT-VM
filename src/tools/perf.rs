//! Performance profiling and metrics collection for DoubleJIT VM
//!
//! This module provides detailed performance metrics for all stages of the JIT pipeline:
//! - Frontend: Instruction decoding, cache performance
//! - Middleend: WAT generation, instruction translation
//! - Backend: WASM compilation, optimization
//! - Execution: Runtime performance, syscall overhead
//!
//! # Example
//!
//! ```
//! use doublejit_vm::tools::perf::{Profiler, ProfilerGuard};
//!
//! let mut profiler = Profiler::new();
//!
//! // Time a specific operation
//! {
//!     let _guard = profiler.start_timer("frontend.decode");
//!     // ... decode instructions ...
//! }
//!
//! // Increment counters
//! profiler.inc_counter("instructions.decoded", 1000);
//!
//! // Print results
//! profiler.print_report();
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Performance profiler that tracks timing and counters across the JIT pipeline
#[derive(Debug, Clone)]
pub struct Profiler {
    /// Timer measurements for different operations
    timers: HashMap<String, TimerStats>,

    /// Event counters (e.g., instructions decoded, cache hits)
    counters: HashMap<String, u64>,

    /// Start time of profiling session
    start_time: Instant,

    /// Whether profiling is enabled
    enabled: bool,
}

/// Statistics for a named timer
#[derive(Debug, Clone)]
struct TimerStats {
    /// Total accumulated time
    total_duration: Duration,

    /// Number of times this timer was recorded
    count: u64,

    /// Minimum duration observed
    min_duration: Duration,

    /// Maximum duration observed
    max_duration: Duration,
}

/// RAII guard that automatically records timing when dropped
pub struct ProfilerGuard<'a> {
    profiler: &'a mut Profiler,
    timer_name: String,
    start: Instant,
}

impl Profiler {
    /// Create a new profiler with profiling enabled
    pub fn new() -> Self {
        Self {
            timers: HashMap::new(),
            counters: HashMap::new(),
            start_time: Instant::now(),
            enabled: true,
        }
    }

    /// Create a disabled profiler (zero overhead)
    pub fn disabled() -> Self {
        Self {
            timers: HashMap::new(),
            counters: HashMap::new(),
            start_time: Instant::now(),
            enabled: false,
        }
    }

    /// Enable profiling
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable profiling
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if profiling is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Start a timer and return a guard that records the duration when dropped
    pub fn start_timer(&mut self, name: &str) -> ProfilerGuard {
        ProfilerGuard {
            profiler: self,
            timer_name: name.to_string(),
            start: Instant::now(),
        }
    }

    /// Record a duration for a named timer
    pub fn record_duration(&mut self, name: &str, duration: Duration) {
        if !self.enabled {
            return;
        }

        let stats = self.timers.entry(name.to_string()).or_insert(TimerStats {
            total_duration: Duration::ZERO,
            count: 0,
            min_duration: Duration::MAX,
            max_duration: Duration::ZERO,
        });

        stats.total_duration += duration;
        stats.count += 1;
        stats.min_duration = stats.min_duration.min(duration);
        stats.max_duration = stats.max_duration.max(duration);
    }

    /// Increment a counter by a specific amount
    pub fn inc_counter(&mut self, name: &str, amount: u64) {
        if !self.enabled {
            return;
        }
        *self.counters.entry(name.to_string()).or_insert(0) += amount;
    }

    /// Set a counter to a specific value
    pub fn set_counter(&mut self, name: &str, value: u64) {
        if !self.enabled {
            return;
        }
        *self.counters.entry(name.to_string()).or_insert(0) = value;
    }

    /// Get the value of a counter
    pub fn get_counter(&self, name: &str) -> u64 {
        self.counters.get(name).copied().unwrap_or(0)
    }

    /// Get total elapsed time since profiler creation
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Reset all timers and counters
    pub fn reset(&mut self) {
        self.timers.clear();
        self.counters.clear();
        self.start_time = Instant::now();
    }

    /// Print a formatted performance report to stdout
    pub fn print_report(&self) {
        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║              DoubleJIT VM Performance Report                     ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
        println!();
        println!("Total elapsed time: {:.3}s", self.elapsed().as_secs_f64());
        println!();

        // Print timers
        if !self.timers.is_empty() {
            println!("┌─ Timing Metrics ────────────────────────────────────────────────┐");
            println!("│ {:<30} {:>10} {:>10} {:>10} {:>10} │",
                "Operation", "Total", "Avg", "Min", "Max");
            println!("├──────────────────────────────────────────────────────────────────┤");

            let mut sorted_timers: Vec<_> = self.timers.iter().collect();
            sorted_timers.sort_by_key(|(name, _)| *name);

            for (name, stats) in sorted_timers {
                let avg = if stats.count > 0 {
                    stats.total_duration / stats.count as u32
                } else {
                    Duration::ZERO
                };

                println!("│ {:<30} {:>9.3}s {:>9.3}s {:>9.3}s {:>9.3}s │",
                    Self::truncate(name, 30),
                    stats.total_duration.as_secs_f64(),
                    avg.as_secs_f64(),
                    stats.min_duration.as_secs_f64(),
                    stats.max_duration.as_secs_f64(),
                );
            }
            println!("└──────────────────────────────────────────────────────────────────┘");
            println!();
        }

        // Print counters
        if !self.counters.is_empty() {
            println!("┌─ Event Counters ────────────────────────────────────────────────┐");
            println!("│ {:<40} {:>23} │", "Counter", "Count");
            println!("├──────────────────────────────────────────────────────────────────┤");

            let mut sorted_counters: Vec<_> = self.counters.iter().collect();
            sorted_counters.sort_by_key(|(name, _)| *name);

            for (name, count) in sorted_counters {
                println!("│ {:<40} {:>23} │",
                    Self::truncate(name, 40),
                    Self::format_number(*count)
                );
            }
            println!("└──────────────────────────────────────────────────────────────────┘");
            println!();
        }

        // Print derived metrics
        self.print_derived_metrics();
    }

    /// Print derived metrics (rates, ratios, etc.)
    fn print_derived_metrics(&self) {
        let mut has_metrics = false;

        println!("┌─ Derived Metrics ───────────────────────────────────────────────┐");

        // Cache hit rate
        let cache_hits = self.get_counter("cache.instruction.hits");
        let cache_misses = self.get_counter("cache.instruction.misses");
        if cache_hits + cache_misses > 0 {
            has_metrics = true;
            let hit_rate = cache_hits as f64 / (cache_hits + cache_misses) as f64 * 100.0;
            println!("│ Instruction cache hit rate: {:.2}%", hit_rate);
        }

        // Instructions per second
        if let Some(exec_time) = self.timers.get("execution.total") {
            let instr_count = self.get_counter("execution.instructions");
            if instr_count > 0 && exec_time.total_duration.as_secs_f64() > 0.0 {
                has_metrics = true;
                let ips = instr_count as f64 / exec_time.total_duration.as_secs_f64();
                println!("│ Instructions per second: {}", Self::format_number(ips as u64));
            }
        }

        // Translation throughput (instructions/second)
        if let Some(trans_time) = self.timers.get("middleend.translate") {
            let instr_count = self.get_counter("middleend.instructions");
            if instr_count > 0 && trans_time.total_duration.as_secs_f64() > 0.0 {
                has_metrics = true;
                let ips = instr_count as f64 / trans_time.total_duration.as_secs_f64();
                println!("│ Translation throughput: {} instr/s", Self::format_number(ips as u64));
            }
        }

        // Syscall overhead
        let syscall_count = self.get_counter("syscall.total");
        if syscall_count > 0 {
            if let Some(syscall_time) = self.timers.get("syscall.handler") {
                has_metrics = true;
                let avg_us = syscall_time.total_duration.as_micros() as f64 / syscall_count as f64;
                println!("│ Average syscall overhead: {:.2}μs", avg_us);
            }
        }

        // Pipeline breakdown (percentage of total time)
        let total_time = self.elapsed().as_secs_f64();
        if total_time > 0.0 {
            let frontend_time = self.timers.get("frontend.total")
                .map(|s| s.total_duration.as_secs_f64()).unwrap_or(0.0);
            let middleend_time = self.timers.get("middleend.total")
                .map(|s| s.total_duration.as_secs_f64()).unwrap_or(0.0);
            let backend_time = self.timers.get("backend.total")
                .map(|s| s.total_duration.as_secs_f64()).unwrap_or(0.0);
            let exec_time = self.timers.get("execution.total")
                .map(|s| s.total_duration.as_secs_f64()).unwrap_or(0.0);

            if frontend_time + middleend_time + backend_time + exec_time > 0.0 {
                has_metrics = true;
                println!("│");
                println!("│ Pipeline time breakdown:");
                if frontend_time > 0.0 {
                    println!("│   Frontend:   {:.2}% ({:.3}s)", frontend_time / total_time * 100.0, frontend_time);
                }
                if middleend_time > 0.0 {
                    println!("│   Middleend:  {:.2}% ({:.3}s)", middleend_time / total_time * 100.0, middleend_time);
                }
                if backend_time > 0.0 {
                    println!("│   Backend:    {:.2}% ({:.3}s)", backend_time / total_time * 100.0, backend_time);
                }
                if exec_time > 0.0 {
                    println!("│   Execution:  {:.2}% ({:.3}s)", exec_time / total_time * 100.0, exec_time);
                }
            }
        }

        if !has_metrics {
            println!("│ No derived metrics available");
        }

        println!("└──────────────────────────────────────────────────────────────────┘");
        println!();
    }

    /// Export metrics to CSV format
    pub fn export_csv(&self, path: &str) -> std::io::Result<()> {
        use std::fs::File;
        use std::io::Write;

        let mut file = File::create(path)?;

        // Write timers
        writeln!(file, "# Timers")?;
        writeln!(file, "Name,Total(s),Count,Avg(s),Min(s),Max(s)")?;
        for (name, stats) in &self.timers {
            let avg = if stats.count > 0 {
                stats.total_duration.as_secs_f64() / stats.count as f64
            } else {
                0.0
            };
            writeln!(file, "{},{},{},{},{},{}",
                name,
                stats.total_duration.as_secs_f64(),
                stats.count,
                avg,
                stats.min_duration.as_secs_f64(),
                stats.max_duration.as_secs_f64()
            )?;
        }

        // Write counters
        writeln!(file, "\n# Counters")?;
        writeln!(file, "Name,Value")?;
        for (name, count) in &self.counters {
            writeln!(file, "{},{}", name, count)?;
        }

        Ok(())
    }

    /// Truncate a string to a maximum length
    fn truncate(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }

    /// Format a number with thousands separators
    fn format_number(n: u64) -> String {
        let s = n.to_string();
        let mut result = String::new();
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(c);
        }
        result.chars().rev().collect()
    }
}

impl Default for Profiler {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Drop for ProfilerGuard<'a> {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        self.profiler.record_duration(&self.timer_name, duration);
    }
}

/// Common timer names for consistency
pub mod timers {
    // Frontend timers
    pub const FRONTEND_TOTAL: &str = "frontend.total";
    pub const FRONTEND_DECODE: &str = "frontend.decode";
    pub const FRONTEND_CACHE_LOOKUP: &str = "frontend.cache_lookup";

    // Middleend timers
    pub const MIDDLEEND_TOTAL: &str = "middleend.total";
    pub const MIDDLEEND_TRANSLATE: &str = "middleend.translate";
    pub const MIDDLEEND_WAT_GEN: &str = "middleend.wat_generation";
    pub const MIDDLEEND_EMIT: &str = "middleend.emit";

    // Backend timers
    pub const BACKEND_TOTAL: &str = "backend.total";
    pub const BACKEND_WAT_TO_WASM: &str = "backend.wat_to_wasm";
    pub const BACKEND_COMPILE: &str = "backend.compile";
    pub const BACKEND_OPTIMIZE: &str = "backend.optimize";

    // Execution timers
    pub const EXECUTION_TOTAL: &str = "execution.total";
    pub const EXECUTION_INIT: &str = "execution.init";
    pub const EXECUTION_RUN: &str = "execution.run";

    // Syscall timers
    pub const SYSCALL_HANDLER: &str = "syscall.handler";
}

/// Common counter names for consistency
pub mod counters {
    // Instruction counters
    pub const INSTRUCTIONS_DECODED: &str = "instructions.decoded";
    pub const INSTRUCTIONS_TRANSLATED: &str = "middleend.instructions";
    pub const INSTRUCTIONS_EXECUTED: &str = "execution.instructions";

    // Cache counters
    pub const CACHE_INSTR_HITS: &str = "cache.instruction.hits";
    pub const CACHE_INSTR_MISSES: &str = "cache.instruction.misses";
    pub const CACHE_BLOCK_HITS: &str = "cache.block.hits";
    pub const CACHE_BLOCK_MISSES: &str = "cache.block.misses";

    // Memory counters
    pub const MEMORY_PAGES: &str = "memory.pages";
    pub const MEMORY_BYTES: &str = "memory.bytes";

    // Syscall counters
    pub const SYSCALL_TOTAL: &str = "syscall.total";
    pub const SYSCALL_WRITE: &str = "syscall.write";
    pub const SYSCALL_READ: &str = "syscall.read";
    pub const SYSCALL_EXIT: &str = "syscall.exit";

    // WAT generation
    pub const WAT_SIZE_BYTES: &str = "wat.size_bytes";
    pub const WASM_SIZE_BYTES: &str = "wasm.size_bytes";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_profiler_timers() {
        let mut profiler = Profiler::new();

        {
            let _guard = profiler.start_timer("test.operation");
            thread::sleep(Duration::from_millis(10));
        }

        let stats = profiler.timers.get("test.operation").unwrap();
        assert_eq!(stats.count, 1);
        assert!(stats.total_duration.as_millis() >= 10);
    }

    #[test]
    fn test_profiler_counters() {
        let mut profiler = Profiler::new();

        profiler.inc_counter("test.counter", 5);
        profiler.inc_counter("test.counter", 3);

        assert_eq!(profiler.get_counter("test.counter"), 8);
    }

    #[test]
    fn test_profiler_disabled() {
        let mut profiler = Profiler::disabled();

        profiler.inc_counter("test.counter", 10);
        {
            let _guard = profiler.start_timer("test.timer");
        }

        // Should not record anything when disabled
        assert_eq!(profiler.counters.len(), 0);
        assert_eq!(profiler.timers.len(), 0);
    }

    #[test]
    fn test_format_number() {
        assert_eq!(Profiler::format_number(1000), "1,000");
        assert_eq!(Profiler::format_number(1000000), "1,000,000");
        assert_eq!(Profiler::format_number(42), "42");
    }
}
