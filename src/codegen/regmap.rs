//! Register mapping and allocation for RISC-V to WASM translation
//!
//! This module provides utilities for mapping RISC-V registers to WASM globals
//! and tracking register usage for optimization.

use std::collections::{HashMap, HashSet};

/// RISC-V register index (0-31 for integer registers)
pub type RegIndex = u8;

/// Register mapping from RISC-V registers to WASM global names
#[derive(Debug, Clone)]
pub struct RegisterMap {
    /// Mapping from RISC-V register index to WASM global name
    reg_to_global: HashMap<RegIndex, String>,

    /// Set of registers that are read in the current basic block
    read_registers: HashSet<RegIndex>,

    /// Set of registers that are written in the current basic block
    written_registers: HashSet<RegIndex>,

    /// Set of registers that are live (needed later)
    live_registers: HashSet<RegIndex>,
}

impl RegisterMap {
    /// Create a new register map with standard RISC-V register names
    pub fn new() -> Self {
        let mut map = HashMap::new();

        // Map all 32 RISC-V integer registers to WASM globals
        for i in 0..32 {
            map.insert(i, format!("$x{}", i));
        }

        Self {
            reg_to_global: map,
            read_registers: HashSet::new(),
            written_registers: HashSet::new(),
            live_registers: HashSet::new(),
        }
    }

    /// Get the WASM global name for a RISC-V register
    pub fn get_global_name(&self, reg: RegIndex) -> Option<&str> {
        self.reg_to_global.get(&reg).map(|s| s.as_str())
    }

    /// Mark a register as read
    pub fn mark_read(&mut self, reg: RegIndex) {
        if reg != 0 {  // x0 is always zero, skip tracking
            self.read_registers.insert(reg);
            self.live_registers.insert(reg);
        }
    }

    /// Mark a register as written
    pub fn mark_written(&mut self, reg: RegIndex) {
        if reg != 0 {  // x0 is always zero, skip tracking
            self.written_registers.insert(reg);
        }
    }

    /// Check if a register is read in the current block
    pub fn is_read(&self, reg: RegIndex) -> bool {
        self.read_registers.contains(&reg)
    }

    /// Check if a register is written in the current block
    pub fn is_written(&self, reg: RegIndex) -> bool {
        self.written_registers.contains(&reg)
    }

    /// Check if a register is live (needed later)
    pub fn is_live(&self, reg: RegIndex) -> bool {
        self.live_registers.contains(&reg)
    }

    /// Mark a register as dead (no longer needed)
    pub fn mark_dead(&mut self, reg: RegIndex) {
        self.live_registers.remove(&reg);
    }

    /// Reset tracking for a new basic block
    pub fn reset_block_tracking(&mut self) {
        self.read_registers.clear();
        self.written_registers.clear();
    }

    /// Get registers that are written but never read (potential dead stores)
    pub fn get_dead_stores(&self) -> Vec<RegIndex> {
        self.written_registers
            .iter()
            .filter(|&&reg| !self.read_registers.contains(&reg) && !self.live_registers.contains(&reg))
            .copied()
            .collect()
    }

    /// Get the number of live registers
    pub fn live_count(&self) -> usize {
        self.live_registers.len()
    }
}

impl Default for RegisterMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Special register names for RISC-V ABI
#[allow(dead_code)]
pub mod abi {
    use super::RegIndex;

    // Special purpose registers
    pub const ZERO: RegIndex = 0;   // Hard-wired zero
    pub const RA: RegIndex = 1;     // Return address
    pub const SP: RegIndex = 2;     // Stack pointer
    pub const GP: RegIndex = 3;     // Global pointer
    pub const TP: RegIndex = 4;     // Thread pointer

    // Temporary registers
    pub const T0: RegIndex = 5;
    pub const T1: RegIndex = 6;
    pub const T2: RegIndex = 7;

    // Saved registers / Frame pointer
    pub const S0_FP: RegIndex = 8;
    pub const S1: RegIndex = 9;

    // Function arguments / Return values
    pub const A0: RegIndex = 10;
    pub const A1: RegIndex = 11;
    pub const A2: RegIndex = 12;
    pub const A3: RegIndex = 13;
    pub const A4: RegIndex = 14;
    pub const A5: RegIndex = 15;
    pub const A6: RegIndex = 16;
    pub const A7: RegIndex = 17;

    // Saved registers
    pub const S2: RegIndex = 18;
    pub const S3: RegIndex = 19;
    pub const S4: RegIndex = 20;
    pub const S5: RegIndex = 21;
    pub const S6: RegIndex = 22;
    pub const S7: RegIndex = 23;
    pub const S8: RegIndex = 24;
    pub const S9: RegIndex = 25;
    pub const S10: RegIndex = 26;
    pub const S11: RegIndex = 27;

    // Temporary registers
    pub const T3: RegIndex = 28;
    pub const T4: RegIndex = 29;
    pub const T5: RegIndex = 30;
    pub const T6: RegIndex = 31;

    /// Get the ABI name for a register
    pub fn get_abi_name(reg: RegIndex) -> &'static str {
        match reg {
            ZERO => "zero",
            RA => "ra",
            SP => "sp",
            GP => "gp",
            TP => "tp",
            T0 => "t0",
            T1 => "t1",
            T2 => "t2",
            S0_FP => "s0/fp",
            S1 => "s1",
            A0 => "a0",
            A1 => "a1",
            A2 => "a2",
            A3 => "a3",
            A4 => "a4",
            A5 => "a5",
            A6 => "a6",
            A7 => "a7",
            S2 => "s2",
            S3 => "s3",
            S4 => "s4",
            S5 => "s5",
            S6 => "s6",
            S7 => "s7",
            S8 => "s8",
            S9 => "s9",
            S10 => "s10",
            S11 => "s11",
            T3 => "t3",
            T4 => "t4",
            T5 => "t5",
            T6 => "t6",
            _ => "unknown",
        }
    }

    /// Check if a register is caller-saved (temporary)
    pub fn is_caller_saved(reg: RegIndex) -> bool {
        matches!(reg, T0 | T1 | T2 | T3 | T4 | T5 | T6 | A0 | A1 | A2 | A3 | A4 | A5 | A6 | A7)
    }

    /// Check if a register is callee-saved
    pub fn is_callee_saved(reg: RegIndex) -> bool {
        matches!(reg, S0_FP | S1 | S2 | S3 | S4 | S5 | S6 | S7 | S8 | S9 | S10 | S11)
    }
}

/// Register usage statistics for optimization
#[derive(Debug, Clone, Default)]
pub struct RegisterStats {
    /// Number of times each register is read
    read_count: HashMap<RegIndex, u64>,

    /// Number of times each register is written
    write_count: HashMap<RegIndex, u64>,

    /// Total register pressure (max live registers)
    max_pressure: usize,
}

impl RegisterStats {
    /// Create new register statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a register read
    pub fn record_read(&mut self, reg: RegIndex) {
        *self.read_count.entry(reg).or_insert(0) += 1;
    }

    /// Record a register write
    pub fn record_write(&mut self, reg: RegIndex) {
        *self.write_count.entry(reg).or_insert(0) += 1;
    }

    /// Update register pressure
    pub fn update_pressure(&mut self, live_count: usize) {
        self.max_pressure = self.max_pressure.max(live_count);
    }

    /// Get read count for a register
    pub fn get_read_count(&self, reg: RegIndex) -> u64 {
        self.read_count.get(&reg).copied().unwrap_or(0)
    }

    /// Get write count for a register
    pub fn get_write_count(&self, reg: RegIndex) -> u64 {
        self.write_count.get(&reg).copied().unwrap_or(0)
    }

    /// Get maximum register pressure
    pub fn max_pressure(&self) -> usize {
        self.max_pressure
    }

    /// Get most frequently used registers
    pub fn most_used_registers(&self, n: usize) -> Vec<(RegIndex, u64)> {
        let mut regs: Vec<_> = self.read_count
            .iter()
            .map(|(&reg, &count)| (reg, count))
            .collect();
        regs.sort_by(|a, b| b.1.cmp(&a.1));
        regs.truncate(n);
        regs
    }

    /// Print statistics
    pub fn print_stats(&self) {
        println!("Register Usage Statistics:");
        println!("  Max register pressure: {} live registers", self.max_pressure);
        println!("  Most used registers:");
        for (reg, count) in self.most_used_registers(10) {
            println!("    x{} ({}): {} reads", reg, abi::get_abi_name(reg), count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_map_creation() {
        let map = RegisterMap::new();
        assert_eq!(map.get_global_name(0), Some("$x0"));
        assert_eq!(map.get_global_name(31), Some("$x31"));
        assert_eq!(map.get_global_name(32), None);
    }

    #[test]
    fn test_register_tracking() {
        let mut map = RegisterMap::new();
        map.mark_read(10);
        map.mark_written(11);

        assert!(map.is_read(10));
        assert!(map.is_written(11));
        assert!(!map.is_read(12));
    }

    #[test]
    fn test_dead_store_detection() {
        let mut map = RegisterMap::new();
        map.mark_written(5);  // Write to t0
        map.mark_read(6);     // Read from t1
        map.mark_written(6);  // Write to t1

        let dead = map.get_dead_stores();
        assert!(dead.contains(&5));  // t0 is written but never read
        assert!(!dead.contains(&6)); // t1 is read
    }

    #[test]
    fn test_abi_names() {
        assert_eq!(abi::get_abi_name(abi::ZERO), "zero");
        assert_eq!(abi::get_abi_name(abi::SP), "sp");
        assert_eq!(abi::get_abi_name(abi::RA), "ra");
        assert!(abi::is_caller_saved(abi::T0));
        assert!(abi::is_callee_saved(abi::S0_FP));
    }

    #[test]
    fn test_register_stats() {
        let mut stats = RegisterStats::new();
        stats.record_read(10);
        stats.record_read(10);
        stats.record_write(10);
        stats.update_pressure(15);

        assert_eq!(stats.get_read_count(10), 2);
        assert_eq!(stats.get_write_count(10), 1);
        assert_eq!(stats.max_pressure(), 15);
    }
}
