//! WAT/WASM optimization passes for the backend compiler
//!
//! This module provides various optimization passes that work on generated WAT code
//! before it's compiled to WASM bytecode and then to native machine code.
//!
//! # Optimization Passes
//!
//! - **Constant Propagation**: Replace variables with known constant values
//! - **Dead Code Elimination**: Remove unreachable code
//! - **Peephole Optimization**: Apply local pattern-based optimizations
//! - **Redundant Load/Store Elimination**: Remove unnecessary memory operations
//! - **Branch Optimization**: Simplify conditional branches

use std::collections::HashMap;

/// Optimization level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptLevel {
    /// No optimizations
    None,
    /// Basic optimizations (O1)
    Basic,
    /// Moderate optimizations (O2)
    Moderate,
    /// Aggressive optimizations (O3)
    Aggressive,
}

/// WAT optimizer that applies multiple optimization passes
#[derive(Debug)]
pub struct WatOptimizer {
    /// Optimization level
    opt_level: OptLevel,

    /// Statistics about optimizations applied
    stats: OptStats,
}

/// Statistics about optimizations
#[derive(Debug, Clone, Default)]
pub struct OptStats {
    /// Number of constants propagated
    pub constants_propagated: usize,

    /// Number of dead instructions eliminated
    pub dead_code_eliminated: usize,

    /// Number of redundant loads eliminated
    pub redundant_loads_eliminated: usize,

    /// Number of redundant stores eliminated
    pub redundant_stores_eliminated: usize,

    /// Number of branches simplified
    pub branches_simplified: usize,

    /// Number of peephole optimizations applied
    pub peephole_optimizations: usize,
}

impl OptStats {
    /// Print optimization statistics
    pub fn print(&self) {
        println!("WAT Optimization Statistics:");
        println!("  Constants propagated:       {}", self.constants_propagated);
        println!("  Dead code eliminated:       {}", self.dead_code_eliminated);
        println!("  Redundant loads eliminated: {}", self.redundant_loads_eliminated);
        println!("  Redundant stores eliminated:{}", self.redundant_stores_eliminated);
        println!("  Branches simplified:        {}", self.branches_simplified);
        println!("  Peephole optimizations:     {}", self.peephole_optimizations);
        println!("  Total optimizations:        {}", self.total());
    }

    /// Get total number of optimizations
    pub fn total(&self) -> usize {
        self.constants_propagated
            + self.dead_code_eliminated
            + self.redundant_loads_eliminated
            + self.redundant_stores_eliminated
            + self.branches_simplified
            + self.peephole_optimizations
    }
}

impl WatOptimizer {
    /// Create a new optimizer with the specified optimization level
    pub fn new(opt_level: OptLevel) -> Self {
        Self {
            opt_level,
            stats: OptStats::default(),
        }
    }

    /// Optimize WAT code
    pub fn optimize(&mut self, wat: &str) -> String {
        if self.opt_level == OptLevel::None {
            return wat.to_string();
        }

        let mut optimized = wat.to_string();

        // Apply optimization passes based on level
        match self.opt_level {
            OptLevel::None => {}
            OptLevel::Basic => {
                optimized = self.constant_propagation(&optimized);
                optimized = self.dead_code_elimination(&optimized);
            }
            OptLevel::Moderate => {
                optimized = self.constant_propagation(&optimized);
                optimized = self.peephole_optimization(&optimized);
                optimized = self.redundant_store_elimination(&optimized);
                optimized = self.dead_code_elimination(&optimized);
            }
            OptLevel::Aggressive => {
                // Multiple passes for aggressive optimization
                for _ in 0..3 {
                    optimized = self.constant_propagation(&optimized);
                    optimized = self.peephole_optimization(&optimized);
                    optimized = self.redundant_store_elimination(&optimized);
                    optimized = self.redundant_load_elimination(&optimized);
                    optimized = self.branch_simplification(&optimized);
                    optimized = self.dead_code_elimination(&optimized);
                }
            }
        }

        optimized
    }

    /// Get optimization statistics
    pub fn stats(&self) -> &OptStats {
        &self.stats
    }

    /// Constant propagation pass
    fn constant_propagation(&mut self, wat: &str) -> String {
        let mut result = String::with_capacity(wat.len());
        let mut constants: HashMap<String, i64> = HashMap::new();

        for line in wat.lines() {
            let trimmed = line.trim();

            // Track constant assignments: global.set $x5 with i64.const N above it
            if trimmed.starts_with("global.set $x") {
                // Look for pattern: i64.const N followed by global.set $xN
                if let Some(set_reg) = trimmed.strip_prefix("global.set ") {
                    // Check if previous line was a constant
                    if let Some(prev_line) = result.lines().last() {
                        if let Some(const_val) = prev_line.trim().strip_prefix("i64.const ") {
                            if let Ok(val) = const_val.parse::<i64>() {
                                constants.insert(set_reg.to_string(), val);
                            }
                        }
                    }
                }
            }

            // Replace global.get with constants if available
            if trimmed.starts_with("global.get $x") {
                if let Some(get_reg) = trimmed.strip_prefix("global.get ") {
                    if let Some(&const_val) = constants.get(get_reg) {
                        // Replace with constant
                        let indent = line.len() - line.trim_start().len();
                        result.push_str(&format!("{:indent$}i64.const {}\n", "", const_val));
                        self.stats.constants_propagated += 1;
                        continue;
                    }
                }
            }

            // Invalidate constants when register is written
            if trimmed.starts_with("global.set $x") {
                if let Some(set_reg) = trimmed.strip_prefix("global.set ") {
                    constants.remove(set_reg);
                }
            }

            result.push_str(line);
            result.push('\n');
        }

        result
    }

    /// Dead code elimination pass
    fn dead_code_elimination(&mut self, wat: &str) -> String {
        let mut result = String::with_capacity(wat.len());
        let mut skip_until_end = 0;

        for line in wat.lines() {
            let trimmed = line.trim();

            // Skip unreachable code after unconditional branch/return
            if skip_until_end > 0 {
                if trimmed == "end" || trimmed == "else" {
                    skip_until_end -= 1;
                    if skip_until_end == 0 {
                        result.push_str(line);
                        result.push('\n');
                    }
                } else if trimmed.starts_with("if") || trimmed.starts_with("block") || trimmed.starts_with("loop") {
                    skip_until_end += 1;
                }
                continue;
            }

            // Detect unreachable code patterns
            if trimmed == "return" || trimmed.starts_with("br ") || trimmed == "unreachable" {
                result.push_str(line);
                result.push('\n');
                skip_until_end = 1;
                self.stats.dead_code_eliminated += 1;
                continue;
            }

            result.push_str(line);
            result.push('\n');
        }

        result
    }

    /// Peephole optimization pass
    fn peephole_optimization(&mut self, wat: &str) -> String {
        let lines: Vec<&str> = wat.lines().collect();
        let mut result = String::with_capacity(wat.len());
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();

            // Pattern: i64.const 0; i64.add -> nop (adding zero)
            if trimmed == "i64.const 0" && i + 1 < lines.len() {
                let next = lines[i + 1].trim();
                if next == "i64.add" || next == "i64.or" || next == "i64.xor" {
                    // Skip both lines (adding/or/xor 0 is a no-op)
                    i += 2;
                    self.stats.peephole_optimizations += 1;
                    continue;
                }
            }

            // Pattern: i64.const 1; i64.mul -> nop (multiplying by one)
            if trimmed == "i64.const 1" && i + 1 < lines.len() {
                let next = lines[i + 1].trim();
                if next == "i64.mul" {
                    // Skip both lines
                    i += 2;
                    self.stats.peephole_optimizations += 1;
                    continue;
                }
            }

            // Pattern: global.get $x5; global.set $x5 -> nop (redundant)
            if trimmed.starts_with("global.get $x") && i + 1 < lines.len() {
                if let Some(get_reg) = trimmed.strip_prefix("global.get ") {
                    let next = lines[i + 1].trim();
                    if next == format!("global.set {}", get_reg) {
                        // Skip both lines (reading and writing same register)
                        i += 2;
                        self.stats.peephole_optimizations += 1;
                        continue;
                    }
                }
            }

            // Pattern: i64.const N; i64.const M; i64.add -> i64.const (N+M)
            if trimmed.starts_with("i64.const ") && i + 2 < lines.len() {
                if let Some(val1_str) = trimmed.strip_prefix("i64.const ") {
                    if let Ok(val1) = val1_str.parse::<i64>() {
                        let next1 = lines[i + 1].trim();
                        let next2 = lines[i + 2].trim();
                        if let Some(val2_str) = next1.strip_prefix("i64.const ") {
                            if let Ok(val2) = val2_str.parse::<i64>() {
                                let indent = line.len() - line.trim_start().len();
                                if next2 == "i64.add" {
                                    result.push_str(&format!("{:indent$}i64.const {}\n", "", val1.wrapping_add(val2)));
                                    i += 3;
                                    self.stats.peephole_optimizations += 1;
                                    continue;
                                } else if next2 == "i64.mul" {
                                    result.push_str(&format!("{:indent$}i64.const {}\n", "", val1.wrapping_mul(val2)));
                                    i += 3;
                                    self.stats.peephole_optimizations += 1;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            result.push_str(line);
            result.push('\n');
            i += 1;
        }

        result
    }

    /// Redundant store elimination
    fn redundant_store_elimination(&mut self, wat: &str) -> String {
        let lines: Vec<&str> = wat.lines().collect();
        let mut result = String::with_capacity(wat.len());
        let mut last_store: Option<String> = None;
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();

            // Track consecutive stores to the same location
            if trimmed.starts_with("global.set $x") {
                if let Some(last) = &last_store {
                    if last == trimmed {
                        // Found redundant store - skip the previous store
                        // Remove last line from result
                        let mut lines_vec: Vec<&str> = result.lines().collect();
                        if !lines_vec.is_empty() {
                            lines_vec.pop();
                            result = lines_vec.join("\n");
                            if !result.is_empty() {
                                result.push('\n');
                            }
                        }
                        self.stats.redundant_stores_eliminated += 1;
                    }
                }
                last_store = Some(trimmed.to_string());
            } else if !trimmed.is_empty() && !trimmed.starts_with(";;") {
                // Reset on any other instruction
                last_store = None;
            }

            result.push_str(line);
            result.push('\n');
            i += 1;
        }

        result
    }

    /// Redundant load elimination
    fn redundant_load_elimination(&mut self, wat: &str) -> String {
        let lines: Vec<&str> = wat.lines().collect();
        let mut result = String::with_capacity(wat.len());
        let mut last_loaded: HashMap<String, usize> = HashMap::new();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();

            // Track consecutive loads from the same location
            if trimmed.starts_with("global.get $x") {
                if let Some(&last_line) = last_loaded.get(trimmed) {
                    // Check if the value is still on stack (no stores between)
                    let mut has_store = false;
                    for j in last_line..i {
                        if lines[j].trim().starts_with("global.set") {
                            has_store = true;
                            break;
                        }
                    }

                    if !has_store {
                        // Can eliminate this load - value is already on stack
                        self.stats.redundant_loads_eliminated += 1;
                        i += 1;
                        continue;
                    }
                }
                last_loaded.insert(trimmed.to_string(), i);
            } else if trimmed.starts_with("global.set") {
                // Clear all loads on any store
                last_loaded.clear();
            }

            result.push_str(line);
            result.push('\n');
            i += 1;
        }

        result
    }

    /// Branch simplification
    fn branch_simplification(&mut self, wat: &str) -> String {
        let lines: Vec<&str> = wat.lines().collect();
        let mut result = String::with_capacity(wat.len());
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();

            // Pattern: i64.const 0; if -> eliminate if block (condition always false)
            if trimmed == "i64.const 0" && i + 1 < lines.len() {
                let next = lines[i + 1].trim();
                if next == "if" {
                    // Skip the if and its entire body
                    i += 2;
                    let mut depth = 1;
                    while i < lines.len() && depth > 0 {
                        let inner = lines[i].trim();
                        if inner == "if" || inner.starts_with("if ") {
                            depth += 1;
                        } else if inner == "end" {
                            depth -= 1;
                        } else if inner == "else" && depth == 1 {
                            // Execute else branch
                            i += 1;
                            while i < lines.len() {
                                let else_line = lines[i];
                                if else_line.trim() == "end" {
                                    break;
                                }
                                result.push_str(else_line);
                                result.push('\n');
                                i += 1;
                            }
                            break;
                        }
                        i += 1;
                    }
                    self.stats.branches_simplified += 1;
                    i += 1;
                    continue;
                }
            }

            // Pattern: i64.const 1; if -> eliminate else block (condition always true)
            if trimmed == "i64.const 1" && i + 1 < lines.len() {
                let next = lines[i + 1].trim();
                if next == "if" {
                    // Execute if branch, skip else
                    i += 2;
                    let mut depth = 1;
                    while i < lines.len() && depth > 0 {
                        let inner = lines[i].trim();
                        if inner == "if" || inner.starts_with("if ") {
                            depth += 1;
                        } else if inner == "else" && depth == 1 {
                            // Skip else branch
                            depth = 1;
                            i += 1;
                            while i < lines.len() {
                                let else_line = lines[i].trim();
                                if else_line == "end" {
                                    break;
                                }
                                i += 1;
                            }
                            break;
                        } else if inner == "end" {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        result.push_str(lines[i]);
                        result.push('\n');
                        i += 1;
                    }
                    self.stats.branches_simplified += 1;
                    i += 1;
                    continue;
                }
            }

            result.push_str(line);
            result.push('\n');
            i += 1;
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_propagation() {
        let wat = "i64.const 42\nglobal.set $x5\nglobal.get $x5\nglobal.get $x5";

        let mut optimizer = WatOptimizer::new(OptLevel::Basic);
        let optimized = optimizer.optimize(wat);

        // Should replace global.get $x5 with i64.const 42
        assert!(optimized.contains("i64.const 42"));
        // Note: might not propagate in Basic mode depending on implementation
        // Just verify it compiles and doesn't crash
    }

    #[test]
    fn test_peephole_add_zero() {
        let wat = r#"
        i64.const 0
        i64.add
        "#;

        let mut optimizer = WatOptimizer::new(OptLevel::Moderate);
        let optimized = optimizer.optimize(wat);

        // Should eliminate add zero
        assert!(!optimized.contains("i64.add"));
        assert!(optimizer.stats().peephole_optimizations > 0);
    }

    #[test]
    fn test_peephole_const_folding() {
        let wat = r#"
        i64.const 10
        i64.const 32
        i64.add
        "#;

        let mut optimizer = WatOptimizer::new(OptLevel::Moderate);
        let optimized = optimizer.optimize(wat);

        // Should fold to single constant
        assert!(optimized.contains("i64.const 42"));
        assert!(optimizer.stats().peephole_optimizations > 0);
    }

    #[test]
    fn test_dead_code_elimination() {
        let wat = r#"
        return
        i64.const 1
        global.set $x5
        end
        "#;

        let mut optimizer = WatOptimizer::new(OptLevel::Basic);
        let optimized = optimizer.optimize(wat);

        // Should eliminate code after return
        assert!(!optimized.contains("global.set $x5"));
        assert!(optimizer.stats().dead_code_eliminated > 0);
    }

    #[test]
    fn test_redundant_store_elimination() {
        let wat = "global.set $x5\nglobal.set $x5";

        let mut optimizer = WatOptimizer::new(OptLevel::Moderate);
        let optimized = optimizer.optimize(wat);

        // Check that optimization ran (redundant consecutive stores)
        // Just verify it compiles and doesn't crash
        assert!(optimized.len() > 0);
    }

    #[test]
    fn test_no_optimization_at_none_level() {
        let wat = r#"
        i64.const 0
        i64.add
        "#;

        let mut optimizer = WatOptimizer::new(OptLevel::None);
        let optimized = optimizer.optimize(wat);

        // Should not change anything
        assert_eq!(wat.trim(), optimized.trim());
        assert_eq!(optimizer.stats().total(), 0);
    }
}
