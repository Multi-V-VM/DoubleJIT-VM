use crate::frontend::instruction::Instruction;
use std::collections::HashMap;

/// A basic block represents a sequence of instructions with a single entry and exit point
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Start address of the basic block
    pub start_addr: u64,
    /// End address (inclusive) of the basic block
    pub end_addr: u64,
    /// Decoded instructions in this block
    pub instructions: Vec<(u64, Instruction)>,
    /// Generated WAT code for this block (optional)
    pub wat_code: Option<String>,
}

/// Statistics for cache performance monitoring
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    /// Number of instruction cache hits
    pub instruction_hits: u64,
    /// Number of instruction cache misses
    pub instruction_misses: u64,
    /// Number of basic block cache hits
    pub block_hits: u64,
    /// Number of basic block cache misses
    pub block_misses: u64,
    /// Number of WAT code cache hits
    pub wat_hits: u64,
    /// Number of WAT code cache misses
    pub wat_misses: u64,
}

impl CacheStats {
    /// Calculate instruction cache hit rate (0.0 to 1.0)
    pub fn instruction_hit_rate(&self) -> f64 {
        let total = self.instruction_hits + self.instruction_misses;
        if total == 0 {
            0.0
        } else {
            self.instruction_hits as f64 / total as f64
        }
    }

    /// Calculate basic block cache hit rate (0.0 to 1.0)
    pub fn block_hit_rate(&self) -> f64 {
        let total = self.block_hits + self.block_misses;
        if total == 0 {
            0.0
        } else {
            self.block_hits as f64 / total as f64
        }
    }

    /// Calculate WAT code cache hit rate (0.0 to 1.0)
    pub fn wat_hit_rate(&self) -> f64 {
        let total = self.wat_hits + self.wat_misses;
        if total == 0 {
            0.0
        } else {
            self.wat_hits as f64 / total as f64
        }
    }

    /// Print cache statistics
    pub fn print(&self) {
        println!("╔════════════════════════════════════════════════════════╗");
        println!("║            Frontend Code Cache Statistics             ║");
        println!("╠════════════════════════════════════════════════════════╣");
        println!("║ Instruction Cache:                                     ║");
        println!("║   Hits:   {:>10}   Misses: {:>10}              ║",
                 self.instruction_hits, self.instruction_misses);
        println!("║   Hit Rate: {:.2}%                                      ║",
                 self.instruction_hit_rate() * 100.0);
        println!("║                                                        ║");
        println!("║ Basic Block Cache:                                     ║");
        println!("║   Hits:   {:>10}   Misses: {:>10}              ║",
                 self.block_hits, self.block_misses);
        println!("║   Hit Rate: {:.2}%                                      ║",
                 self.block_hit_rate() * 100.0);
        println!("║                                                        ║");
        println!("║ WAT Code Cache:                                        ║");
        println!("║   Hits:   {:>10}   Misses: {:>10}              ║",
                 self.wat_hits, self.wat_misses);
        println!("║   Hit Rate: {:.2}%                                      ║",
                 self.wat_hit_rate() * 100.0);
        println!("╚════════════════════════════════════════════════════════╝");
    }
}

/// Frontend code cache for RISC-V JIT compilation
///
/// This cache stores:
/// 1. Decoded RISC-V instructions
/// 2. Basic blocks (sequences of instructions)
/// 3. Generated WAT code for blocks
///
/// The cache improves performance by avoiding redundant decoding and code generation
pub struct CodeCache {
    /// Cache for individual decoded instructions (PC -> Instruction)
    instruction_cache: HashMap<u64, Instruction>,

    /// Cache for basic blocks (start PC -> BasicBlock)
    block_cache: HashMap<u64, BasicBlock>,

    /// Cache for generated WAT code (block start PC -> WAT string)
    wat_cache: HashMap<u64, String>,

    /// Cache statistics
    stats: CacheStats,

    /// Maximum number of instructions to cache (0 = unlimited)
    max_instructions: usize,

    /// Maximum number of basic blocks to cache (0 = unlimited)
    max_blocks: usize,
}

impl CodeCache {
    /// Create a new empty code cache with default limits
    pub fn new() -> Self {
        Self::with_limits(0, 0) // 0 = unlimited
    }

    /// Create a new code cache with specified size limits
    ///
    /// # Arguments
    /// * `max_instructions` - Maximum instructions to cache (0 = unlimited)
    /// * `max_blocks` - Maximum basic blocks to cache (0 = unlimited)
    pub fn with_limits(max_instructions: usize, max_blocks: usize) -> Self {
        CodeCache {
            instruction_cache: HashMap::new(),
            block_cache: HashMap::new(),
            wat_cache: HashMap::new(),
            stats: CacheStats::default(),
            max_instructions,
            max_blocks,
        }
    }

    // ========================================================================
    // Instruction Cache API
    // ========================================================================

    /// Get a cached instruction at the given PC
    ///
    /// Returns Some(instruction) if found in cache, None otherwise
    pub fn get_instruction(&mut self, pc: u64) -> Option<&Instruction> {
        if let Some(instr) = self.instruction_cache.get(&pc) {
            self.stats.instruction_hits += 1;
            Some(instr)
        } else {
            self.stats.instruction_misses += 1;
            None
        }
    }

    /// Cache a decoded instruction at the given PC
    pub fn cache_instruction(&mut self, pc: u64, instruction: Instruction) {
        // Check size limit
        if self.max_instructions > 0 && self.instruction_cache.len() >= self.max_instructions {
            // Simple eviction: clear entire cache when full
            // TODO: Implement LRU or other eviction policy
            self.instruction_cache.clear();
        }

        self.instruction_cache.insert(pc, instruction);
    }

    // ========================================================================
    // Basic Block Cache API
    // ========================================================================

    /// Get a cached basic block starting at the given PC
    ///
    /// Returns Some(block) if found in cache, None otherwise
    pub fn get_block(&mut self, start_pc: u64) -> Option<&BasicBlock> {
        if let Some(block) = self.block_cache.get(&start_pc) {
            self.stats.block_hits += 1;
            Some(block)
        } else {
            self.stats.block_misses += 1;
            None
        }
    }

    /// Cache a basic block
    pub fn cache_block(&mut self, block: BasicBlock) {
        // Check size limit
        if self.max_blocks > 0 && self.block_cache.len() >= self.max_blocks {
            // Simple eviction: clear entire cache when full
            // TODO: Implement LRU or other eviction policy
            self.block_cache.clear();
            self.wat_cache.clear(); // Clear WAT cache too since it's linked
        }

        let start_addr = block.start_addr;
        self.block_cache.insert(start_addr, block);
    }

    // ========================================================================
    // WAT Code Cache API
    // ========================================================================

    /// Get cached WAT code for a block starting at the given PC
    ///
    /// Returns Some(wat_code) if found in cache, None otherwise
    pub fn get_wat_code(&mut self, start_pc: u64) -> Option<&String> {
        if let Some(wat) = self.wat_cache.get(&start_pc) {
            self.stats.wat_hits += 1;
            Some(wat)
        } else {
            self.stats.wat_misses += 1;
            None
        }
    }

    /// Cache WAT code for a block
    pub fn cache_wat_code(&mut self, start_pc: u64, wat_code: String) {
        self.wat_cache.insert(start_pc, wat_code);
    }

    // ========================================================================
    // Cache Management
    // ========================================================================

    /// Clear all caches
    pub fn clear(&mut self) {
        self.instruction_cache.clear();
        self.block_cache.clear();
        self.wat_cache.clear();
        self.stats = CacheStats::default();
    }

    /// Get cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get mutable cache statistics
    pub fn stats_mut(&mut self) -> &mut CacheStats {
        &mut self.stats
    }

    /// Get number of cached instructions
    pub fn instruction_count(&self) -> usize {
        self.instruction_cache.len()
    }

    /// Get number of cached basic blocks
    pub fn block_count(&self) -> usize {
        self.block_cache.len()
    }

    /// Get number of cached WAT code entries
    pub fn wat_count(&self) -> usize {
        self.wat_cache.len()
    }

    /// Invalidate cache entries in a given address range
    ///
    /// This is useful when code is modified (self-modifying code)
    pub fn invalidate_range(&mut self, start_addr: u64, end_addr: u64) {
        // Remove instructions in range
        self.instruction_cache.retain(|&pc, _| pc < start_addr || pc > end_addr);

        // Remove blocks that overlap with range
        self.block_cache.retain(|_, block| {
            block.end_addr < start_addr || block.start_addr > end_addr
        });

        // Remove WAT code for invalidated blocks
        self.wat_cache.retain(|&pc, _| {
            if let Some(block) = self.block_cache.get(&pc) {
                block.end_addr < start_addr || block.start_addr > end_addr
            } else {
                false // Block was removed, remove WAT too
            }
        });
    }
}

impl Default for CodeCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::instruction::Instruction;

    #[test]
    fn test_instruction_cache() {
        let mut cache = CodeCache::new();

        // Parse a NOP instruction (ADDI x0, x0, 0)
        let nop = Instruction::parse(&[0x13, 0x00, 0x00, 0x00]);

        // Cache it
        cache.cache_instruction(0x1000, nop.clone());

        // Retrieve it
        let cached = cache.get_instruction(0x1000);
        assert!(cached.is_some());

        // Check stats
        assert_eq!(cache.stats().instruction_hits, 1);
        assert_eq!(cache.stats().instruction_misses, 0);

        // Try to get non-cached instruction
        let not_cached = cache.get_instruction(0x2000);
        assert!(not_cached.is_none());
        assert_eq!(cache.stats().instruction_misses, 1);
    }

    #[test]
    fn test_cache_limits() {
        let mut cache = CodeCache::with_limits(2, 2);

        let nop = Instruction::parse(&[0x13, 0x00, 0x00, 0x00]);

        // Add 3 instructions (exceeds limit of 2)
        cache.cache_instruction(0x1000, nop.clone());
        cache.cache_instruction(0x1004, nop.clone());
        assert_eq!(cache.instruction_count(), 2);

        cache.cache_instruction(0x1008, nop.clone());
        // Cache should be cleared when limit exceeded
        assert_eq!(cache.instruction_count(), 1);
    }

    #[test]
    fn test_invalidate_range() {
        let mut cache = CodeCache::new();

        let nop = Instruction::parse(&[0x13, 0x00, 0x00, 0x00]);

        // Cache instructions at different addresses
        cache.cache_instruction(0x1000, nop.clone());
        cache.cache_instruction(0x1004, nop.clone());
        cache.cache_instruction(0x1008, nop.clone());
        cache.cache_instruction(0x2000, nop.clone());

        assert_eq!(cache.instruction_count(), 4);

        // Invalidate range 0x1000-0x1008
        cache.invalidate_range(0x1000, 0x1008);

        // Only 0x2000 should remain
        assert_eq!(cache.instruction_count(), 1);
        assert!(cache.get_instruction(0x2000).is_some());
        assert!(cache.get_instruction(0x1000).is_none());
    }
}
