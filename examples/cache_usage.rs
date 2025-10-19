/// Example: How to use the frontend code cache
///
/// This demonstrates the three-level caching system:
/// 1. Instruction cache
/// 2. Basic block cache
/// 3. WAT code cache

use doublejit_vm::frontend::cache::{BasicBlock, CodeCache};
use doublejit_vm::frontend::instruction::Instruction;

fn main() {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║         Frontend Code Cache Usage Example             ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // Create a new code cache with limits
    // - Max 1000 instructions
    // - Max 100 basic blocks
    let mut cache = CodeCache::with_limits(1000, 100);

    println!("1️⃣  Instruction Cache Example\n");

    // Example 1: Cache individual instructions
    let nop_bytes = [0x13, 0x00, 0x00, 0x00]; // ADDI x0, x0, 0 (NOP)
    let nop = Instruction::parse(&nop_bytes);

    let pc = 0x80000000;
    cache.cache_instruction(pc, nop.clone());

    // Retrieve from cache
    match cache.get_instruction(pc) {
        Some(_instr) => println!("   ✅ Instruction found in cache at PC 0x{:x}", pc),
        None => println!("   ❌ Cache miss at PC 0x{:x}", pc),
    }

    println!("\n2️⃣  Basic Block Cache Example\n");

    // Example 2: Cache a basic block
    let block = BasicBlock {
        start_addr: 0x80000000,
        end_addr: 0x8000000C,
        instructions: vec![
            (0x80000000, nop.clone()),
            (0x80000004, nop.clone()),
            (0x80000008, nop.clone()),
            (0x8000000C, nop.clone()),
        ],
        wat_code: None,
    };

    cache.cache_block(block);

    // Retrieve basic block
    match cache.get_block(0x80000000) {
        Some(block) => {
            println!("   ✅ Basic block found:");
            println!("      Range: 0x{:x} - 0x{:x}", block.start_addr, block.end_addr);
            println!("      Instructions: {}", block.instructions.len());
        }
        None => println!("   ❌ Block not found"),
    }

    println!("\n3️⃣  WAT Code Cache Example\n");

    // Example 3: Cache generated WAT code
    let wat_code = r#"
    ;; Basic block WAT code
    global.get $pc
    i64.const 4
    i64.add
    global.set $pc
    "#.to_string();

    cache.cache_wat_code(0x80000000, wat_code);

    match cache.get_wat_code(0x80000000) {
        Some(wat) => {
            println!("   ✅ WAT code found:");
            println!("      {} bytes", wat.len());
        }
        None => println!("   ❌ WAT code not found"),
    }

    println!("\n4️⃣  Cache Statistics\n");

    // Add more cache accesses to generate statistics
    for i in 0..10 {
        let addr = 0x80000000 + i * 4;
        cache.get_instruction(addr); // Most will be misses
    }

    // Print statistics
    cache.stats().print();

    println!("\n5️⃣  Cache Management\n");

    println!("   Cache contents:");
    println!("      Instructions: {}", cache.instruction_count());
    println!("      Basic blocks: {}", cache.block_count());
    println!("      WAT entries:  {}", cache.wat_count());

    // Invalidate a range (e.g., for self-modifying code)
    println!("\n   Invalidating range 0x80000000-0x80000008...");
    cache.invalidate_range(0x80000000, 0x80000008);

    println!("   After invalidation:");
    println!("      Instructions: {}", cache.instruction_count());
    println!("      Basic blocks: {}", cache.block_count());

    // Clear all caches
    println!("\n   Clearing all caches...");
    cache.clear();

    println!("   After clearing:");
    println!("      Instructions: {}", cache.instruction_count());
    println!("      Basic blocks: {}", cache.block_count());
    println!("      WAT entries:  {}", cache.wat_count());

    println!("\n✅ Cache usage example complete!");
}
