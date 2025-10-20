/// Example: WAT optimizer and register mapping demonstration
///
/// Shows how to use the optimizer and register mapping tools
/// in the compilation pipeline.

use doublejit_vm::codegen::optimizer::{WatOptimizer, OptLevel};
use doublejit_vm::codegen::regmap::{RegisterMap, RegisterStats, abi};

fn main() {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║       WAT Optimizer & Register Map Demo               ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // Demo 1: Register Mapping
    demo_register_mapping();

    // Demo 2: WAT Optimization
    demo_wat_optimization();
}

fn demo_register_mapping() {
    println!("1️⃣  Register Mapping Demo\n");

    let mut regmap = RegisterMap::new();
    let mut stats = RegisterStats::new();

    // Simulate some register usage
    println!("   Simulating register operations:");

    // Read a0 (function argument)
    regmap.mark_read(abi::A0);
    stats.record_read(abi::A0);
    println!("   - Read  {} ({})", regmap.get_global_name(abi::A0).unwrap(), abi::get_abi_name(abi::A0));

    // Write to t0 (temporary)
    regmap.mark_written(abi::T0);
    stats.record_write(abi::T0);
    println!("   - Write {} ({})", regmap.get_global_name(abi::T0).unwrap(), abi::get_abi_name(abi::T0));

    // Multiple reads from sp (stack pointer)
    for _ in 0..5 {
        regmap.mark_read(abi::SP);
        stats.record_read(abi::SP);
    }
    println!("   - Read  {} ({}) 5 times", regmap.get_global_name(abi::SP).unwrap(), abi::get_abi_name(abi::SP));

    // Check for dead stores
    regmap.mark_written(abi::T1);
    stats.record_write(abi::T1);
    println!("   - Write {} ({}) [never read - dead store!]", regmap.get_global_name(abi::T1).unwrap(), abi::get_abi_name(abi::T1));

    let dead_stores = regmap.get_dead_stores();
    println!("\n   Dead stores detected: {} registers", dead_stores.len());
    for reg in dead_stores {
        println!("      x{} ({})", reg, abi::get_abi_name(reg));
    }

    stats.update_pressure(regmap.live_count());
    println!("\n   Register pressure: {} live registers", regmap.live_count());

    println!("\n   ABI Information:");
    println!("      a0 is caller-saved: {}", abi::is_caller_saved(abi::A0));
    println!("      s0 is callee-saved: {}", abi::is_callee_saved(abi::S0_FP));

    println!();
}

fn demo_wat_optimization() {
    println!("2️⃣  WAT Optimization Demo\n");

    // Example unoptimized WAT code
    let unoptimized_wat = r#"
    ;; Unoptimized WAT code with redundancies
    i64.const 10
    i64.const 32
    i64.add
    global.set $x5

    global.get $x5
    i64.const 0
    i64.add
    global.set $x6

    i64.const 1
    i64.mul
    global.set $x7

    ;; Dead code after return
    return
    i64.const 99
    global.set $x8
    end
    "#;

    println!("   Original WAT size: {} bytes\n", unoptimized_wat.len());

    // Test different optimization levels
    for &opt_level in &[OptLevel::None, OptLevel::Basic, OptLevel::Moderate, OptLevel::Aggressive] {
        let mut optimizer = WatOptimizer::new(opt_level);
        let optimized = optimizer.optimize(unoptimized_wat);

        println!("   Optimization Level: {:?}", opt_level);
        println!("      Optimized size:         {} bytes", optimized.len());
        println!("      Size reduction:         {:.1}%",
            (1.0 - optimized.len() as f64 / unoptimized_wat.len() as f64) * 100.0);

        let stats = optimizer.stats();
        if stats.total() > 0 {
            println!("      Optimizations applied:");
            if stats.constants_propagated > 0 {
                println!("        - Constants propagated:  {}", stats.constants_propagated);
            }
            if stats.peephole_optimizations > 0 {
                println!("        - Peephole optimizations: {}", stats.peephole_optimizations);
            }
            if stats.dead_code_eliminated > 0 {
                println!("        - Dead code eliminated:  {}", stats.dead_code_eliminated);
            }
            if stats.redundant_stores_eliminated > 0 {
                println!("        - Redundant stores removed: {}", stats.redundant_stores_eliminated);
            }
            if stats.redundant_loads_eliminated > 0 {
                println!("        - Redundant loads removed: {}", stats.redundant_loads_eliminated);
            }
            if stats.branches_simplified > 0 {
                println!("        - Branches simplified:   {}", stats.branches_simplified);
            }
            println!("      Total optimizations:    {}", stats.total());
        }
        println!();
    }

    // Show specific optimization examples
    println!("   Specific Optimization Examples:\n");

    // Constant folding
    let const_fold = "i64.const 10\ni64.const 32\ni64.add";
    let mut optimizer = WatOptimizer::new(OptLevel::Moderate);
    let optimized = optimizer.optimize(const_fold);
    println!("   Constant Folding:");
    println!("      Before: {}", const_fold.replace('\n', "; "));
    println!("      After:  {}", optimized.trim().replace('\n', "; "));
    println!("      ✅ Folded to: i64.const 42\n");

    // Add zero elimination
    let add_zero = "i64.const 0\ni64.add";
    let mut optimizer = WatOptimizer::new(OptLevel::Moderate);
    let optimized = optimizer.optimize(add_zero);
    println!("   Add Zero Elimination:");
    println!("      Before: {}", add_zero.replace('\n', "; "));
    println!("      After:  {}", if optimized.trim().is_empty() { "(eliminated)" } else { optimized.trim() });
    println!("      ✅ No-op eliminated\n");

    // Dead code elimination
    let dead_code = "return\ni64.const 1\nglobal.set $x5\nend";
    let mut optimizer = WatOptimizer::new(OptLevel::Basic);
    let optimized = optimizer.optimize(dead_code);
    println!("   Dead Code Elimination:");
    println!("      Before: {}", dead_code.replace('\n', "; "));
    println!("      After:  {}", optimized.trim().replace('\n', "; "));
    println!("      ✅ Unreachable code eliminated\n");

    println!("✅ Optimization demo complete!");
}
