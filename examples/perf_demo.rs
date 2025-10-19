/// Example: Performance profiling demonstration
///
/// This demonstrates how to use the performance profiler to measure
/// all stages of the DoubleJIT VM pipeline.

use doublejit_vm::tools::perf::{Profiler, timers, counters};

fn main() {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║     DoubleJIT VM Performance Profiling Demo           ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // Create a new profiler
    let mut profiler = Profiler::new();

    // Simulate frontend: instruction decoding
    println!("1️⃣  Frontend: Decoding instructions...");
    let start = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(100));
    profiler.record_duration(timers::FRONTEND_TOTAL, start.elapsed());
    profiler.inc_counter(counters::INSTRUCTIONS_DECODED, 10000);
    profiler.inc_counter(counters::CACHE_INSTR_HITS, 8500);
    profiler.inc_counter(counters::CACHE_INSTR_MISSES, 1500);

    // Simulate middleend: WAT generation
    println!("2️⃣  Middleend: Generating WAT code...");
    let start = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(150));
    profiler.record_duration(timers::MIDDLEEND_TOTAL, start.elapsed());
    profiler.record_duration(timers::MIDDLEEND_WAT_GEN, std::time::Duration::from_millis(150));
    profiler.inc_counter(counters::INSTRUCTIONS_TRANSLATED, 10000);
    profiler.set_counter(counters::WAT_SIZE_BYTES, 2_500_000);

    // Simulate backend: WASM compilation
    println!("3️⃣  Backend: Compiling WASM to native code...");
    let start = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(200));
    profiler.record_duration(timers::BACKEND_TOTAL, start.elapsed());
    profiler.record_duration(timers::BACKEND_COMPILE, std::time::Duration::from_millis(200));
    profiler.set_counter(counters::WASM_SIZE_BYTES, 1_800_000);

    // Simulate execution
    println!("4️⃣  Execution: Running native code...");
    let start = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(50));
    profiler.record_duration(timers::EXECUTION_TOTAL, start.elapsed());
    profiler.record_duration(timers::EXECUTION_RUN, std::time::Duration::from_millis(50));
    profiler.inc_counter(counters::INSTRUCTIONS_EXECUTED, 10000);
    profiler.inc_counter(counters::SYSCALL_TOTAL, 25);
    profiler.inc_counter(counters::SYSCALL_WRITE, 15);
    profiler.inc_counter(counters::SYSCALL_EXIT, 1);

    println!("\n✅ Execution complete!\n");

    // Print the performance report
    profiler.print_report();

    // Export to CSV for further analysis
    if let Err(e) = profiler.export_csv("/tmp/doublejit_perf.csv") {
        eprintln!("Failed to export CSV: {}", e);
    } else {
        println!("📊 Performance data exported to /tmp/doublejit_perf.csv");
    }
}
