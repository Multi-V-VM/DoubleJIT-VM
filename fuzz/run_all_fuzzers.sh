#!/bin/bash
# Run all fuzzing targets for DoubleJIT VM
# Usage: ./run_all_fuzzers.sh [duration_in_seconds]

set -e

DURATION=${1:-3600}  # Default: 1 hour
WORKERS=$(nproc)     # Use all available cores

echo "════════════════════════════════════════════════════════════"
echo "  DoubleJIT VM Fuzzing Suite"
echo "════════════════════════════════════════════════════════════"
echo "Duration: ${DURATION}s per target"
echo "Workers: ${WORKERS}"
echo "════════════════════════════════════════════════════════════"
echo ""

# Check if cargo-fuzz is installed
if ! command -v cargo-fuzz &> /dev/null; then
    echo "❌ cargo-fuzz not found. Installing..."
    cargo install cargo-fuzz
fi

# Create output directory
RESULTS_DIR="fuzz/results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Array of fuzzing targets
TARGETS=("asm" "vector_instructions" "instruction_stream")

echo "Starting fuzzing campaigns..."
echo ""

# Function to run a single fuzzer
run_fuzzer() {
    local target=$1
    local log_file="${RESULTS_DIR}/${target}.log"

    echo "▶ Starting fuzzer: $target"

    cargo fuzz run "$target" -- \
        -max_total_time="$DURATION" \
        -workers="$WORKERS" \
        -print_final_stats=1 \
        2>&1 | tee "$log_file" &

    echo "  └─ PID: $! | Log: $log_file"
}

# Run all fuzzers in parallel
for target in "${TARGETS[@]}"; do
    run_fuzzer "$target"
    sleep 1  # Stagger starts
done

echo ""
echo "All fuzzers started. Waiting for completion..."
echo "Monitor progress with: tail -f ${RESULTS_DIR}/*.log"
echo ""

# Wait for all background jobs
wait

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Fuzzing Complete!"
echo "════════════════════════════════════════════════════════════"
echo ""

# Check for crashes
echo "📊 Results Summary:"
echo ""

for target in "${TARGETS[@]}"; do
    artifact_dir="fuzz/artifacts/$target"
    if [ -d "$artifact_dir" ] && [ "$(ls -A $artifact_dir 2>/dev/null)" ]; then
        crash_count=$(find "$artifact_dir" -type f | wc -l)
        echo "⚠️  $target: $crash_count crash(es) found"
        ls -lh "$artifact_dir"
    else
        echo "✅ $target: No crashes found"
    fi
    echo ""
done

# Generate coverage report if requested
if [ "$2" == "--coverage" ]; then
    echo "Generating coverage reports..."
    for target in "${TARGETS[@]}"; do
        echo "  ▶ Coverage for $target..."
        cargo fuzz coverage "$target" 2>&1 | tee "${RESULTS_DIR}/${target}_coverage.log"
    done
fi

echo "Results saved to: $RESULTS_DIR"
echo ""
echo "To reproduce crashes:"
echo "  cargo fuzz run <target> fuzz/artifacts/<target>/crash-<id>"
echo ""
echo "To minimize crashes:"
echo "  cargo fuzz tmin <target> fuzz/artifacts/<target>/crash-<id>"
echo ""
