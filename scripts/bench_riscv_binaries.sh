#!/usr/bin/env bash
set -u
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${RUNNER:-$ROOT_DIR/target/release/examples/doublejit-runner}"
RESULT_DIR="${RESULT_DIR:-$ROOT_DIR/bench-results}"
RUNS="${RUNS:-1}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-65536}"
CSV="$RESULT_DIR/riscv-binaries.csv"
SUMMARY="$RESULT_DIR/riscv-binaries.md"
LOG_DIR="$RESULT_DIR/logs"

mkdir -p "$LOG_DIR"

if [[ ! -x "$RUNNER" ]]; then
  cargo build --release --example doublejit-runner --manifest-path "$ROOT_DIR/Cargo.toml"
fi

mapfile -t BINARIES < <(
  find "$ROOT_DIR/test_binaries" -type f -perm -111 -print \
    | while IFS= read -r path; do
        if file "$path" | grep -q "UCB RISC-V"; then
          printf '%s\n' "$path"
        fi
      done \
    | sort
)

{
  printf 'binary,run,status,process_status,program_exit,wall_ms,instructions,log\n'
} > "$CSV"

{
  printf '# RISC-V Binary Benchmarks\n\n'
  printf '%s\n' "- runner: \`$RUNNER\`"
  printf '%s\n' "- runs per binary: \`$RUNS\`"
  printf '%s\n\n' "- timeout seconds: \`$TIMEOUT_SECONDS\`"
  printf '%s\n\n' "- max log bytes: \`$MAX_LOG_BYTES\`"
  printf '| Binary | Run | Status | Program Exit | Wall ms | Instructions | Log |\n'
  printf '| --- | ---: | --- | ---: | ---: | ---: | --- |\n'
} > "$SUMMARY"

for binary in "${BINARIES[@]}"; do
  rel="${binary#$ROOT_DIR/}"
  safe_name="${rel//\//__}"
  safe_name="${safe_name//[^A-Za-z0-9_.-]/_}"

  for run in $(seq 1 "$RUNS"); do
    log="$LOG_DIR/${safe_name}.run${run}.log"
    start_ns="$(date +%s%N)"
    timeout "$TIMEOUT_SECONDS" "$RUNNER" "$binary" >"$log" 2>&1
    process_status="$?"
    end_ns="$(date +%s%N)"
    wall_ms="$(((end_ns - start_ns) / 1000000))"

    if [[ "$MAX_LOG_BYTES" -gt 0 ]]; then
      log_size="$(wc -c < "$log")"
      if [[ "$log_size" -gt "$MAX_LOG_BYTES" ]]; then
        tmp_log="$log.tmp"
        half_log_bytes="$((MAX_LOG_BYTES / 2))"
        {
          printf '%s\n' "--- log truncated from $log_size bytes to $MAX_LOG_BYTES bytes ---"
          printf '%s\n' "--- first $half_log_bytes bytes ---"
          head -c "$half_log_bytes" "$log"
          printf '\n%s\n' "--- last $half_log_bytes bytes ---"
          tail -c "$half_log_bytes" "$log"
        } > "$tmp_log"
        mv "$tmp_log" "$log"
      fi
    fi

    if [[ "$process_status" -eq 124 ]]; then
      status="timeout"
    elif [[ "$process_status" -eq 0 ]]; then
      status="ok"
    else
      status="fail"
    fi

    program_exit="$(sed -n 's/^Exit code: //p' "$log" | tail -n 1)"
    [[ -n "$program_exit" ]] || program_exit="NA"

    instructions="$(
      sed -n 's/^.*DEBUG: Executed \([0-9][0-9]*\) instructions.*$/\1/p' "$log" \
        | tail -n 1
    )"
    [[ -n "$instructions" ]] || instructions="NA"

    log_rel="${log#$ROOT_DIR/}"
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$rel" "$run" "$status" "$process_status" "$program_exit" "$wall_ms" "$instructions" "$log_rel" \
      >> "$CSV"

    {
      printf '| `%s` | %s | %s | %s | %s | %s | `%s` |\n' \
        "$rel" "$run" "$status" "$program_exit" "$wall_ms" "$instructions" "$log_rel"
    } >> "$SUMMARY"

    printf '%-55s run=%s status=%s wall_ms=%s instructions=%s\n' \
      "$rel" "$run" "$status" "$wall_ms" "$instructions"
  done
done

printf '\nWrote %s\nWrote %s\n' "$CSV" "$SUMMARY"
