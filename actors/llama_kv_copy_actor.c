/*
 * A portable I/O-path actor modeled after llama.cpp KV-cache page movement.
 *
 * The actor moves one 4 KiB KV page per request, updates an 8 KiB control
 * state, and checks three cache-line sentinels. It deliberately excludes the
 * transformer matmul path: ReFlux classifies that as compute-intensive and
 * non-migratable, while KV-cache movement is an I/O-path actor.
 */

#include <stdint.h>

#ifndef LLAMA_KV_PAGE_BYTES
#define LLAMA_KV_PAGE_BYTES 4096
#endif

#ifndef LLAMA_KV_ACTOR_ROUNDS
#define LLAMA_KV_ACTOR_ROUNDS 2048
#endif

#define LLAMA_KV_WORDS (LLAMA_KV_PAGE_BYTES / sizeof(uint64_t))
#define LLAMA_KV_CONTROL_BYTES 8192

struct llama_kv_actor_state {
    uint64_t sequence;
    uint64_t checksum;
    uint8_t control[LLAMA_KV_CONTROL_BYTES];
};

static uint64_t kv_source[LLAMA_KV_WORDS] = {
    [0] = UINT64_C(0x0badf00ddeadbeef),
    [LLAMA_KV_WORDS / 2] = UINT64_C(0x0123456789abcdef),
    [LLAMA_KV_WORDS - 1] = UINT64_C(0xfedcba9876543210),
};
static uint64_t kv_destination[LLAMA_KV_WORDS];
static struct llama_kv_actor_state actor_state;

static inline void actor_copy_page(uint64_t *destination, const uint64_t *source) {
#if defined(__x86_64__)
    uint64_t *out = destination;
    const uint64_t *in = source;
    unsigned long words = LLAMA_KV_WORDS;
    __asm__ volatile("rep movsq"
                     : "+D"(out), "+S"(in), "+c"(words)
                     :
                     : "memory");
#else
    for (unsigned long index = 0; index < LLAMA_KV_WORDS; ++index) {
        destination[index] = source[index];
    }
#endif
}

int main(void) {
    for (unsigned long round = 0; round < LLAMA_KV_ACTOR_ROUNDS; ++round) {
        actor_copy_page(kv_destination, kv_source);
        actor_state.sequence += 1;
        actor_state.control[(round * 17) & (LLAMA_KV_CONTROL_BYTES - 1)] =
            (uint8_t) actor_state.sequence;
    }

    actor_state.checksum = kv_destination[0] ^
                           kv_destination[LLAMA_KV_WORDS / 2] ^
                           kv_destination[LLAMA_KV_WORDS - 1] ^
                           actor_state.sequence;

    if (kv_destination[0] != UINT64_C(0x0badf00ddeadbeef) ||
        kv_destination[LLAMA_KV_WORDS / 2] != UINT64_C(0x0123456789abcdef) ||
        kv_destination[LLAMA_KV_WORDS - 1] != UINT64_C(0xfedcba9876543210)) {
        return 1;
    }
    return actor_state.sequence % LLAMA_KV_ACTOR_ROUNDS == 0 ? 0 : 2;
}
