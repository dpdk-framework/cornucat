#ifndef PG_STREAMS_H
#define PG_STREAMS_H

#include "packet.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PG_MAX_STREAMS 16u
#define PG_STREAM_NAME_MAX 31u
#define PG_STREAM_LINE_MAX 1024u
#define PG_STREAM_MAX_PPS UINT64_C(1000000000)

struct pg_stream_spec {
    char name[PG_STREAM_NAME_MAX + 1u];
    enum pg_protocol protocol;
    uint64_t pps, count, seed;
    uint16_t payload_size;
    uint8_t ttl_min, ttl_max;
    bool unlimited, paused;
    bool explicit_ttl, explicit_seed;
    uint8_t tcp_flags; /* Supported raw TCP profile; zero means SYN. */
    uint32_t tcp_ack; /* ACK number; not a claim of valid connection state. */
};

enum pg_stream_command_kind {
    PG_STREAM_CMD_HELP, PG_STREAM_CMD_STATUS, PG_STREAM_CMD_PAUSE,
    PG_STREAM_CMD_RESUME, PG_STREAM_CMD_RATE, PG_STREAM_CMD_COUNT,
    PG_STREAM_CMD_TTL, PG_STREAM_CMD_ADD, PG_STREAM_CMD_REMOVE,
    PG_STREAM_CMD_STOP
};

struct pg_stream_command {
    enum pg_stream_command_kind kind;
    char name[PG_STREAM_NAME_MAX + 1u];
    union {
        struct pg_stream_spec add;
        struct { uint64_t pps; bool unlimited; } rate;
        uint64_t count;
        struct { uint8_t min, max; } ttl;
    } value;
};

/* Strict bounded CSV. Required: name, protocol, and exactly one of pps or
 * unlimited=1. Optional: count (default UINT64_MAX), payload (default 18 for UDP /
 * ICMP, 6 for TCP), ttl-min+ttl-max (default 64), seed (nonzero; deterministic name
 * hash by default), pause=0|1 (default 0), tcp-flags (canonical profile name,
 * default SYN), tcp-ack (0..UINT32_MAX, default zero; nonzero requires ACK).
 * TCP keys require protocol=tcp; they create raw headers, not established TCP
 * sessions. explicit_ttl/explicit_seed record supplied fields so callers can
 * inherit global defaults safely. Unknown/duplicate fields fail. Names
 * contain 1..31 ASCII letters, digits, '_' or '-'. No whitespace/quoting/escapes.
 * Parsing is transactional: *out is untouched on failure. error may be NULL;
 * an available error buffer is always NUL terminated. Storage must not overlap.
 */
int pg_stream_parse(const char *text, struct pg_stream_spec *out,
                    char *error, size_t error_size);

/* One ASCII command, at most 1024 bytes including an optional terminal LF/CRLF:
 * help | status | pause NAME | resume NAME | rate NAME PPS|unlimited |
 * count NAME TOTAL | ttl NAME MIN MAX | add STREAMSPEC | remove NAME | stop.
 * Count targets are lifetime accepted/submitted totals; the runtime must reject
 * totals below already accepted packets. Names/table capacity/existence and all
 * runtime state changes are validated by the owner, after successful parsing.
 * The parser neither allocates nor changes runtime state; *out is transactional.
 */
int pg_stream_command_parse(const char *text, struct pg_stream_command *out,
                            char *error, size_t error_size);

/* Fast non-cryptographic per-stream PRNG. Caller owns the non-NULL state; zero
 * state is repaired deterministically. TTL selection is inclusive and uses
 * rejection sampling to avoid modulo-range bias. Fixed TTL performs no RNG
 * work. Invalid ranges/state return 0 and leave state unchanged. No allocation,
 * system calls, global shared state, or security/randomness guarantees.
 */
uint64_t pg_stream_rng_next(uint64_t *state);
uint8_t pg_stream_random_ttl(uint64_t *state, uint8_t minimum, uint8_t maximum);

#endif
