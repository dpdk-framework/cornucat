#ifndef PG_REPLAY_H
#define PG_REPLAY_H

#include "packet.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define PG_REPLAY_MAX_INPUT_BYTES (UINT64_C(64) * 1024u * 1024u)
#define PG_REPLAY_MAX_FRAMES 100000u
#define PG_REPLAY_MIN_TX_FRAME 60u

struct pg_replay_frame {
    uint8_t *data;
    uint32_t length; /* Captured bytes; callers zero-pad to 60 bytes for TX. */
    uint64_t timestamp_ns; /* Relative to the first captured frame. */
    enum pg_protocol protocol;
};

struct pg_replay_capture {
    struct pg_replay_frame *frames;
    size_t count;
    uint64_t captured_bytes;
    uint64_t frame_bytes; /* Sum of max(frame.length, 60), excluding FCS. */
    uint64_t duration_ns;
    uint64_t udp_packets;
    uint64_t tcp_packets;
    uint64_t icmp_packets;
};

/* Classic PCAP v2.4, microsecond/nanosecond resolution, either byte order,
 * Ethernet DLT 1 only. Records must be complete, monotonic, and at most 1514
 * bytes; all frames must have valid unfragmented IPv4 and TCP/UDP/ICMP
 * checksums. A zero UDP checksum is valid for IPv4. Captured Ethernet padding
 * is preserved. IPv4 options are checked for consistent lengths. Empty files,
 * PCAPNG, unsupported link types, truncation, and malformed input fail.
 *
 * Capture must be zero-initialized or previously loaded by this API. On failure
 * it is unchanged. On success its old allocation is freed and replaced. The
 * FILE variant consumes from the current position through EOF but never owns
 * or closes the stream, and reads at most the input limit plus one byte.
 * Inputs/error/output storage must not overlap. Error may be NULL. */
int pg_replay_load(const char *path, struct pg_replay_capture *capture,
                   char *error, size_t error_size);
int pg_replay_load_file(FILE *file, struct pg_replay_capture *capture,
                        char *error, size_t error_size);

/* Explicit lab interlock: both distinct fixture addresses must be inside
 * 198.18.0.0/15, the RFC 2544 benchmark range. Every frame is revalidated and
 * must have exactly the supplied source -> destination address pair. It does
 * not rewrite IP addresses, transport fields, TTLs, or application payloads.
 * This is an address restriction, not a claim of TCP session reconstruction. */
int pg_replay_validate_lab(const struct pg_replay_capture *capture,
                           const uint8_t source_ip[4],
                           const uint8_t destination_ip[4],
                           char *error, size_t error_size);

/* Frees all allocations and resets capture to zero; accepts NULL. */
void pg_replay_free(struct pg_replay_capture *capture);

#endif
