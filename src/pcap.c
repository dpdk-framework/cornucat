#include "options.h"
#include <errno.h>
#include <inttypes.h>
#include <string.h>

static void little16(uint8_t *p, uint16_t value)
{ p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8); }
static void little32(uint8_t *p, uint32_t value)
{ for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (8 * i)); }

int pg_write_pcap(const struct pg_options *o)
{
    FILE *file = fopen(o->output, "wbx");
    if (!file) { fprintf(stderr, "Cannot create '%s': %s\n", o->output, strerror(errno)); return -1; }
    uint8_t header[24] = {0};
    little32(header, UINT32_C(0xa1b2c3d4)); little16(header + 4, 2); little16(header + 6, 4);
    little32(header + 16, PG_MAX_FRAME_SIZE); little32(header + 20, 1); /* Ethernet */
    int status = -1;
    uint64_t rng = o->seed;
    if (fwrite(header, 1, sizeof(header), file) != sizeof(header)) goto done;
    for (uint64_t i = 0; i < o->count; ++i) {
        uint8_t frame[PG_MAX_FRAME_SIZE], record[16];
        size_t length = 0;
        char error[128];
        if (pg_packet_build(&o->packet, (uint32_t)i, frame, sizeof(frame), &length, error, sizeof(error))) {
            fprintf(stderr, "Packet construction failed: %s\n", error); goto done;
        }
        /* Synthetic deterministic timestamps; these are fixtures, not measured timing. */
        if (o->ttl_min != o->ttl_max)
            pg_packet_set_ttl_unchecked(frame, pg_stream_random_ttl(&rng, o->ttl_min, o->ttl_max));
        uint64_t microseconds = (uint64_t)i * UINT64_C(1000000) / o->pps;
        little32(record, (uint32_t)(microseconds / UINT64_C(1000000)));
        little32(record + 4, (uint32_t)(microseconds % UINT64_C(1000000)));
        little32(record + 8, (uint32_t)length); little32(record + 12, (uint32_t)length);
        if (fwrite(record, 1, sizeof(record), file) != sizeof(record)
            || fwrite(frame, 1, length, file) != length) goto done;
    }
    status = 0;
done:
    if (fclose(file)) status = -1;
    if (status) fprintf(stderr, "PCAP output failed; '%s' may contain an incomplete capture\n", o->output);
    else printf("Wrote %" PRIu64 " packets to %s (no network transmission)\n", o->count, o->output);
    return status;
}
