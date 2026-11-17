/* Read-only PCAP analysis and wizard preflight; no EAL or NIC initialization. */
#include "options.h"
#include "replay.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

enum { ICMP_VALUES = 256, ETHERNET_HEADER_BYTES = 14 };

static const char *icmp_name(unsigned type)
{
    switch (type) {
    case 0: return "Echo Reply";
    case 3: return "Destination Unreachable";
    case 5: return "Redirect";
    case 8: return "Echo Request";
    case 11: return "Time Exceeded";
    case 12: return "Parameter Problem";
    default: return "Unknown";
    }
}

static void print_counts(const struct pg_replay_capture *capture)
{
    printf("{\"packets\":%zu,\"captured_bytes\":%" PRIu64 ",\"frame_bytes\":%" PRIu64
           ",\"duration_ns\":%" PRIu64 ",\"udp\":%" PRIu64 ",\"tcp\":%" PRIu64
           ",\"icmp\":%" PRIu64, capture->count, capture->captured_bytes,
           capture->frame_bytes, capture->duration_ns, capture->udp_packets,
           capture->tcp_packets, capture->icmp_packets);
}

static int print_analysis(const struct pg_replay_capture *capture, bool require_udp_checksum)
{
    /* Limit the histogram to the two 8-bit fields. Allocate only for ICMP captures. */
    uint32_t (*icmp)[ICMP_VALUES] = NULL;
    if (capture->icmp_packets != 0u) {
        icmp = calloc(ICMP_VALUES, sizeof(*icmp));
        if (icmp == NULL) {
            fputs("cannot allocate ICMP type/code counts\n", stderr);
            return EXIT_FAILURE;
        }
    }
    uint64_t udp_omitted = 0;
    for (size_t i = 0; i < capture->count; ++i) {
        const struct pg_replay_frame *frame = &capture->frames[i];
        /* The loader already checked Ethernet type, IHL, and transport lengths
         * and rejected invalid checksums. It allows omitted IPv4 UDP checksums. */
        const uint8_t *ip = frame->data + ETHERNET_HEADER_BYTES;
        const uint8_t *transport = ip + (size_t)(ip[0] & 15u) * 4u;
        if (frame->protocol == PG_UDP && transport[6] == 0u && transport[7] == 0u)
            ++udp_omitted;
        else if (frame->protocol == PG_ICMP)
            ++icmp[transport[0]][transport[1]];
    }

    print_counts(capture);
    printf(",\"checksums\":{\"ipv4_verified\":%zu,\"udp_verified\":%" PRIu64
           ",\"udp_omitted\":%" PRIu64 ",\"tcp_verified\":%" PRIu64
           ",\"icmp_verified\":%" PRIu64 "},\"icmp_type_codes\":[",
           capture->count, capture->udp_packets - udp_omitted, udp_omitted,
           capture->tcp_packets, capture->icmp_packets);
    bool first = true;
    if (icmp != NULL) {
        for (unsigned type = 0; type < ICMP_VALUES; ++type) {
            for (unsigned code = 0; code < ICMP_VALUES; ++code) {
                uint32_t count = icmp[type][code];
                if (count == 0u) continue;
                printf("%s{\"type\":%u,\"code\":%u,\"name\":\"%s\",\"packets\":%" PRIu32 "}",
                       first ? "" : ",", type, code, icmp_name(type), count);
                first = false;
            }
        }
    }
    fputs("]}\n", stdout);
    free(icmp);
    if (require_udp_checksum && udp_omitted != 0u) {
        fputs("capture contains IPv4 UDP packets with omitted checksums\n", stderr);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static void usage(FILE *out)
{
    fputs("Usage: inspect-pcap --capture-only [--require-udp-checksum] PATH\n"
          "       inspect-pcap PATH SOURCE-IP DESTINATION-IP\n", out);
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--help")) {
        usage(stdout);
        return EXIT_SUCCESS;
    }
    bool analyze = argc >= 2 && !strcmp(argv[1], "--capture-only");
    bool strict = analyze && argc == 4 && !strcmp(argv[2], "--require-udp-checksum");
    if ((analyze && ((!strict && argc != 3) || !strcmp(argv[argc - 1], "--require-udp-checksum"))) ||
        (!analyze && argc != 4)) {
        usage(stderr);
        return EXIT_FAILURE;
    }

    struct pg_options options;
    struct pg_replay_capture capture = {0};
    char error[256];
    if (!analyze) {
        char *addresses[] = {"--src-ip", argv[2], "--dst-ip", argv[3]};
        pg_options_default(&options);
        if (pg_options_parse(4, addresses, &options, error, sizeof(error))) {
            fprintf(stderr, "%s\n", error);
            return EXIT_FAILURE;
        }
    }
    const char *path = analyze ? argv[strict ? 3 : 2] : argv[1];
    if (pg_replay_load(path, &capture, error, sizeof(error)) ||
        (!analyze && pg_replay_validate_lab(&capture, options.packet.src_ip,
                                            options.packet.dst_ip, error, sizeof(error)))) {
        fprintf(stderr, "%s\n", error);
        pg_replay_free(&capture);
        return EXIT_FAILURE;
    }
    int status = EXIT_SUCCESS;
    if (analyze) {
        status = print_analysis(&capture, strict);
    } else {
        print_counts(&capture);
        fputs("}\n", stdout);
    }
    pg_replay_free(&capture);
    return fflush(stdout) == EOF || ferror(stdout) ? EXIT_FAILURE : status;
}
