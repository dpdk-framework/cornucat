#ifndef PG_OPTIONS_H
#define PG_OPTIONS_H

#include "packet.h"
#include "streams.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum pg_mode { PG_MODE_PCAP, PG_MODE_DPDK };
enum pg_template_mode { PG_TEMPLATE_SEQUENCE, PG_TEMPLATE_STATIC };
enum pg_pacing_mode { PG_PACING_SMOOTH, PG_PACING_CATCH_UP };
struct pg_options {
    struct pg_packet_config packet;
    enum pg_mode mode;
    const char *output;
    uint64_t count;
    uint64_t pps;
    uint64_t rate_mbps;
    uint32_t duration_ms;
    uint16_t workers;
    uint16_t burst;
    uint16_t flows;
    uint16_t tx_descriptors;
    enum pg_template_mode template_mode;
    enum pg_pacing_mode pacing_mode;
    const char *stats_json;
    bool unlimited;
    uint16_t port_id;
    bool explicit_src_ip, explicit_dst_ip, explicit_dst_mac, explicit_port;
    struct pg_stream_spec streams[PG_MAX_STREAMS];
    uint16_t stream_count;
    const char *control_socket;
    uint8_t ttl_min, ttl_max;
    uint64_t seed;
    bool explicit_seed;
    const char *replay_input;
    uint64_t replay_loops;
    bool replay_original_timing, explicit_count, ttl_override;
};

void pg_options_default(struct pg_options *options);
/* argv contains only application options, with no program name or EAL arguments. */
int pg_options_parse(int argc, char *const argv[], struct pg_options *options,
                     char *error, size_t error_size);
bool pg_is_lab_ip(const uint8_t ip[4]);
void pg_usage(FILE *stream, const char *program);
int pg_write_pcap(const struct pg_options *options);
#ifdef PG_HAVE_DPDK
int pg_dpdk_run(int eal_argc, char **eal_argv, const struct pg_options *options);
int pg_dpdk_stream_run(int eal_argc, char **eal_argv, const struct pg_options *options);
int pg_dpdk_replay_run(int eal_argc, char **eal_argv, const struct pg_options *options);
#endif
#endif
