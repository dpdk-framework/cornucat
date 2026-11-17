#define _POSIX_C_SOURCE 200809L
#include "options.h"
#include "replay.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_pause.h>

#define REPLAY_BURST 256u

static volatile sig_atomic_t replay_interrupted;

static void replay_signal(int number)
{
    (void)number;
    replay_interrupted = 1;
}

struct replay_tx {
    const struct pg_options *options;
    struct pg_replay_capture capture;
    struct rte_mempool *pool;
    struct rte_mbuf *pending[REPLAY_BURST];
    /* Prefix metadata is cached before ownership passes to the PMD. */
    uint64_t byte_prefix[REPLAY_BURST + 1u];
    uint16_t udp_prefix[REPLAY_BURST + 1u];
    uint16_t tcp_prefix[REPLAY_BURST + 1u];
    uint16_t icmp_prefix[REPLAY_BURST + 1u];
    uint8_t source_mac[6];
    uint16_t pending_count, offset, descriptors;
    uint64_t hz, start, end, start_unix_ns, end_unix_ns, deadline, quota;
    uint64_t next_due, next_report, report_at, report_packets, report_bytes;
    uint64_t submitted, released, bytes, udp, tcp, icmp;
    uint64_t tx_calls, backpressure, allocation_retries, pacing_resets;
    uint64_t last_progress, allocation_since, rng, loop;
    size_t cursor;
    long double fractional_ticks;
    unsigned lcore;
    const char *reason;
    bool failed, hardware_available;
    struct rte_eth_stats hardware;
};

static uint64_t replay_unix_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > UINT64_MAX / UINT64_C(1000000000)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static bool replay_running(const struct replay_tx *tx, uint64_t now)
{
    return !replay_interrupted && !tx->failed &&
           (!tx->deadline || now < tx->deadline);
}

static void replay_report(struct replay_tx *tx, uint64_t now)
{
    if (now < tx->next_report) return;
    double seconds = (double)(now - tx->report_at) / (double)tx->hz;
    printf("TX submitted: %" PRIu64 " packets | %.3f Mpps | %.3f frame Gbps | "
           "UDP=%" PRIu64 " TCP=%" PRIu64 " ICMP=%" PRIu64 " (RX unmeasured)\n",
           tx->submitted,
           seconds > 0 ? (double)(tx->submitted - tx->report_packets) / seconds / 1e6 : 0,
           seconds > 0 ? (double)(tx->bytes - tx->report_bytes) * 8.0 / seconds / 1e9 : 0,
           tx->udp, tx->tcp, tx->icmp);
    fflush(stdout);
    tx->report_at = now;
    tx->report_packets = tx->submitted;
    tx->report_bytes = tx->bytes;
    tx->next_report = now > UINT64_MAX - tx->hz ? UINT64_MAX : now + tx->hz;
}

static bool replay_wait(struct replay_tx *tx, uint64_t target)
{
    for (;;) {
        uint64_t now = rte_get_tsc_cycles();
        if (!replay_running(tx, now)) return false;
        replay_report(tx, now);
        if (now >= target) return true;
        if (target - now > tx->hz / 5000u) {
            long double estimated_ns = (long double)(target - now) * 1e9L / tx->hz;
            uint64_t ns = estimated_ns > 1e6L ? UINT64_C(1000000) : (uint64_t)estimated_ns;
            struct timespec delay = {0, (long)ns};
            if (nanosleep(&delay, NULL) != 0 && errno != EINTR) {
                tx->failed = true;
                return false;
            }
        } else rte_pause();
    }
}

static int capture_target(struct replay_tx *tx, size_t cursor, uint64_t loop,
                           uint64_t *target)
{
    uint64_t duration = tx->capture.duration_ns;
    uint64_t timestamp = tx->capture.frames[cursor].timestamp_ns;
    if ((duration && loop > UINT64_MAX / duration) ||
        (duration * loop > UINT64_MAX - timestamp)) {
        tx->failed = true;
        fprintf(stderr, "Replay capture timing exceeds the supported clock range\n");
        return -1;
    }
    uint64_t offset_ns = duration * loop + timestamp;
    long double ticks = (long double)offset_ns * tx->hz / 1e9L;
    if (ticks >= (long double)(UINT64_MAX - tx->start)) {
        tx->failed = true;
        fprintf(stderr, "Replay capture timing exceeds the supported clock range\n");
        return -1;
    }
    *target = tx->start + (uint64_t)ticks;
    return 0;
}

static int configured_target(struct replay_tx *tx, uint64_t *target)
{
    const struct pg_options *o = tx->options;
    if (o->unlimited) { *target = 0; return 0; }
    if (o->pacing_mode == PG_PACING_SMOOTH) { *target = tx->next_due; return 0; }
    long double ticks = o->rate_mbps ?
        (long double)tx->bytes * 8.0L * tx->hz / ((long double)o->rate_mbps * 1e6L) :
        (long double)tx->submitted * tx->hz / o->pps;
    if (ticks >= (long double)(UINT64_MAX - tx->start)) {
        tx->failed = true;
        return -1;
    }
    *target = tx->start + (uint64_t)ticks;
    return 0;
}

static int charge_pacing(struct replay_tx *tx, uint64_t now,
                         uint16_t accepted, uint64_t bytes)
{
    const struct pg_options *o = tx->options;
    if (o->unlimited || o->replay_original_timing ||
        o->pacing_mode != PG_PACING_SMOOTH || !accepted) return 0;
    long double ticks = tx->fractional_ticks + (o->rate_mbps ?
        (long double)bytes * 8.0L * tx->hz / ((long double)o->rate_mbps * 1e6L) :
        (long double)accepted * tx->hz / o->pps);
    if (ticks >= (long double)UINT64_MAX) return -1;
    uint64_t whole = (uint64_t)ticks;
    tx->fractional_ticks = ticks - (long double)whole;
    if (tx->next_due < now) {
        tx->next_due = now;
        ++tx->pacing_resets;
    }
    if (whole > UINT64_MAX - tx->next_due) return -1;
    tx->next_due += whole;
    return 0;
}

static void release_pending(struct replay_tx *tx)
{
    if (tx->pending_count > tx->offset) {
        uint16_t count = (uint16_t)(tx->pending_count - tx->offset);
        rte_pktmbuf_free_bulk(tx->pending + tx->offset, count);
        tx->released += count;
    }
    tx->pending_count = tx->offset = 0;
}

/* Return 1 for a prepared batch, 0 for an allocation retry, -1 on failure. */
static int prepare_batch(struct replay_tx *tx, uint16_t burst, uint64_t now)
{
    uint64_t remaining = tx->quota - tx->submitted;
    uint16_t count = remaining < burst ? (uint16_t)remaining : burst;
    if (tx->options->replay_original_timing) {
        size_t cursor = tx->cursor;
        uint64_t loop = tx->loop;
        uint16_t due = 0;
        for (; due < count; ++due) {
            uint64_t target;
            if (capture_target(tx, cursor, loop, &target)) return -1;
            if (target > now) break;
            if (++cursor == tx->capture.count) {
                cursor = 0;
                if (loop == UINT64_MAX) { tx->failed = true; return -1; }
                ++loop;
            }
        }
        count = due;
    }
    if (!count) return 0;
    if (rte_pktmbuf_alloc_bulk(tx->pool, tx->pending, count) != 0) {
        ++tx->allocation_retries;
        (void)rte_eth_tx_done_cleanup(tx->options->port_id, 0, 0);
        if (!tx->allocation_since) tx->allocation_since = now;
        if (now - tx->allocation_since > tx->hz) {
            fprintf(stderr, "Replay allocation made no progress for one second\n");
            tx->failed = true;
            return -1;
        }
        rte_pause();
        return 0;
    }
    tx->allocation_since = 0;
    tx->pending_count = count;
    tx->offset = 0;
    tx->byte_prefix[0] = 0;
    tx->udp_prefix[0] = tx->tcp_prefix[0] = tx->icmp_prefix[0] = 0;
    for (uint16_t i = 0; i < count; ++i) {
        const struct pg_replay_frame *frame = &tx->capture.frames[tx->cursor];
        uint16_t length = (uint16_t)(frame->length < PG_REPLAY_MIN_TX_FRAME ?
                                    PG_REPLAY_MIN_TX_FRAME : frame->length);
        uint8_t *data = rte_pktmbuf_mtod(tx->pending[i], uint8_t *);
        rte_memcpy(data, frame->data, frame->length);
        if (length > frame->length) memset(data + frame->length, 0, length - frame->length);
        memcpy(data, tx->options->packet.dst_mac, 6u);
        memcpy(data + 6u, tx->source_mac, 6u);
        if (tx->options->ttl_override)
            pg_packet_set_ttl_unchecked(data, pg_stream_random_ttl(&tx->rng,
                tx->options->ttl_min, tx->options->ttl_max));
        tx->pending[i]->data_len = length;
        tx->pending[i]->pkt_len = length;
        tx->byte_prefix[i + 1u] = tx->byte_prefix[i] + length;
        tx->udp_prefix[i + 1u] = (uint16_t)(tx->udp_prefix[i] + (frame->protocol == PG_UDP));
        tx->tcp_prefix[i + 1u] = (uint16_t)(tx->tcp_prefix[i] + (frame->protocol == PG_TCP));
        tx->icmp_prefix[i + 1u] = (uint16_t)(tx->icmp_prefix[i] + (frame->protocol == PG_ICMP));
        if (++tx->cursor == tx->capture.count) {
            tx->cursor = 0;
            if (tx->loop == UINT64_MAX) {
                tx->failed = true;
                return -1;
            }
            ++tx->loop;
        }
    }
    tx->last_progress = now;
    return 1;
}

static void run_replay(struct replay_tx *tx)
{
    uint16_t burst = tx->options->burst;
    const struct pg_options *o = tx->options;
    if (!o->replay_original_timing && !o->unlimited) {
        long double pps = o->rate_mbps ?
            (long double)o->rate_mbps * 1e6L * tx->capture.count /
                ((long double)tx->capture.frame_bytes * 8.0L) : (long double)o->pps;
        uint64_t paced = pps < 10000.0L ? 1u : (uint64_t)(pps / 10000.0L);
        if (paced < burst) burst = (uint16_t)paced;
    }
    while (tx->submitted < tx->quota) {
        uint64_t now = rte_get_tsc_cycles(), target;
        if (!replay_running(tx, now)) break;
        replay_report(tx, now);
        if (o->replay_original_timing) {
            if (!tx->pending_count && capture_target(tx, tx->cursor, tx->loop, &target)) break;
            if (tx->pending_count) target = 0;
        } else if (configured_target(tx, &target)) break;
        if (!replay_wait(tx, target)) break;
        if (!tx->pending_count) {
            int result = prepare_batch(tx, burst, rte_get_tsc_cycles());
            if (result < 0) break;
            if (!result) continue;
        }
        now = rte_get_tsc_cycles();
        if (!replay_running(tx, now)) break;
        uint16_t offered = (uint16_t)(tx->pending_count - tx->offset);
        if (tx->byte_prefix[tx->pending_count] - tx->byte_prefix[tx->offset] > UINT64_MAX - tx->bytes) {
            tx->failed = true;
            break;
        }
        ++tx->tx_calls;
        uint16_t previous = tx->offset;
        uint16_t accepted = rte_eth_tx_burst(o->port_id, 0, tx->pending + previous, offered);
        tx->offset = (uint16_t)(previous + accepted);
        /* These counters use only the cached metadata, never accepted mbufs. */
        uint64_t bytes = tx->byte_prefix[tx->offset] - tx->byte_prefix[previous];
        tx->submitted += accepted;
        tx->bytes += bytes;
        tx->udp += (uint16_t)(tx->udp_prefix[tx->offset] - tx->udp_prefix[previous]);
        tx->tcp += (uint16_t)(tx->tcp_prefix[tx->offset] - tx->tcp_prefix[previous]);
        tx->icmp += (uint16_t)(tx->icmp_prefix[tx->offset] - tx->icmp_prefix[previous]);
        if (accepted) tx->last_progress = now;
        if (charge_pacing(tx, now, accepted, bytes)) { tx->failed = true; break; }
        if (accepted < offered) {
            ++tx->backpressure;
            if ((tx->backpressure & UINT64_C(255)) == 0u)
                (void)rte_eth_tx_done_cleanup(o->port_id, 0, 0);
            if (now - tx->last_progress > tx->hz) {
                fprintf(stderr, "Replay TX made no progress for one second\n");
                tx->failed = true;
                break;
            }
            if (!accepted) {
                uint64_t delay = tx->hz / UINT64_C(1000000) + 1u;
                if (delay > UINT64_MAX - now || !replay_wait(tx, now + delay)) break;
            }
        }
        if (tx->offset == tx->pending_count) tx->offset = tx->pending_count = 0;
    }
    tx->end = rte_get_tsc_cycles();
    tx->end_unix_ns = replay_unix_ns();
    tx->reason = tx->failed ? "error" : replay_interrupted ? "signal" :
        tx->submitted == tx->quota ? "count" : "duration";
    release_pending(tx);
}

static int write_statistics(FILE *json, const struct replay_tx *tx, int status)
{
    double seconds = tx->hz && tx->start && tx->end >= tx->start ?
        (double)(tx->end - tx->start) / (double)tx->hz : 0;
    int result = fprintf(json,
        "{\"schema_version\":1,\"mode\":\"replay\",\"status\":\"%s\",\"stop_reason\":\"%s\","
        "\"workers\":1,\"lcore\":%u,\"queue\":0,\"burst\":%u,\"tx_descriptors\":%u,"
        "\"submitted\":%" PRIu64 ",\"not_submitted\":%" PRIu64 ",\"frame_bytes_total\":%" PRIu64 ","
        "\"elapsed_seconds\":%.9f,\"start_unix_ns\":%" PRIu64 ",\"end_unix_ns\":%" PRIu64 ","
        "\"tx_calls\":%" PRIu64 ",\"backpressure_events\":%" PRIu64 ",\"allocation_retries\":%" PRIu64 ","
        "\"pacing_resets\":%" PRIu64 ",\"capture_packets\":%zu,\"capture_bytes\":%" PRIu64 ","
        "\"capture_frame_bytes\":%" PRIu64 ",\"capture_duration_ns\":%" PRIu64 ","
        "\"capture_protocols\":{\"udp\":%" PRIu64 ",\"tcp\":%" PRIu64 ",\"icmp\":%" PRIu64 "},"
        "\"submitted_protocols\":{\"udp\":%" PRIu64 ",\"tcp\":%" PRIu64 ",\"icmp\":%" PRIu64 "},"
        "\"requested_loops\":%" PRIu64 ",\"completed_loops\":%" PRIu64 ",\"quota\":%" PRIu64 ","
        "\"timing\":\"%s\",\"ttl_override\":%s,\"hardware_stats_available\":%s,"
        "\"hardware_opackets\":%" PRIu64 ",\"hardware_obytes\":%" PRIu64 ",\"hardware_oerrors\":%" PRIu64 "}\n",
        status ? "error" : replay_interrupted ? "interrupted" : "complete", tx->reason,
        tx->lcore, tx->options->burst, tx->descriptors, tx->submitted, tx->released, tx->bytes,
        seconds, tx->start_unix_ns, tx->end_unix_ns, tx->tx_calls, tx->backpressure,
        tx->allocation_retries, tx->pacing_resets, tx->capture.count, tx->capture.captured_bytes,
        tx->capture.frame_bytes, tx->capture.duration_ns, tx->capture.udp_packets,
        tx->capture.tcp_packets, tx->capture.icmp_packets, tx->udp, tx->tcp, tx->icmp,
        tx->options->replay_loops, tx->capture.count ? tx->submitted / tx->capture.count : 0,
        tx->quota, tx->options->replay_original_timing ? "capture" : "configured-rate",
        tx->options->ttl_override ? "true" : "false", tx->hardware_available ? "true" : "false",
        tx->hardware.opackets, tx->hardware.obytes, tx->hardware.oerrors);
    return result < 0 ? -1 : 0;
}

int pg_dpdk_replay_run(int eal_argc, char **eal_argv, const struct pg_options *o)
{
    struct replay_tx tx = {0};
    tx.options = o;
    tx.reason = "error";
    int status = -1;
    char error[256];
    FILE *json = NULL;
    bool eal = false, configured = false, start_attempted = false, safe = true;
    bool have_int = false, have_term = false;
    struct sigaction action = {0}, old_int = {0}, old_term = {0};
    if (!o || !o->replay_input || o->workers != 1u || o->burst == 0u ||
        o->burst > REPLAY_BURST || (!o->unlimited && !o->replay_original_timing &&
        !o->pps && !o->rate_mbps) || (o->ttl_override &&
        (!o->ttl_min || o->ttl_min > o->ttl_max))) {
        fprintf(stderr, "Replay requires one TX worker, a valid burst/rate, and a capture\n");
        return -1;
    }
    replay_interrupted = 0;
    if (pg_replay_load(o->replay_input, &tx.capture, error, sizeof(error)) ||
        pg_replay_validate_lab(&tx.capture, o->packet.src_ip, o->packet.dst_ip, error, sizeof(error))) {
        fprintf(stderr, "Cannot replay capture: %s\n", error);
        goto done;
    }
    if (o->replay_loops && o->replay_loops > UINT64_MAX / tx.capture.count) {
        fprintf(stderr, "Replay loop count times capture length overflows packet quota\n");
        goto done;
    }
    tx.quota = o->replay_loops ? o->replay_loops * tx.capture.count : UINT64_MAX;
    if (o->explicit_count && o->count < tx.quota) tx.quota = o->count;
    if (!tx.quota) { fprintf(stderr, "Replay packet quota must be nonzero\n"); goto done; }
    tx.rng = o->seed;
    if (o->stats_json) {
        json = fopen(o->stats_json, "wx");
        if (!json) { perror("Cannot create replay statistics"); goto done; }
    }
    if (rte_eal_init(eal_argc, eal_argv) < 0) goto done;
    eal = true;
    tx.lcore = rte_get_main_lcore();
    tx.hz = rte_get_tsc_hz();
    if (!tx.hz || tx.hz > UINT64_MAX / UINT64_C(3600000) ||
        !rte_eth_dev_is_valid_port(o->port_id)) goto done;
    struct rte_eth_dev_info device = {0};
    struct rte_ether_addr mac;
    if (rte_eth_dev_info_get(o->port_id, &device) || !device.max_tx_queues ||
        rte_eth_macaddr_get(o->port_id, &mac)) goto done;
    memcpy(tx.source_mac, mac.addr_bytes, sizeof(tx.source_mac));
    struct rte_eth_conf configuration = {0};
    if (device.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        configuration.txmode.offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    if (rte_eth_dev_configure(o->port_id, 0, 1, &configuration)) goto done;
    configured = true;
    uint16_t rx_descriptors = 128;
    tx.descriptors = o->tx_descriptors;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(o->port_id, &rx_descriptors, &tx.descriptors)) goto done;
    int socket_id = rte_eth_dev_socket_id(o->port_id);
    if (socket_id < 0) socket_id = (int)rte_socket_id();
    if (socket_id < 0) goto done;
    size_t room = RTE_PKTMBUF_HEADROOM + PG_MAX_FRAME_SIZE;
    room = (room + RTE_CACHE_LINE_SIZE - 1u) / RTE_CACHE_LINE_SIZE * RTE_CACHE_LINE_SIZE;
    tx.pool = rte_pktmbuf_pool_create("pg_replay_pool", (uint32_t)tx.descriptors + 12288u,
                                    256, 0, (uint16_t)room, socket_id);
    if (!tx.pool) goto done;
    struct rte_eth_txconf configuration_tx = device.default_txconf;
    configuration_tx.offloads = configuration.txmode.offloads;
    if (rte_eth_tx_queue_setup(o->port_id, 0, tx.descriptors,
                               (unsigned)socket_id, &configuration_tx)) goto done;
    start_attempted = true;
    if (rte_eth_dev_start(o->port_id)) goto done;
    struct rte_eth_stats before = {0}, after = {0};
    bool baseline = true;
    if (rte_eth_stats_reset(o->port_id)) baseline = rte_eth_stats_get(o->port_id, &before) == 0;
    replay_interrupted = 0;
    action.sa_handler = replay_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, &old_int)) goto done;
    have_int = true;
    if (sigaction(SIGTERM, &action, &old_term)) goto done;
    have_term = true;
    tx.start = rte_get_tsc_cycles();
    tx.start_unix_ns = replay_unix_ns();
    tx.next_due = tx.report_at = tx.start;
    if (tx.hz > UINT64_MAX - tx.start) goto done;
    tx.next_report = tx.start + tx.hz;
    if (o->duration_ms) {
        uint64_t duration_ticks = tx.hz * o->duration_ms / 1000u;
        if (duration_ticks > UINT64_MAX - tx.start) goto done;
        tx.deadline = tx.start + duration_ticks;
    }
    printf("READY replay=%zu frames loops=%" PRIu64 " quota=%" PRIu64 " lcore=%u queue=0 timing=%s\n",
           tx.capture.count, o->replay_loops, tx.quota, tx.lcore,
           o->replay_original_timing ? "capture" : "configured-rate");
    fflush(stdout);
    run_replay(&tx);
    status = tx.failed ? -1 : 0;
    if (tx.submitted) {
        uint64_t now = rte_get_tsc_cycles();
        uint64_t until = tx.hz / 5u > UINT64_MAX - now ? UINT64_MAX : now + tx.hz / 5u;
        do {
            (void)rte_eth_tx_done_cleanup(o->port_id, 0, 0);
            struct timespec delay = {0, 1000000};
            (void)nanosleep(&delay, NULL);
        } while (rte_get_tsc_cycles() < until);
    }
    tx.hardware_available = baseline && rte_eth_stats_get(o->port_id, &after) == 0;
    if (tx.hardware_available) {
        after.opackets = after.opackets >= before.opackets ? after.opackets - before.opackets : 0;
        after.obytes = after.obytes >= before.obytes ? after.obytes - before.obytes : 0;
        after.oerrors = after.oerrors >= before.oerrors ? after.oerrors - before.oerrors : 0;
        tx.hardware = after;
    }
    double seconds = (double)(tx.end - tx.start) / (double)tx.hz;
    printf("Replay TX submitted: %" PRIu64 "; not submitted: %" PRIu64 "; elapsed %.6f s; "
           "%.3f Mpps; frame data %.3f Gbps (RX unmeasured)\n",
           tx.submitted, tx.released, seconds, seconds > 0 ? (double)tx.submitted / seconds / 1e6 : 0,
           seconds > 0 ? (double)tx.bytes * 8.0 / seconds / 1e9 : 0);
done:
    release_pending(&tx);
    if (start_attempted && rte_eth_dev_stop(o->port_id)) { status = -1; safe = false; }
    if (configured && safe && rte_eth_dev_close(o->port_id)) { status = -1; safe = false; }
    if (safe && tx.pool) rte_mempool_free(tx.pool);
    if (safe && eal && rte_eal_cleanup()) status = -1;
    if (have_term) (void)sigaction(SIGTERM, &old_term, NULL);
    if (have_int) (void)sigaction(SIGINT, &old_int, NULL);
    if (json) {
        int written = write_statistics(json, &tx, status);
        int closed = fclose(json);
        if (written || closed) status = -1;
    }
    pg_replay_free(&tx.capture);
    return status;
}
