#define _POSIX_C_SOURCE 200809L
/* Dedicated two-port vhost-user lab relay. Packet validity is checked independently by
 * the receiving guest; this program forwards bytes without rewriting them. */
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_pause.h>

#define FW_PORTS 2u
#define FW_MAX_QUEUES 8u
#define FW_BURST 256u
#define FW_POOL_SIZE 4096u
#define FW_IDLE_POLLS 256u
_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "Signal stop flag must be lock-free");

struct fw_options {
    uint16_t queues;
    uint32_t duration_s;
    uint32_t idle_sleep_us;
    bool persistent;
    const char *stats_path;
};

struct fw_direction {
    /* Accepted buffers may be freed inside tx_burst. Cache lengths before
     * handing them over, and never dereference the accepted prefix again. */
    struct rte_mbuf *buffers[FW_BURST];
    uint32_t lengths[FW_BURST];
    uint16_t offset, count;
    uint16_t max_pending;
    uint64_t received, received_bytes, accepted, accepted_bytes;
    uint64_t rx_calls, tx_calls, backpressure, zero_acceptance;
    uint64_t stall_start, stalled_ticks, max_stall_ticks;
    uint64_t released, released_bytes;
};

struct fw_queue {
    uint16_t id;
    unsigned lcore;
    uint64_t idle_sleep_calls;
    struct fw_direction directions[FW_PORTS];
} __rte_cache_aligned;

static struct fw_options options;
static struct fw_queue queues[FW_MAX_QUEUES];
static atomic_bool workers_start;
static atomic_bool workers_stop;
static atomic_bool interrupted;
static uint64_t hz, start_tsc, end_tsc;
static const char *stop_reason = "setup_failure";

static void request_stop(int signal_number)
{
    (void)signal_number;
    atomic_store_explicit(&interrupted, true, memory_order_relaxed);
}

static void usage(FILE *stream, const char *name)
{
    fprintf(stream,
        "Usage: %s [EAL options including --no-pci and two net_vhost vdevs] -- [options]\n"
        "Bidirectional relay for two dedicated lab guests using net_vhost ports.\n"
        "  --queues N       Queues on each of the two ports, 1..8 (default 1)\n"
        "                   Enable at least this many EAL lcores.\n"
        "  --duration-s N   Finite relay duration, 1..1800 (default 300)\n"
        "  --persistent     Keep the dedicated backend alive until signaled; no duration\n"
        "  --idle-us N      Sleep 0..1000 us after 256 empty polls; default 0\n"
        "  --stats-json P   Exclusively create a JSON report; required\n"
        "  --help           Display usage without initializing DPDK\n",
        name);
}

static bool number(const char *text, uint32_t maximum, uint32_t *value)
{
    if (!text || !*text) return false;
    uint32_t result = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        uint32_t digit = (uint32_t)(*p - '0');
        if (result > maximum / 10u ||
            (result == maximum / 10u && digit > maximum % 10u)) return false;
        result = result * 10u + digit;
    }
    *value = result;
    return true;
}

static int parse_options(int argc, char *const argv[])
{
    options = (struct fw_options){.queues = 1, .duration_s = 300};
    unsigned seen = 0;
    for (int i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) return 1;
        const char *key = argv[i];
        if (!strcmp(key, "--persistent")) {
            if (seen & 8u) { fprintf(stderr, "Duplicate relay option: %s\n", key); return -1; }
            seen |= 8u;
            options.persistent = true;
            continue;
        }
        if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", key); return -1; }
        const char *value = argv[i];
        unsigned flag;
        uint32_t parsed;
        if (!strcmp(key, "--queues")) {
            flag = 1u;
            if (!number(value, FW_MAX_QUEUES, &parsed) || !parsed) goto invalid;
            options.queues = (uint16_t)parsed;
        } else if (!strcmp(key, "--duration-s")) {
            flag = 2u;
            if (!number(value, 1800u, &parsed) || !parsed) goto invalid;
            options.duration_s = parsed;
        } else if (!strcmp(key, "--stats-json")) {
            flag = 4u;
            if (!*value) goto invalid;
            options.stats_path = value;
        } else if (!strcmp(key, "--idle-us")) {
            flag = 16u;
            if (!number(value, 1000u, &parsed)) goto invalid;
            options.idle_sleep_us = parsed;
        } else { fprintf(stderr, "Unknown relay option: %s\n", key); return -1; }
        if (seen & flag) { fprintf(stderr, "Duplicate relay option: %s\n", key); return -1; }
        seen |= flag;
        continue;
invalid:
        fprintf(stderr, "Invalid value for %s\n", key);
        return -1;
    }
    if (options.persistent && (seen & 2u)) {
        fprintf(stderr, "Choose --persistent or --duration-s, not both\n"); return -1;
    }
    if (options.persistent) options.duration_s = 0;
    if (!options.stats_path) { fprintf(stderr, "Explicit --stats-json is required\n"); return -1; }
    return 0;
}

static uint64_t realtime_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) || now.tv_sec < 0) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static void finish_stall(struct fw_direction *direction, uint64_t now)
{
    if (!direction->stall_start) return;
    uint64_t ticks = now >= direction->stall_start ? now - direction->stall_start : 0;
    direction->stalled_ticks += ticks;
    if (ticks > direction->max_stall_ticks) direction->max_stall_ticks = ticks;
    direction->stall_start = 0;
}

/* No application drop under backpressure: retain the unaccepted suffix and
 * do not dequeue another burst from this source until it has been accepted. */
static bool forward_direction(struct fw_queue *queue, uint16_t source)
{
    struct fw_direction *direction = &queue->directions[source];
    uint16_t destination = (uint16_t)(1u - source);
    if (!direction->count) {
        ++direction->rx_calls;
        uint16_t received = rte_eth_rx_burst(source, queue->id, direction->buffers, FW_BURST);
        if (!received) return false;
        direction->count = received;
        direction->offset = 0;
        direction->received += received;
        if (received > direction->max_pending) direction->max_pending = received;
        uint64_t bytes = 0;
        for (uint16_t i = 0; i < received; ++i) {
            direction->lengths[i] = rte_pktmbuf_pkt_len(direction->buffers[i]);
            bytes += direction->lengths[i];
        }
        direction->received_bytes += bytes;
    }
    uint16_t remaining = (uint16_t)(direction->count - direction->offset);
    ++direction->tx_calls;
    uint16_t accepted = rte_eth_tx_burst(destination, queue->id,
        direction->buffers + direction->offset, remaining);
    uint64_t bytes = 0;
    for (uint16_t i = 0; i < accepted; ++i) bytes += direction->lengths[direction->offset + i];
    direction->accepted += accepted;
    direction->accepted_bytes += bytes;
    direction->offset = (uint16_t)(direction->offset + accepted);
    if (accepted < remaining) {
        ++direction->backpressure;
        if (!accepted) ++direction->zero_acceptance;
        if (!direction->stall_start) direction->stall_start = rte_get_timer_cycles();
    } else {
        if (direction->stall_start) finish_stall(direction, rte_get_timer_cycles());
        direction->count = 0;
        direction->offset = 0;
    }
    return accepted != 0;
}

static void coordinator_check(void)
{
    if (atomic_load_explicit(&interrupted, memory_order_relaxed)) stop_reason = "signal";
    else if (!options.persistent &&
             rte_get_timer_cycles() - start_tsc >= hz * options.duration_s) stop_reason = "duration";
    else return;
    atomic_store_explicit(&workers_stop, true, memory_order_relaxed);
}

static int forward_queue(void *argument)
{
    struct fw_queue *queue = argument;
    queue->lcore = rte_lcore_id();
    const uint32_t idle_sleep_us = options.idle_sleep_us;
    while (!atomic_load_explicit(&workers_start, memory_order_acquire) &&
           !atomic_load_explicit(&workers_stop, memory_order_relaxed)) rte_pause();
    unsigned polls = 0, empty_polls = 0;
    while (!atomic_load_explicit(&workers_stop, memory_order_relaxed)) {
        bool progress = forward_direction(queue, 0);
        progress = forward_direction(queue, 1) || progress;
        if (!progress) {
            rte_pause();
            /* Sleep only after sustained empty RX polling. A stalled suffix
             * remains owned by this worker and must keep being retried. */
            if (idle_sleep_us && !queue->directions[0].count &&
                !queue->directions[1].count) {
                if (++empty_polls == FW_IDLE_POLLS) {
                    struct timespec delay = {0, (long)idle_sleep_us * 1000L};
                    (void)nanosleep(&delay, NULL);
                    ++queue->idle_sleep_calls;
                    empty_polls = 0;
                }
            } else empty_polls = 0;
        } else empty_polls = 0;
        if (queue->id == 0u && (++polls & 1023u) == 0u) coordinator_check();
    }
    return 0;
}

static uint64_t difference(uint64_t after, uint64_t before)
{
    return after >= before ? after - before : 0;
}

static double seconds(uint64_t ticks)
{
    return hz ? (double)ticks / (double)hz : 0.0;
}

static int write_report(FILE *report, int status, uint64_t unix_start, uint64_t unix_end,
                        const struct rte_eth_stats before[FW_PORTS],
                        const struct rte_eth_stats after[FW_PORTS],
                        const int baseline_result[FW_PORTS], const int stats_result[FW_PORTS])
{
    uint64_t received = 0, accepted = 0, released = 0;
    bool accounting_ok = true;
    for (uint16_t q = 0; q < options.queues; ++q) {
        for (uint16_t p = 0; p < FW_PORTS; ++p) {
            const struct fw_direction *direction = &queues[q].directions[p];
            received += direction->received;
            accepted += direction->accepted;
            released += direction->released;
            if (direction->received != direction->accepted + direction->released ||
                direction->received_bytes != direction->accepted_bytes + direction->released_bytes)
                accounting_ok = false;
        }
    }
    fprintf(report,
        "{\n  \"schema_version\": 1,\n  \"status\": \"%s\",\n  \"stop_reason\": \"%s\",\n"
        "  \"queue_count\": %u,\n  \"duration_limit_s\": %" PRIu32 ",\n"
        "  \"persistent\": %s,\n  \"idle_sleep_us\": %" PRIu32 ",\n"
        "  \"idle_sleep_after_empty_polls\": %u,\n"
        "  \"duration_seconds\": %.9f,\n  \"start_unix_ns\": %" PRIu64 ",\n"
        "  \"end_unix_ns\": %" PRIu64 ",\n  \"received_packets\": %" PRIu64 ",\n"
        "  \"accepted_packets\": %" PRIu64 ",\n  \"released_on_exit_packets\": %" PRIu64 ",\n"
        "  \"accounting_ok\": %s,\n  \"burst_limit\": %u,\n  \"ports\": [\n",
        status || !accounting_ok ? "failure" : (!strcmp(stop_reason, "signal") ? "interrupted" : "success"),
        stop_reason, (unsigned)options.queues, options.duration_s,
        options.persistent ? "true" : "false", options.idle_sleep_us, FW_IDLE_POLLS,
        seconds(difference(end_tsc, start_tsc)), unix_start, unix_end,
        received, accepted, released, accounting_ok ? "true" : "false", FW_BURST);
    for (uint16_t p = 0; p < FW_PORTS; ++p) {
        bool available = baseline_result[p] == 0 && stats_result[p] == 0;
        fprintf(report,
            "    {\"port_id\": %u, \"hardware_stats_available\": %s, \"baseline_result\": %d, \"stats_result\": %d,"
            " \"ipackets\": %" PRIu64 ", \"opackets\": %" PRIu64 ", \"ibytes\": %" PRIu64
            ", \"obytes\": %" PRIu64 ", \"imissed\": %" PRIu64 ", \"ierrors\": %" PRIu64
            ", \"oerrors\": %" PRIu64 ", \"rx_nombuf\": %" PRIu64 "}%s\n",
            (unsigned)p, available ? "true" : "false", baseline_result[p], stats_result[p],
            available ? difference(after[p].ipackets, before[p].ipackets) : 0,
            available ? difference(after[p].opackets, before[p].opackets) : 0,
            available ? difference(after[p].ibytes, before[p].ibytes) : 0,
            available ? difference(after[p].obytes, before[p].obytes) : 0,
            available ? difference(after[p].imissed, before[p].imissed) : 0,
            available ? difference(after[p].ierrors, before[p].ierrors) : 0,
            available ? difference(after[p].oerrors, before[p].oerrors) : 0,
            available ? difference(after[p].rx_nombuf, before[p].rx_nombuf) : 0,
            p + 1u < FW_PORTS ? "," : "");
    }
    fputs("  ],\n  \"queues\": [\n", report);
    for (uint16_t q = 0; q < options.queues; ++q) {
        fprintf(report, "    {\"queue_id\": %u, \"lcore_id\": %u, \"idle_sleep_calls\": %" PRIu64
                ", \"directions\": [\n", (unsigned)q, queues[q].lcore, queues[q].idle_sleep_calls);
        for (uint16_t p = 0; p < FW_PORTS; ++p) {
            const struct fw_direction *direction = &queues[q].directions[p];
            fprintf(report,
                "      {\"source_port\": %u, \"destination_port\": %u, \"received_packets\": %" PRIu64
                ", \"received_bytes\": %" PRIu64 ", \"accepted_packets\": %" PRIu64
                ", \"accepted_bytes\": %" PRIu64 ", \"released_on_exit_packets\": %" PRIu64
                ", \"released_on_exit_bytes\": %" PRIu64 ", \"rx_calls\": %" PRIu64
                ", \"tx_calls\": %" PRIu64 ", \"backpressure_events\": %" PRIu64
                ", \"zero_acceptance_calls\": %" PRIu64 ", \"max_pending_packets\": %u"
                ", \"stalled_seconds\": %.9f, \"maximum_stall_seconds\": %.9f}%s\n",
                (unsigned)p, (unsigned)(1u - p), direction->received, direction->received_bytes,
                direction->accepted, direction->accepted_bytes, direction->released,
                direction->released_bytes, direction->rx_calls, direction->tx_calls,
                direction->backpressure, direction->zero_acceptance, (unsigned)direction->max_pending,
                seconds(direction->stalled_ticks), seconds(direction->max_stall_ticks),
                p + 1u < FW_PORTS ? "," : "");
        }
        fprintf(report, "    ]}%s\n", q + 1u < options.queues ? "," : "");
    }
    fputs("  ],\n  \"note\": \"Receive counts describe packets dequeued from one guest; accepted counts describe ownership transferred to the peer guest's vhost PMD, not independently confirmed endpoint reception. Unaccepted packets are retained during forwarding and only released at finite shutdown. Duration includes guest connection wait; endpoint receiver reports determine delivered throughput.\"\n}\n", report);
    return ferror(report) || !accounting_ok ? -1 : 0;
}

int main(int argc, char **argv)
{
    int separator = -1;
    bool no_pci = false;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--")) { separator = i; break; }
        if (!strcmp(argv[i], "--no-pci")) no_pci = true;
    }
    int first = separator < 0 ? 1 : separator + 1;
    int parsed = parse_options(argc - first, argv + first);
    if (parsed == 1) { usage(stdout, argv[0]); return EXIT_SUCCESS; }
    if (parsed < 0 || separator < 0 || !no_pci) {
        if (separator < 0 || !no_pci) fprintf(stderr, "Explicit --no-pci and EAL/options separator -- are required\n");
        usage(stderr, argv[0]); return EXIT_FAILURE;
    }
    int fd = open(options.stats_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { perror("Cannot create relay JSON report"); return EXIT_FAILURE; }
    FILE *report = fdopen(fd, "w");
    if (!report) { perror("Cannot open relay report stream"); (void)close(fd); return EXIT_FAILURE; }
    int status = -1;
    bool eal_started = false, safe_teardown = true;
    bool configured[FW_PORTS] = {false}, start_attempted[FW_PORTS] = {false};
    bool can_close[FW_PORTS] = {true, true};
    bool int_handler = false, term_handler = false;
    struct sigaction action = {0}, old_int = {0}, old_term = {0};
    struct rte_mempool *pools[FW_PORTS][FW_MAX_QUEUES] = {{0}};
    struct rte_eth_stats hw_before[FW_PORTS] = {{0}}, hw_after[FW_PORTS] = {{0}};
    int baseline_result[FW_PORTS] = {-1, -1}, stats_result[FW_PORTS] = {-1, -1};
    unsigned launched[FW_MAX_QUEUES] = {0}, launch_count = 0;
    uint64_t unix_start = 0, unix_end = 0;
    atomic_init(&workers_start, false);
    atomic_init(&workers_stop, false);
    atomic_init(&interrupted, false);
    for (uint16_t q = 0; q < options.queues; ++q) queues[q].id = q;
    if (rte_eal_init(separator + 1, argv) < 0) {
        fprintf(stderr, "Relay EAL initialization failed: %s\n", rte_strerror(rte_errno)); goto done;
    }
    eal_started = true;
    hz = rte_get_timer_hz();
    if (!hz || hz > UINT64_MAX / UINT64_C(1800)) { fprintf(stderr, "Unsupported relay timer frequency\n"); goto done; }
    if (rte_lcore_count() < options.queues) { fprintf(stderr, "Provide an EAL lcore for each forwarding queue\n"); goto done; }
    if (rte_eth_dev_count_avail() != FW_PORTS || !rte_eth_dev_is_valid_port(0) || !rte_eth_dev_is_valid_port(1)) {
        fprintf(stderr, "Exactly two vhost PMD ports (0 and 1) are required\n"); goto done;
    }
    unsigned socket = rte_socket_id();
    if (socket > INT_MAX) { fprintf(stderr, "Invalid relay EAL socket ID\n"); goto done; }
    for (uint16_t p = 0; p < FW_PORTS; ++p) {
        struct rte_eth_dev_info info = {0};
        int result = rte_eth_dev_info_get(p, &info);
        if (result || !info.driver_name || strcmp(info.driver_name, "net_vhost") ||
            info.max_rx_queues < options.queues || info.max_tx_queues < options.queues) {
            fprintf(stderr, "Relay ports must be net_vhost PMDs supporting the requested queues\n"); goto done;
        }
        struct rte_eth_conf configuration = {0};
        result = rte_eth_dev_configure(p, options.queues, options.queues, &configuration);
        if (result) { fprintf(stderr, "Relay port %u configuration failed: %d\n", (unsigned)p, result); goto done; }
        configured[p] = true;
        uint16_t rx_desc = 1024, tx_desc = 1024;
        result = rte_eth_dev_adjust_nb_rx_tx_desc(p, &rx_desc, &tx_desc);
        if (result) { fprintf(stderr, "Relay descriptor adjustment failed: %d\n", result); goto done; }
        struct rte_eth_rxconf rx_configuration = info.default_rxconf;
        struct rte_eth_txconf tx_configuration = info.default_txconf;
        rx_configuration.offloads = 0;
        tx_configuration.offloads = 0;
        for (uint16_t q = 0; q < options.queues; ++q) {
            char name[48];
            (void)snprintf(name, sizeof(name), "pg_relay_pool_%u_%u", (unsigned)p, (unsigned)q);
            pools[p][q] = rte_pktmbuf_pool_create(name, FW_POOL_SIZE, 256, 0,
                                                RTE_MBUF_DEFAULT_BUF_SIZE, (int)socket);
            if (!pools[p][q]) { fprintf(stderr, "Relay pool creation failed: %s\n", rte_strerror(rte_errno)); goto done; }
            result = rte_eth_rx_queue_setup(p, q, rx_desc, socket, &rx_configuration, pools[p][q]);
            if (result) { fprintf(stderr, "Relay RX setup failed: %d\n", result); goto done; }
            result = rte_eth_tx_queue_setup(p, q, tx_desc, socket, &tx_configuration);
            if (result) { fprintf(stderr, "Relay TX setup failed: %d\n", result); goto done; }
        }
        start_attempted[p] = true;
        result = rte_eth_dev_start(p);
        if (result) { fprintf(stderr, "Relay port %u start failed: %d\n", (unsigned)p, result); goto done; }
        baseline_result[p] = rte_eth_stats_get(p, &hw_before[p]);
    }
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, &old_int)) { perror("Relay SIGINT handler"); goto done; }
    int_handler = true;
    if (sigaction(SIGTERM, &action, &old_term)) { perror("Relay SIGTERM handler"); goto done; }
    term_handler = true;
    uint16_t q = 1;
    for (unsigned lcore = rte_get_next_lcore(UINT_MAX, 1, 0); lcore < RTE_MAX_LCORE;
         lcore = rte_get_next_lcore(lcore, 1, 0)) {
        if (q >= options.queues) break;
        int result = rte_eal_remote_launch(forward_queue, &queues[q], lcore);
        if (result) { fprintf(stderr, "Relay worker launch failed: %d\n", result); goto done; }
        launched[launch_count++] = lcore;
        ++q;
    }
    if (q != options.queues) { fprintf(stderr, "Relay queue assignment failed\n"); goto done; }
    puts("READY relay configured; two vhost sockets await dedicated lab guests");
    fflush(stdout);
    unix_start = realtime_ns();
    start_tsc = rte_get_timer_cycles();
    stop_reason = "running";
    atomic_store_explicit(&workers_start, true, memory_order_release);
    (void)forward_queue(&queues[0]);
    status = 0;
done:
    atomic_store_explicit(&workers_stop, true, memory_order_relaxed);
    for (unsigned i = 0; i < launch_count; ++i)
        if (rte_eal_wait_lcore(launched[i])) status = -1;
    if (start_tsc) { end_tsc = rte_get_timer_cycles(); unix_end = realtime_ns(); }
    for (uint16_t q_index = 0; q_index < options.queues; ++q_index) {
        for (uint16_t p = 0; p < FW_PORTS; ++p) {
            struct fw_direction *direction = &queues[q_index].directions[p];
            if (direction->stall_start) finish_stall(direction, rte_get_timer_cycles());
            if (direction->count > direction->offset) {
                uint16_t pending = (uint16_t)(direction->count - direction->offset);
                direction->released += pending;
                for (uint16_t i = direction->offset; i < direction->count; ++i)
                    direction->released_bytes += direction->lengths[i];
                rte_pktmbuf_free_bulk(direction->buffers + direction->offset, pending);
                direction->count = 0;
                direction->offset = 0;
            }
        }
    }
    for (uint16_t p = 0; p < FW_PORTS; ++p) {
        if (start_attempted[p]) {
            stats_result[p] = rte_eth_stats_get(p, &hw_after[p]);
            if (rte_eth_dev_stop(p)) {
                fprintf(stderr, "Relay stop failed; retaining driver-owned pools\n");
                can_close[p] = false;
                safe_teardown = false;
                status = -1;
            }
        }
    }
    /* A failed stop must not be followed by a close of that active port.
     * Close other ports, retaining all pools unless all teardown is safe. */
    for (uint16_t p = 0; p < FW_PORTS; ++p) {
        if (configured[p] && can_close[p] && rte_eth_dev_close(p)) {
            fprintf(stderr, "Relay close failed; retaining driver-owned pools\n"); safe_teardown = false; status = -1;
        }
    }
    if (safe_teardown) {
        for (uint16_t p = 0; p < FW_PORTS; ++p)
            for (uint16_t q_index = 0; q_index < options.queues; ++q_index)
                if (pools[p][q_index]) rte_mempool_free(pools[p][q_index]);
        if (eal_started && rte_eal_cleanup()) { fprintf(stderr, "Relay EAL cleanup failed\n"); status = -1; }
    }
    if (term_handler) (void)sigaction(SIGTERM, &old_term, NULL);
    if (int_handler) (void)sigaction(SIGINT, &old_int, NULL);
    if (write_report(report, status, unix_start, unix_end, hw_before, hw_after,
                     baseline_result, stats_result)) status = -1;
    if (fclose(report)) { perror("Cannot finish relay report"); status = -1; }
    return status ? EXIT_FAILURE : EXIT_SUCCESS;
}
