#define _POSIX_C_SOURCE 200809L
#include "options.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_pause.h>

#define PG_MAX_WORKERS 16u
#define PG_MAX_BURST 256u
_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "Signal stop flag must be lock-free");
static atomic_bool stopped;
static atomic_bool ready;
static void stop_requested(int number)
{ (void)number; atomic_store_explicit(&stopped, true, memory_order_relaxed); }

struct pg_tx_worker {
    const struct pg_options *options;
    const struct pg_packet_template **flow_order;
    struct rte_mempool *pool;
    uint16_t port, queue;
    uint16_t frame_length, flow_period, flow_cursor, flow_mask;
    uint16_t tx_ring_descriptors;
    uint32_t sequence;
    bool masked_flows, tx_queue_info_available, prefilled_static_enabled;
    uint32_t prefilled_static_objects;
    uint64_t quota, rate, start, deadline, hz;
    uint64_t submitted, released, tx_calls, backpressure, allocation_retries;
    uint64_t pacing_resets;
    uint64_t end;
    int failed;
} __rte_cache_aligned;

static void prefill_static_object(struct rte_mempool *pool, void *argument,
                                  void *object, unsigned int index)
{
    const struct pg_tx_worker *w = argument;
    struct rte_mbuf *buffer = object;
    (void)pool; (void)index;
    rte_memcpy(rte_pktmbuf_mtod(buffer, uint8_t *),
               w->flow_order[0]->frame, w->frame_length);
}

/* Each pool produces fresh, direct, single-segment mbufs. Frame length and
 * data-room capacity are checked once when creating the pool, so the hot loop
 * can set length fields directly without append bounds checks per packet. */
static uint16_t build_static(struct pg_tx_worker *w, struct rte_mbuf **buffers,
                             uint16_t size)
{
    uint16_t cursor = w->flow_cursor;
    if (w->prefilled_static_enabled) {
        /* Allocation still obtains exclusive fresh mbuf ownership. Only
         * immutable packet bytes are cached; no in-flight mbuf is reused. */
        for (uint16_t i = 0; i < size; ++i) {
            buffers[i]->data_len = w->frame_length;
            buffers[i]->pkt_len = w->frame_length;
        }
    } else if (w->flow_period == 1) {
        const uint8_t *frame = w->flow_order[0]->frame;
        for (uint16_t i = 0; i < size; ++i) {
            rte_memcpy(rte_pktmbuf_mtod(buffers[i], uint8_t *), frame, w->frame_length);
            buffers[i]->data_len = w->frame_length;
            buffers[i]->pkt_len = w->frame_length;
        }
    } else if (w->masked_flows) {
        for (uint16_t i = 0; i < size; ++i) {
            rte_memcpy(rte_pktmbuf_mtod(buffers[i], uint8_t *),
                       w->flow_order[cursor]->frame, w->frame_length);
            buffers[i]->data_len = w->frame_length;
            buffers[i]->pkt_len = w->frame_length;
            cursor = (uint16_t)((cursor + 1u) & w->flow_mask);
        }
    } else {
        for (uint16_t i = 0; i < size; ++i) {
            rte_memcpy(rte_pktmbuf_mtod(buffers[i], uint8_t *),
                       w->flow_order[cursor]->frame, w->frame_length);
            buffers[i]->data_len = w->frame_length;
            buffers[i]->pkt_len = w->frame_length;
            if (++cursor == w->flow_period) cursor = 0;
        }
    }
    w->flow_cursor = cursor;
    return size;
}

static uint16_t build_sequence(struct pg_tx_worker *w, struct rte_mbuf **buffers,
                               uint16_t size)
{
    uint16_t cursor = w->flow_cursor;
    uint16_t built = 0;
    if (w->masked_flows) {
        for (; built < size; ++built) {
            if (pg_packet_template_write(w->flow_order[cursor], w->sequence,
                                         rte_pktmbuf_mtod(buffers[built], uint8_t *),
                                         w->frame_length)) break;
            buffers[built]->data_len = w->frame_length;
            buffers[built]->pkt_len = w->frame_length;
            cursor = (uint16_t)((cursor + 1u) & w->flow_mask);
            w->sequence += w->options->workers;
        }
    } else {
        for (; built < size; ++built) {
            if (pg_packet_template_write(w->flow_order[cursor], w->sequence,
                                         rte_pktmbuf_mtod(buffers[built], uint8_t *),
                                         w->frame_length)) break;
            buffers[built]->data_len = w->frame_length;
            buffers[built]->pkt_len = w->frame_length;
            if (++cursor == w->flow_period) cursor = 0;
            w->sequence += w->options->workers;
        }
    }
    w->flow_cursor = cursor;
    return built;
}

static bool running_at(const struct pg_tx_worker *w, uint64_t now)
{
    return !atomic_load_explicit(&stopped, memory_order_relaxed) &&
           (!w->deadline || now < w->deadline);
}

static bool running(const struct pg_tx_worker *w)
{
    return running_at(w, rte_get_tsc_cycles());
}

/* At high rates a worker polls the TSC; long waits sleep in bounded pieces. */
static bool wait_until(const struct pg_tx_worker *w, uint64_t target)
{
    for (;;) {
        uint64_t now = rte_get_tsc_cycles();
        if (!running_at(w, now)) return false;
        if (now >= target) return true;
        uint64_t ticks = target - now;
        if (ticks > w->hz / UINT64_C(5000)) {
            uint64_t ns = (uint64_t)((double)ticks * 1e9 / (double)w->hz);
            if (ns > UINT64_C(10000000)) ns = UINT64_C(10000000);
            if (ns > UINT64_C(50000)) ns -= UINT64_C(50000);
            struct timespec delay = {0, (long)ns};
            while (nanosleep(&delay, &delay) && errno == EINTR && running(w)) {}
        } else rte_pause();
    }
}

static int transmit(void *argument)
{
    struct pg_tx_worker *w = argument;
    const struct pg_options *o = w->options;
    struct rte_mbuf *buffers[PG_MAX_BURST];
    uint64_t last_progress = 0, next_burst = 0;
    double smooth_ticks = 0;
    uint16_t (*build)(struct pg_tx_worker *, struct rte_mbuf **, uint16_t) =
        o->template_mode == PG_TEMPLATE_STATIC ? build_static : build_sequence;
    bool retrying_allocation = false;
    uint16_t burst = o->burst;
    while (!atomic_load_explicit(&ready, memory_order_acquire)) {
        if (atomic_load_explicit(&stopped, memory_order_relaxed)) return -1;
        rte_pause();
    }
    if (!wait_until(w, w->start)) return 0;
    next_burst = w->start;
    if (w->rate) {
        /* Avoid large microbursts at low requested rates. */
        uint64_t paced_burst = w->rate / UINT64_C(10000);
        if (!paced_burst) paced_burst = 1;
        if (paced_burst < burst) burst = (uint16_t)paced_burst;
    }
    uint64_t now = w->start;
    /* Reuse the last clock sample between batches. A fresh sample below
     * checks the deadline after building and before every TX attempt. */
    while (w->submitted < w->quota && running_at(w, now)) {
        if (w->rate) {
            if (o->pacing_mode == PG_PACING_CATCH_UP) {
                double ticks = (double)w->submitted * (double)w->hz / (double)w->rate;
                if (ticks >= (double)(UINT64_MAX - w->start)) break;
                next_burst = w->start + (uint64_t)ticks;
            }
            if (!wait_until(w, next_burst)) break;
        }
        uint64_t remaining = w->quota - w->submitted;
        uint16_t size = remaining < burst ? (uint16_t)remaining : burst;
        if (rte_pktmbuf_alloc_bulk(w->pool, buffers, size)) {
            now = rte_get_tsc_cycles();
            if (!retrying_allocation) last_progress = now;
            retrying_allocation = true;
            ++w->allocation_retries;
            (void)rte_eth_tx_done_cleanup(w->port, w->queue, 0);
            if (now - last_progress > w->hz) {
                w->failed = 1;
                atomic_store_explicit(&stopped, true, memory_order_relaxed);
                break;
            }
            rte_pause();
            continue;
        }
        retrying_allocation = false;
        uint16_t built = build(w, buffers, size);
        if (built != size) {
            rte_pktmbuf_free_bulk(buffers, size);
            w->released += size;
            w->failed = 1;
            atomic_store_explicit(&stopped, true, memory_order_relaxed);
            break;
        }
        uint16_t offset = 0;
        uint64_t retry_delay = w->hz / UINT64_C(10000000);
        if (!retry_delay) retry_delay = 1;
        now = rte_get_tsc_cycles();
        last_progress = now;
        while (offset < size && running_at(w, now)) {
            ++w->tx_calls;
            uint16_t accepted = rte_eth_tx_burst(w->port, w->queue, buffers + offset,
                                                (uint16_t)(size - offset));
            offset = (uint16_t)(offset + accepted);
            w->submitted += accepted;
            if (accepted) {
                last_progress = now;
                retry_delay = w->hz / UINT64_C(10000000);
                if (!retry_delay) retry_delay = 1;
            }
            if (offset < size) {
                ++w->backpressure;
                if ((w->backpressure & UINT64_C(255)) == 0)
                    (void)rte_eth_tx_done_cleanup(w->port, w->queue, 0);
                /* An accepted packet establishes progress. Only a zero TX
                 * needs another clock sample to test the no-progress limit. */
                if (!accepted) now = rte_get_tsc_cycles();
                if (now - last_progress > w->hz) {
                    w->failed = 1;
                    atomic_store_explicit(&stopped, true, memory_order_relaxed);
                    break;
                }
                /* A full ring needs the device/backend to make progress.
                 * Back off 100 ns..1 us instead of repeatedly rereading its
                 * descriptors millions of times per accepted batch. */
                if (!accepted) {
                    uint64_t retry_at = now + retry_delay;
                    while (running_at(w, now) && now < retry_at) {
                        rte_pause();
                        now = rte_get_tsc_cycles();
                    }
                    uint64_t maximum = w->hz / UINT64_C(1000000);
                    if (retry_delay < maximum) {
                        retry_delay *= 2u;
                        if (retry_delay > maximum) retry_delay = maximum;
                    }
                } else {
                    rte_pause();
                    now = rte_get_tsc_cycles();
                }
            }
        }
        /* TX acceptance transfers ownership. Only the unaccepted suffix is
         * ours to free, including a partially accepted final burst. */
        if (offset < size) {
            uint16_t unsent = (uint16_t)(size - offset);
            rte_pktmbuf_free_bulk(buffers + offset, unsent);
            w->released += unsent;
        }
        if (w->rate && o->pacing_mode == PG_PACING_SMOOTH) {
            /* Keep fractional ticks across batches, but do not build up an
             * unlimited transmission debt while descheduled or backpressured.
             * At most one burst can become immediately eligible after a stall. */
            smooth_ticks += (double)offset * (double)w->hz / (double)w->rate;
            uint64_t ticks = (uint64_t)smooth_ticks;
            smooth_ticks -= (double)ticks;
            if (ticks > UINT64_MAX - next_burst) break;
            next_burst += ticks;
            now = rte_get_tsc_cycles();
            if (next_burst < now) {
                next_burst = now;
                smooth_ticks = 0;
                ++w->pacing_resets;
            }
        }
    }
    w->end = rte_get_tsc_cycles();
    return w->failed ? -1 : 0;
}

static uint64_t unix_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

int pg_dpdk_run(int eal_argc, char **eal_argv, const struct pg_options *o)
{
    int status = -1;
    bool configured = false, start_attempted = false, safe_to_free = true;
    bool int_handler = false, term_handler = false;
    struct sigaction action = {0}, old_int = {0}, old_term = {0};
    struct pg_tx_worker *workers = NULL;
    struct pg_packet_template *templates = NULL;
    const struct pg_packet_template **flow_orders = NULL;
    unsigned ids[PG_MAX_WORKERS] = {0}, launched = 0;
    FILE *json = NULL;
    uint64_t submitted = 0, released = 0, rate = o->pps;
    uint64_t start = 0, end = 0, start_ns = 0, end_ns = 0;
    double elapsed = 0;
    uint16_t rx_desc = 128, tx_desc = o->tx_descriptors;
    uint16_t pool_data_room = 0;
    uint64_t tx_offloads = 0;
    bool descriptors_adjusted = false;
    bool prefilled_static_enabled = false;
    struct rte_eth_stats stats = {0}, stats_before = {0};
    bool stats_available = false;
    bool stats_baseline_available = true;
    atomic_store(&stopped, false); atomic_store(&ready, false);
    if (o->stats_json) {
        json = fopen(o->stats_json, "wx");
        if (!json) { perror("Cannot create statistics file"); return -1; }
    }
    if (rte_eal_init(eal_argc, eal_argv) < 0) {
        fprintf(stderr, "EAL initialization failed: %s\n", rte_strerror(rte_errno));
        if (json) fclose(json);
        return -1;
    }
    if (!rte_eth_dev_is_valid_port(o->port_id)) { fprintf(stderr, "Selected port does not exist\n"); goto done; }
    if (rte_lcore_count() < o->workers) { fprintf(stderr, "Enable at least --workers EAL lcores\n"); goto done; }
    ids[0] = rte_get_main_lcore();
    unsigned id, n = 1;
    for (id = rte_get_next_lcore(UINT_MAX, 1, 0); id < RTE_MAX_LCORE;
         id = rte_get_next_lcore(id, 1, 0)) {
        if (n < o->workers) ids[n++] = id;
    }
    struct rte_eth_dev_info device = {0};
    if (rte_eth_dev_info_get(o->port_id, &device) || device.max_tx_queues < o->workers) {
        fprintf(stderr, "Selected port has insufficient TX queues\n"); goto done;
    }
    struct pg_packet_config packet = o->packet;
    struct rte_ether_addr mac;
    if (rte_eth_macaddr_get(o->port_id, &mac)) { fprintf(stderr, "Cannot read source MAC\n"); goto done; }
    memcpy(packet.src_mac, mac.addr_bytes, sizeof(packet.src_mac));
    templates = rte_zmalloc("pg_templates", sizeof(*templates) * o->flows, RTE_CACHE_LINE_SIZE);
    workers = rte_zmalloc("pg_workers", sizeof(*workers) * o->workers, RTE_CACHE_LINE_SIZE);
    flow_orders = rte_zmalloc("pg_flow_orders", sizeof(*flow_orders) * o->flows * o->workers,
                             RTE_CACHE_LINE_SIZE);
    if (!templates || !workers || !flow_orders) { fprintf(stderr, "Cannot allocate worker/template state\n"); goto done; }
    for (uint16_t f = 0; f < o->flows; ++f) {
        packet.src_port = (uint16_t)(o->packet.src_port + f);
        char error[128];
        if (pg_packet_template_init(&templates[f], &packet, error, sizeof(error))) {
            fprintf(stderr, "Template construction failed: %s\n", error); goto done;
        }
    }
    if (templates[0].length > UINT16_MAX) { fprintf(stderr, "Frame exceeds one mbuf\n"); goto done; }
    /* TX frames have a fixed length during the run. A cache-line-sized data
     * room avoids carrying a default 2 KB buffer for each minimum-size frame,
     * while retaining the PMD's normal headroom and direct mbuf ownership. */
    size_t room = (size_t)RTE_PKTMBUF_HEADROOM + templates[0].length;
    room = (room + RTE_CACHE_LINE_SIZE - 1u) / RTE_CACHE_LINE_SIZE * RTE_CACHE_LINE_SIZE;
    if (room > UINT16_MAX) { fprintf(stderr, "Frame data room exceeds mbuf limit\n"); goto done; }
    pool_data_room = (uint16_t)room;
    if (o->unlimited) rate = 0;
    else if (o->rate_mbps) rate = o->rate_mbps * UINT64_C(1000000) / (templates[0].length * 8u);
    if ((!o->unlimited && (rate < o->workers || rate > UINT64_C(1000000000)))) {
        fprintf(stderr, "Effective PPS must be >= workers and <= 1000000000\n"); goto done;
    }
    struct rte_eth_conf conf = {0};
    /* Every TX queue uses one pool of fresh, direct mbufs with refcnt 1.
     * Drivers that do not advertise this capability keep their normal path. */
    if (device.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        tx_offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    /* These PMDs leave Ethernet bytes unchanged in our no-packet-offload
     * path: PCAP reads them and Virtio writes only its preceding headroom
     * header. Other drivers keep the normal per-allocation frame copy. */
    bool static_prefill_driver = device.driver_name &&
        (!strcmp(device.driver_name, "net_virtio") || !strcmp(device.driver_name, "net_pcap")) &&
        !(tx_offloads & ~RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE);
    conf.txmode.offloads = tx_offloads;
    if (rte_eth_dev_configure(o->port_id, 0, o->workers, &conf)) {
        fprintf(stderr, "Port configuration failed\n"); goto done;
    }
    configured = true;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(o->port_id, &rx_desc, &tx_desc)) {
        fprintf(stderr, "Descriptor configuration failed\n"); goto done;
    }
    descriptors_adjusted = true;
    int socket = rte_eth_dev_socket_id(o->port_id);
    if (socket < 0) socket = (int)rte_socket_id();
    if (socket < 0) { fprintf(stderr, "Invalid socket ID\n"); goto done; }
    for (uint16_t q = 0; q < o->workers; ++q) {
        char name[48];
        (void)snprintf(name, sizeof(name), "pg_pool_%u", (unsigned)q);
        uint32_t pool_size = (uint32_t)tx_desc + 8192u;
        workers[q].pool = rte_pktmbuf_pool_create(name, pool_size, 256, 0,
                                                pool_data_room, socket);
        if (!workers[q].pool) { fprintf(stderr, "Pool creation failed: %s\n", rte_strerror(rte_errno)); goto done; }
        uint16_t data_room = rte_pktmbuf_data_room_size(workers[q].pool);
        if (data_room < RTE_PKTMBUF_HEADROOM ||
            (size_t)(data_room - RTE_PKTMBUF_HEADROOM) < templates[0].length) {
            fprintf(stderr, "Frame exceeds pool data room\n"); goto done;
        }
        struct rte_eth_txconf tx = device.default_txconf;
        tx.offloads = tx_offloads;
        if (rte_eth_tx_queue_setup(o->port_id, q, tx_desc, (unsigned)socket, &tx)) {
            fprintf(stderr, "TX queue setup failed\n"); goto done;
        }
        struct rte_eth_txq_info tx_info = {0};
        if (rte_eth_tx_queue_info_get(o->port_id, q, &tx_info) == 0) {
            workers[q].tx_queue_info_available = true;
            workers[q].tx_ring_descriptors = tx_info.nb_desc;
        }
        workers[q].options = o;
        workers[q].frame_length = (uint16_t)templates[0].length;
        workers[q].flow_order = flow_orders + (size_t)q * o->flows;
        uint16_t first = (uint16_t)(q % o->flows), flow = first;
        uint16_t step = (uint16_t)(o->workers % o->flows);
        do {
            workers[q].flow_order[workers[q].flow_period++] = &templates[flow];
            flow = (uint16_t)(flow + step);
            if (flow >= o->flows) flow = (uint16_t)(flow - o->flows);
        } while (flow != first);
        workers[q].masked_flows = !(workers[q].flow_period & (workers[q].flow_period - 1u));
        workers[q].flow_mask = (uint16_t)(workers[q].flow_period - 1u);
        if (o->template_mode == PG_TEMPLATE_STATIC && workers[q].flow_period == 1 &&
            static_prefill_driver) {
            unsigned int initialized = rte_mempool_obj_iter(workers[q].pool,
                                                            prefill_static_object, &workers[q]);
            if (initialized != pool_size) {
                fprintf(stderr, "Cannot prefill every pool object\n"); goto done;
            }
            workers[q].prefilled_static_objects = initialized;
            workers[q].prefilled_static_enabled = true;
            prefilled_static_enabled = true;
        }
        workers[q].sequence = q;
        workers[q].port = o->port_id; workers[q].queue = q;
        workers[q].quota = o->count / o->workers + (q < o->count % o->workers ? 1u : 0u);
        workers[q].rate = rate ? rate / o->workers + (q < rate % o->workers ? 1u : 0u) : 0;
        workers[q].hz = rte_get_tsc_hz();
        if (!workers[q].hz || workers[q].hz > UINT64_MAX / UINT64_C(3600000)) {
            fprintf(stderr, "Unsupported TSC frequency\n"); goto done;
        }
    }
    start_attempted = true;
    if (rte_eth_dev_start(o->port_id)) { fprintf(stderr, "Port start failed\n"); goto done; }
    if (rte_eth_stats_reset(o->port_id))
        stats_baseline_available = rte_eth_stats_get(o->port_id, &stats_before) == 0;
    action.sa_handler = stop_requested;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, &old_int)) goto done;
    int_handler = true;
    if (sigaction(SIGTERM, &action, &old_term)) goto done;
    term_handler = true;
    for (uint16_t q = 1; q < o->workers; ++q) {
        if (rte_eal_remote_launch(transmit, &workers[q], ids[q])) {
            fprintf(stderr, "Cannot launch TX worker\n"); goto join;
        }
        ++launched;
    }
    start = rte_get_tsc_cycles() + workers[0].hz / 200u;
    start_ns = unix_ns() + UINT64_C(5000000);
    for (uint16_t q = 0; q < o->workers; ++q) {
        workers[q].start = start;
        workers[q].deadline = o->duration_ms ? start + workers[q].hz * o->duration_ms / 1000u : 0;
    }
    atomic_store_explicit(&ready, true, memory_order_release);
    status = transmit(&workers[0]);
join:
    if (!atomic_load_explicit(&ready, memory_order_relaxed)) atomic_store(&stopped, true);
    for (unsigned q = 1; q <= launched; ++q)
        if (rte_eal_wait_lcore(ids[q])) status = -1;
    end = rte_get_tsc_cycles();
    end_ns = unix_ns();
    if (start && end >= start) elapsed = (double)(end - start) / (double)rte_get_tsc_hz();
    for (uint16_t q = 0; q < o->workers; ++q) {
        submitted += workers[q].submitted; released += workers[q].released;
        if (workers[q].failed) status = -1;
    }
    /* Allow accepted descriptors to cross the virtual/physical device before
     * stopping it. This bounded drain is outside the measured TX interval. */
    if (submitted) {
        uint64_t drain_end = rte_get_tsc_cycles() + rte_get_tsc_hz() / 5u;
        do {
            for (uint16_t q = 0; q < o->workers; ++q)
                (void)rte_eth_tx_done_cleanup(o->port_id, q, 0);
            struct timespec delay = {0, 1000000};
            (void)nanosleep(&delay, NULL);
        } while (rte_get_tsc_cycles() < drain_end && !atomic_load(&stopped));
    }
    stats_available = stats_baseline_available && rte_eth_stats_get(o->port_id, &stats) == 0;
    if (stats_available) {
        stats.opackets = stats.opackets >= stats_before.opackets ? stats.opackets - stats_before.opackets : 0;
        stats.obytes = stats.obytes >= stats_before.obytes ? stats.obytes - stats_before.obytes : 0;
        stats.oerrors = stats.oerrors >= stats_before.oerrors ? stats.oerrors - stats_before.oerrors : 0;
    }
    printf("Submitted to PMD: %" PRIu64 "; not submitted: %" PRIu64 "\n", submitted, released);
    printf("Elapsed: %.6f s; submitted: %.3f Mpps; frame throughput: %.3f Gbps\n",
           elapsed, elapsed > 0 ? (double)submitted / elapsed / 1e6 : 0,
           elapsed > 0 ? (double)submitted * (double)templates[0].length * 8.0 / elapsed / 1e9 : 0);
done:
    if (start_attempted && rte_eth_dev_stop(o->port_id)) {
        fprintf(stderr, "Port stop failed; retaining driver-owned memory\n"); safe_to_free = false; status = -1;
    }
    if (configured && safe_to_free && rte_eth_dev_close(o->port_id)) {
        fprintf(stderr, "Port close failed; retaining driver-owned memory\n"); safe_to_free = false; status = -1;
    }
    /* Snapshot counters before releasing EAL memory. Report teardown failures
     * in the same final status as the process exit code. */
    struct pg_tx_worker snapshots[PG_MAX_WORKERS] = {0};
    bool have_workers = workers != NULL;
    size_t length = templates ? templates[0].length : 0;
    if (workers) memcpy(snapshots, workers, sizeof(*workers) * o->workers);
    if (safe_to_free && workers) for (uint16_t q = 0; q < o->workers; ++q)
        if (workers[q].pool) rte_mempool_free(workers[q].pool);
    rte_free(flow_orders); rte_free(templates); rte_free(workers);
    if (safe_to_free && rte_eal_cleanup()) {
        fprintf(stderr, "EAL cleanup failed\n"); status = -1;
    }
    if (json) {
        fprintf(json, "{\n  \"status\": \"%s\",\n  \"requested_count\": %" PRIu64
                ",\n  \"requested_pps\": %" PRIu64 ",\n  \"requested_frame_mbps\": %" PRIu64
                ",\n  \"unlimited\": %s,\n  \"duration_ms\": %" PRIu32
                ",\n  \"workers\": %u,\n  \"burst\": %u,\n  \"flows\": %u,\n  \"template\": \"%s\""
                ",\n  \"pacing\": \"%s\",\n  \"requested_tx_descriptors\": %u"
                ",\n  \"tx_descriptors\": %u,\n  \"mbuf_fast_free_enabled\": %s"
                ",\n  \"mbuf_data_room_bytes\": %u,\n  \"mbuf_headroom_bytes\": %u"
                ",\n  \"prefilled_static_enabled\": %s"
                ",\n  \"frame_bytes\": %zu,\n  \"submitted\": %" PRIu64
                ",\n  \"not_submitted\": %" PRIu64 ",\n  \"elapsed_seconds\": %.9f"
                ",\n  \"start_unix_ns\": %" PRIu64 ",\n  \"end_unix_ns\": %" PRIu64
                ",\n  \"actual_pps\": %.3f,\n  \"frame_gbps\": %.9f,\n  \"wire_equivalent_gbps\": %.9f"
                ",\n  \"drain_wait_ms\": 200,\n  \"hardware_stats_available\": %s,\n  \"hardware_opackets\": %" PRIu64
                ",\n  \"hardware_obytes\": %" PRIu64 ",\n  \"hardware_oerrors\": %" PRIu64 ",\n  \"per_worker\": [",
                status ? "error" : (atomic_load(&stopped) ? "interrupted" : "complete"),
                o->count, rate, o->rate_mbps, o->unlimited ? "true" : "false", o->duration_ms,
                (unsigned)o->workers, (unsigned)o->burst, (unsigned)o->flows,
                o->template_mode == PG_TEMPLATE_STATIC ? "static" : "sequence",
                o->pacing_mode == PG_PACING_SMOOTH ? "smooth" : "catch-up",
                (unsigned)o->tx_descriptors, descriptors_adjusted ? (unsigned)tx_desc : 0u,
                configured && tx_offloads ? "true" : "false", (unsigned)pool_data_room,
                (unsigned)RTE_PKTMBUF_HEADROOM, prefilled_static_enabled ? "true" : "false", length,
                submitted, released, elapsed, start_ns, end_ns,
                elapsed > 0 ? (double)submitted / elapsed : 0,
                elapsed > 0 ? (double)submitted * (double)length * 8.0 / elapsed / 1e9 : 0,
                elapsed > 0 ? (double)submitted * (double)(length + 24u) * 8.0 / elapsed / 1e9 : 0,
                stats_available ? "true" : "false", stats.opackets, stats.obytes, stats.oerrors);
        if (have_workers) for (uint16_t q = 0; q < o->workers; ++q)
            fprintf(json, "%s\n    {\"queue\": %u, \"lcore\": %u, \"submitted\": %" PRIu64
                    ", \"released\": %" PRIu64 ", \"tx_calls\": %" PRIu64
                    ", \"backpressure_events\": %" PRIu64 ", \"allocation_retries\": %" PRIu64
                    ", \"pacing_resets\": %" PRIu64 ", \"tx_queue_info_available\": %s"
                    ", \"tx_ring_descriptors\": %u, \"prefilled_static_enabled\": %s"
                    ", \"prefilled_static_objects\": %" PRIu32 "}",
                    q ? "," : "", (unsigned)q, ids[q], snapshots[q].submitted, snapshots[q].released,
                    snapshots[q].tx_calls, snapshots[q].backpressure, snapshots[q].allocation_retries,
                    snapshots[q].pacing_resets, snapshots[q].tx_queue_info_available ? "true" : "false",
                    (unsigned)snapshots[q].tx_ring_descriptors,
                    snapshots[q].prefilled_static_enabled ? "true" : "false", snapshots[q].prefilled_static_objects);
        fprintf(json, "\n  ]\n}\n");
        if (ferror(json)) status = -1;
        if (fclose(json)) status = -1;
    }
    if (term_handler) (void)sigaction(SIGTERM, &old_term, NULL);
    if (int_handler) (void)sigaction(SIGINT, &old_int, NULL);
    return status;
}
