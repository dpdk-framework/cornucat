#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
/* Receive-only measurement companion. It never creates or transmits a packet. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_pause.h>
#include <rte_prefetch.h>

#define RX_MAX_QUEUES 16u
#define RX_BURST 256u
#define RX_PREFETCH 4u
#define RX_SAMPLE_INTERVAL UINT64_C(1000000)
#define RX_LIVE_PUBLISH_MS 10u
enum rx_tcp_profile {
    RX_TCP_SYN, RX_TCP_ACK, RX_TCP_SYN_ACK, RX_TCP_PSH_ACK,
    RX_TCP_FIN_ACK, RX_TCP_RST, RX_TCP_RST_ACK, RX_TCP_PROFILES
};
enum { RX_TCP_CLASS_BASE = 256 };
_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "Signal stop flag must be lock-free");

struct rx_options {
    uint16_t port;
    uint16_t queues;
    uint16_t descriptors;
    uint32_t duration_ms;
    uint32_t idle_ms;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    const char *stats_path;
    const char *live_path;
    bool explicit_port;
    bool continuous;
};

struct rx_queue {
    uint16_t id;
    uint16_t descriptors;
    int descriptor_query_result;
    unsigned lcore;
    uint64_t packets;
    uint64_t bytes;
    uint64_t matched;
    uint64_t matched_bytes;
    uint64_t malformed;
    uint64_t other;
    uint64_t samples;
    uint64_t next_sample;
    uint64_t checksum_errors;
    uint64_t udp;
    uint64_t tcp;
    uint64_t icmp;
    uint64_t tcp_profiles[RX_TCP_PROFILES];
    uint64_t first_tsc;
    uint64_t final_tsc;
    /* Only this cache line is shared with the coordinator. Keep its periodic
     * reads away from counters that the queue's owner updates continuously. */
    atomic_uint_fast64_t last_tsc __rte_cache_aligned;
} __rte_cache_aligned;

static struct rx_options options;
static struct rx_queue queue_stats[RX_MAX_QUEUES];
static atomic_bool workers_start;
static atomic_bool workers_stop;
static uint64_t clock_hz;
static uint64_t start_tsc;
static uint64_t end_tsc;
static const char *stop_reason = "setup_failure";
static atomic_bool interrupted;

/* The RX owner touches these locks only when publishing (about 100 times/s).
 * The monitor copies a publication under the lock, then does all file I/O
 * after releasing it. It never reads the owner's mutable queue counters. */
struct live_counters {
    uint64_t packets, bytes, matched, matched_bytes, malformed, other;
    uint64_t samples, checksum_errors, udp, tcp, icmp;
    uint64_t tcp_profiles[RX_TCP_PROFILES];
};
struct live_queue {
    pthread_mutex_t lock;
    struct live_counters counters;
    uint64_t monotonic_ns;
} __rte_cache_aligned;
static struct live_queue live_queues[RX_MAX_QUEUES];
static atomic_bool live_finished;
static atomic_bool live_failed;
static int live_directory = -1;
static char *live_name;
static dev_t live_device;
static ino_t live_inode;
static uint64_t live_sequence;
static uint64_t live_start_ns;
static char live_session[80];
static cpu_set_t original_affinity;
static bool have_original_affinity;

static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static void publish_queue(const struct rx_queue *s, bool final)
{
    struct live_queue *published = &live_queues[s->id];
    int result = final ? pthread_mutex_lock(&published->lock) :
        pthread_mutex_trylock(&published->lock);
    /* A preempted monitor must never stall packet reception. A skipped
     * publication is retried at the next interval and its age remains visible.
     * The final control-thread publication follows the monitor's join. */
    if (!final && result == EBUSY) return;
    if (result) {
        atomic_store_explicit(&live_failed, true, memory_order_relaxed);
        atomic_store_explicit(&workers_stop, true, memory_order_relaxed);
        return;
    }
    published->counters = (struct live_counters){
        .packets = s->packets, .bytes = s->bytes, .matched = s->matched,
        .matched_bytes = s->matched_bytes, .malformed = s->malformed,
        .other = s->other, .samples = s->samples, .checksum_errors = s->checksum_errors,
        .udp = s->udp, .tcp = s->tcp, .icmp = s->icmp};
    memcpy(published->counters.tcp_profiles, s->tcp_profiles, sizeof(s->tcp_profiles));
    published->monotonic_ns = monotonic_ns();
    (void)pthread_mutex_unlock(&published->lock);
}

static void request_stop(int signal_number)
{
    (void)signal_number;
    atomic_store_explicit(&interrupted, true, memory_order_relaxed);
}

static void usage(FILE *stream, const char *name)
{
    fprintf(stream,
        "Usage: %s [EAL options] -- --port-id N --stats-json PATH [options]\n"
        "Receive-only DPDK companion; use an explicitly selected isolated lab port.\n"
        "  --queues N        RX queues, 1..16; one EAL lcore per queue (default 1)\n"
        "  --descriptors N   Requested RX ring size, 64..4096 (default 1024);\n"
        "                    the PMD may adjust it to a supported value\n"
        "  --duration-ms N   Maximum polling time, 1..3600000 (default 30000)\n"
        "  --continuous      Poll until SIGINT/SIGTERM; excludes duration/idle options\n"
        "  --idle-ms N       Stop after first match and this much idle time,\n"
        "                    0 disables idle stopping, max 60000 (default 1000)\n"
        "  --src-ip IPV4     Expected source, lab address (default 198.18.0.1)\n"
        "  --dst-ip IPV4     Expected destination, lab address (default 198.18.0.2)\n"
        "  --stats-json PATH Exclusively create the JSON measurement report\n"
        "  --live-stats PATH Exclusively create then atomically replace a live RX\n"
        "                    snapshot about once per second in a private directory\n"
        "  --help            Show this help before initializing DPDK\n", name);
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

static bool lab_ip(const uint8_t ip[4])
{
    return ip[0] == 10u || (ip[0] == 172u && ip[1] >= 16u && ip[1] <= 31u) ||
        (ip[0] == 192u && ip[1] == 168u) ||
        (ip[0] == 198u && (ip[1] == 18u || ip[1] == 19u));
}

static bool parse_ip(const char *text, uint8_t ip[4])
{
    const char *p = text;
    for (unsigned i = 0; i < 4u; ++i) {
        uint32_t octet = 0;
        unsigned digits = 0;
        while (*p >= '0' && *p <= '9') {
            octet = octet * 10u + (uint32_t)(*p++ - '0');
            if (++digits > 3u || octet > 255u) return false;
        }
        if (!digits || (i < 3u ? *p++ != '.' : *p != '\0')) return false;
        ip[i] = (uint8_t)octet;
    }
    return lab_ip(ip);
}

static int parse_options(int argc, char *const argv[])
{
    options = (struct rx_options){.queues = 1, .descriptors = 1024, .duration_ms = 30000,
        .idle_ms = 1000, .src_ip = {198,18,0,1}, .dst_ip = {198,18,0,2}};
    unsigned seen = 0;
    for (int i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) return 1;
        const char *key = argv[i];
        if (!strcmp(key, "--continuous")) {
            if (seen & 256u) { fprintf(stderr, "Duplicate receiver option: %s\n", key); return -1; }
            seen |= 256u;
            options.continuous = true;
            continue;
        }
        if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", key); return -1; }
        const char *value = argv[i];
        unsigned flag;
        uint32_t parsed;
        if (!strcmp(key, "--port-id")) {
            flag = 1u;
            if (!number(value, UINT16_MAX, &parsed)) goto invalid;
            options.port = (uint16_t)parsed;
            options.explicit_port = true;
        } else if (!strcmp(key, "--queues")) {
            flag = 2u;
            if (!number(value, RX_MAX_QUEUES, &parsed) || !parsed) goto invalid;
            options.queues = (uint16_t)parsed;
        } else if (!strcmp(key, "--duration-ms")) {
            flag = 4u;
            if (!number(value, 3600000u, &parsed) || !parsed) goto invalid;
            options.duration_ms = parsed;
        } else if (!strcmp(key, "--idle-ms")) {
            flag = 8u;
            if (!number(value, 60000u, &parsed)) goto invalid;
            options.idle_ms = parsed;
        } else if (!strcmp(key, "--src-ip")) {
            flag = 16u;
            if (!parse_ip(value, options.src_ip)) goto invalid;
        } else if (!strcmp(key, "--dst-ip")) {
            flag = 32u;
            if (!parse_ip(value, options.dst_ip)) goto invalid;
        } else if (!strcmp(key, "--stats-json")) {
            flag = 64u;
            if (!*value) goto invalid;
            options.stats_path = value;
        } else if (!strcmp(key, "--descriptors")) {
            flag = 128u;
            if (!number(value, 4096u, &parsed) || parsed < 64u) goto invalid;
            options.descriptors = (uint16_t)parsed;
        } else if (!strcmp(key, "--live-stats")) {
            flag = 512u;
            if (!*value) goto invalid;
            options.live_path = value;
        } else { fprintf(stderr, "Unknown receiver option: %s\n", key); return -1; }
        if (seen & flag) { fprintf(stderr, "Duplicate receiver option: %s\n", key); return -1; }
        seen |= flag;
        continue;
invalid:
        fprintf(stderr, "Invalid value for %s\n", key);
        return -1;
    }
    if (!options.explicit_port || !options.stats_path) {
        fprintf(stderr, "Explicit --port-id and --stats-json are required\n");
        return -1;
    }
    if (!memcmp(options.src_ip, options.dst_ip, 4)) {
        fprintf(stderr, "Source and destination must differ\n");
        return -1;
    }
    if (options.continuous) {
        if (seen & (4u | 8u)) {
            fprintf(stderr, "--continuous excludes explicit --duration-ms and --idle-ms\n");
            return -1;
        }
        options.duration_ms = 0;
        options.idle_ms = 0;
    }
    if (options.live_path && !strcmp(options.live_path, options.stats_path)) {
        fprintf(stderr, "Live snapshot and final report paths must differ\n");
        return -1;
    }
    return 0;
}

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t checksum_add(uint32_t sum, const uint8_t *p, size_t length)
{
    while (length >= 2u) {
        sum += be16(p);
        p += 2;
        length -= 2u;
    }
    if (length) sum += (uint32_t)*p << 8;
    return sum;
}

static bool checksum_valid(uint32_t sum)
{
    while (sum >> 16) sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
    return sum == UINT32_C(0xffff);
}

/* Slow validation occurs only for the first match and every million matches
 * per queue. Every frame still receives bounded length and flow checks. */
static bool sample_checksum(const struct rte_mbuf *buffer)
{
    uint8_t header_copy[34];
    if (rte_pktmbuf_pkt_len(buffer) < sizeof(header_copy)) return false;
    const uint8_t *header = rte_pktmbuf_data_len(buffer) >= sizeof(header_copy) ?
        rte_pktmbuf_mtod(buffer, const uint8_t *) :
        rte_pktmbuf_read(buffer, 0, sizeof(header_copy), header_copy);
    if (!header) return false;
    uint16_t ip_length = be16(header + 16);
    uint8_t ip_header = (uint8_t)((header[14] & 15u) * 4u);
    uint8_t protocol = header[23];
    unsigned minimum_transport = protocol == 6u ? 20u : 8u;
    if (ip_header < 20u || ip_length < (unsigned)ip_header + minimum_transport ||
        (protocol != 1u && protocol != 6u && protocol != 17u)) return false;
    uint8_t copy[1514];
    uint32_t needed = (uint32_t)ip_length + 14u;
    if (needed > sizeof(copy)) return false;
    const uint8_t *frame = rte_pktmbuf_data_len(buffer) >= needed ?
        rte_pktmbuf_mtod(buffer, const uint8_t *) :
        rte_pktmbuf_read(buffer, 0, needed, copy);
    if (!frame) return false;
    const uint8_t *ip = frame + 14;
    if (!checksum_valid(checksum_add(0, ip, ip_header))) return false;
    size_t transport_length = (size_t)ip_length - ip_header;
    const uint8_t *transport = ip + ip_header;
    if (protocol == 1u) return checksum_valid(checksum_add(0, transport, transport_length));
    if (protocol == 17u && be16(transport + 6) == 0u) return false;
    uint32_t sum = checksum_add(0, ip + 12, 8);
    sum += protocol;
    sum += (uint32_t)transport_length;
    return checksum_valid(checksum_add(sum, transport, transport_length));
}

/* Return UDP/ICMP's IP protocol or RX_TCP_CLASS_BASE + raw TCP profile for a
 * structurally valid expected flow, 0 for another flow, -1 for a malformed
 * frame. Raw TCP headers are not evidence of an established connection.
 * This read-only classifier lets the
 * owner accumulate counters in registers until the entire burst is parsed. */
static int classify(const struct rte_mbuf *buffer)
{
    uint32_t frame_length = rte_pktmbuf_pkt_len(buffer);
    if (frame_length < 14u) return -1;
    uint8_t scratch[94];
    uint32_t inspected = frame_length < sizeof(scratch) ? frame_length : (uint32_t)sizeof(scratch);
    /* Virtio and most NICs deliver the bounded header contiguously. Read it
     * in place; segmented headers still use DPDK's checked copying fallback. */
    const uint8_t *frame = rte_pktmbuf_data_len(buffer) >= inspected ?
        rte_pktmbuf_mtod(buffer, const uint8_t *) :
        rte_pktmbuf_read(buffer, 0, inspected, scratch);
    if (!frame) return -1;
    if (be16(frame + 12) != UINT16_C(0x0800)) return 0;
    if (frame_length < 34u) return -1;
    const uint8_t *ip = frame + 14;
    if (memcmp(ip + 12, options.src_ip, 4) || memcmp(ip + 16, options.dst_ip, 4)) return 0;
    uint8_t header = (uint8_t)((ip[0] & 15u) * 4u);
    uint16_t length = be16(ip + 2);
    if ((ip[0] >> 4) != 4u || header < 20u || length < header ||
        (uint32_t)length + 14u > frame_length || (be16(ip + 6) & UINT16_C(0x3fff))) return -1;
    uint16_t transport_length = (uint16_t)(length - header);
    const uint8_t *transport = ip + header;
    uint8_t protocol = ip[9];
    if (protocol == 17u) {
        if (transport_length < 8u || !be16(transport) || !be16(transport + 2) ||
            be16(transport + 4) != transport_length) return -1;
    } else if (protocol == 6u) {
        if (transport_length < 20u || !be16(transport) || !be16(transport + 2) ||
            (transport[12] >> 4) < 5u || (unsigned)(transport[12] >> 4) * 4u > transport_length ||
            (transport[12] & 15u)) return -1;
        /* Deliberately independent of the generator's profile helpers. */
        switch (transport[13]) {
        case 0x02: return RX_TCP_CLASS_BASE + RX_TCP_SYN;
        case 0x10: return RX_TCP_CLASS_BASE + RX_TCP_ACK;
        case 0x12: return RX_TCP_CLASS_BASE + RX_TCP_SYN_ACK;
        case 0x18: return RX_TCP_CLASS_BASE + RX_TCP_PSH_ACK;
        case 0x11: return RX_TCP_CLASS_BASE + RX_TCP_FIN_ACK;
        case 0x04: return RX_TCP_CLASS_BASE + RX_TCP_RST;
        case 0x14: return RX_TCP_CLASS_BASE + RX_TCP_RST_ACK;
        default: return -1;
        }
    } else if (protocol == 1u) {
        if (transport_length < 8u || transport[0] != 8u || transport[1] != 0u) return -1;
    } else return 0;
    return protocol;
}

static void coordinator_check(void)
{
    uint64_t now = rte_get_timer_cycles();
    if (atomic_load_explicit(&interrupted, memory_order_relaxed)) stop_reason = "signal";
    else if (atomic_load_explicit(&live_failed, memory_order_relaxed)) stop_reason = "live_stats_failure";
    else if (!options.continuous && now - start_tsc >= clock_hz * options.duration_ms / 1000u) stop_reason = "duration";
    else if (options.idle_ms) {
        uint64_t last = 0;
        for (uint16_t q = 0; q < options.queues; ++q) {
            uint64_t value = atomic_load_explicit(&queue_stats[q].last_tsc, memory_order_relaxed);
            if (value > last) last = value;
        }
        if (last && now >= last && now - last >= clock_hz * options.idle_ms / 1000u) stop_reason = "idle";
        else return;
    } else return;
    atomic_store_explicit(&workers_stop, true, memory_order_relaxed);
}

static int receive_queue(void *argument)
{
    struct rx_queue *stats = argument;
    stats->lcore = rte_lcore_id();
    while (!atomic_load_explicit(&workers_start, memory_order_acquire) &&
           !atomic_load_explicit(&workers_stop, memory_order_relaxed)) rte_pause();
    /* A setup failure can cancel a launched worker before release. Do not
     * read timer state unless the start release has been acquired. */
    if (!atomic_load_explicit(&workers_start, memory_order_acquire)) return 0;
    struct rte_mbuf *buffers[RX_BURST];
    unsigned polls = 0;
    uint64_t next_publication = start_tsc + clock_hz * RX_LIVE_PUBLISH_MS / 1000u;
    while (!atomic_load_explicit(&workers_stop, memory_order_relaxed)) {
        uint16_t received = rte_eth_rx_burst(options.port, stats->id, buffers, RX_BURST);
        if (received) {
            uint64_t bytes = 0, matched_bytes = 0;
            uint64_t matched_base = stats->matched, next_sample = stats->next_sample;
            uint16_t matched = 0, malformed = 0, other = 0;
            uint16_t udp = 0, tcp = 0, icmp = 0, samples = 0, checksum_errors = 0;
            uint16_t tcp_profiles[RX_TCP_PROFILES] = {0};
            stats->packets += received;
            for (uint16_t i = 0; i < received && i < RX_PREFETCH; ++i)
                rte_prefetch0(rte_pktmbuf_mtod(buffers[i], const void *));
            for (uint16_t i = 0; i < received; ++i) {
                if ((unsigned)i + RX_PREFETCH < received)
                    rte_prefetch0(rte_pktmbuf_mtod(buffers[i + RX_PREFETCH], const void *));
                uint32_t frame_bytes = rte_pktmbuf_pkt_len(buffers[i]);
                bytes += frame_bytes;
                int classification = classify(buffers[i]);
                if (classification > 0) {
                    if (matched_base + matched == next_sample) {
                        next_sample += RX_SAMPLE_INTERVAL;
                        ++samples;
                        if (!sample_checksum(buffers[i])) ++checksum_errors;
                    }
                    ++matched;
                    matched_bytes += frame_bytes;
                    if (classification == 17) ++udp;
                    else if (classification >= RX_TCP_CLASS_BASE) {
                        ++tcp;
                        ++tcp_profiles[(unsigned)(classification - RX_TCP_CLASS_BASE)];
                    }
                    else ++icmp;
                } else if (classification < 0) ++malformed;
                else ++other;
            }
            stats->bytes += bytes;
            stats->matched += matched;
            stats->matched_bytes += matched_bytes;
            stats->malformed += malformed;
            stats->other += other;
            stats->udp += udp;
            stats->tcp += tcp;
            for (unsigned p = 0; p < RX_TCP_PROFILES; ++p)
                stats->tcp_profiles[p] += tcp_profiles[p];
            stats->icmp += icmp;
            stats->samples += samples;
            stats->checksum_errors += checksum_errors;
            stats->next_sample = next_sample;
            if (matched) {
                uint64_t now = rte_get_timer_cycles();
                if (!stats->first_tsc) stats->first_tsc = now;
                stats->final_tsc = now;
                atomic_store_explicit(&stats->last_tsc, now, memory_order_relaxed);
                if (options.live_path && now >= next_publication) {
                    publish_queue(stats, false);
                    next_publication = now + clock_hz * RX_LIVE_PUBLISH_MS / 1000u;
                }
            }
            rte_pktmbuf_free_bulk(buffers, received);
        }
        if ((stats->id == 0u || options.live_path) && (++polls & 1023u) == 0u) {
            if (options.live_path) {
                uint64_t now = rte_get_timer_cycles();
                if (now >= next_publication) {
                    publish_queue(stats, false);
                    next_publication = now + clock_hz * RX_LIVE_PUBLISH_MS / 1000u;
                }
            }
            if (stats->id == 0u) coordinator_check();
        }
    }
    if (options.live_path) publish_queue(stats, false);
    return 0;
}

static uint64_t realtime_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) || now.tv_sec < 0) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static bool live_target_owned(void)
{
    struct stat target;
    return !fstatat(live_directory, live_name, &target, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(target.st_mode) && target.st_uid == geteuid() && target.st_nlink == 1 &&
        !(target.st_mode & 077u) && target.st_dev == live_device && target.st_ino == live_inode;
}

static int prepare_live_file(void)
{
    char *path = strdup(options.live_path);
    if (!path) return -1;
    char *slash = strrchr(path, '/');
    const char *directory = ".";
    const char *name = path;
    if (slash) {
        name = slash + 1;
        *slash = '\0';
        directory = slash == path ? "/" : path;
    }
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) {
        free(path); errno = EINVAL; return -1;
    }
    live_name = strdup(name);
    if (!live_name) { free(path); return -1; }
    live_directory = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    free(path);
    if (live_directory < 0) return -1;
    struct stat parent;
    if (fstat(live_directory, &parent)) return -1;
    /* A directory writable by another UID cannot safely hold an atomic
     * replacement target. Keep a directory FD so path changes cannot redirect
     * subsequent writes; reject symlinks and unexpected target replacements. */
    if (parent.st_uid != geteuid() || (parent.st_mode & 022u)) {
        errno = EACCES; return -1;
    }
    int fd = openat(live_directory, live_name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    struct stat initial;
    int result = fstat(fd, &initial);
    if (!result) { live_device = initial.st_dev; live_inode = initial.st_ino; }
    if (close(fd)) result = -1;
    (void)snprintf(live_session, sizeof(live_session), "%ld-%016" PRIx64,
                   (long)getpid(), monotonic_ns());
    return result;
}

static void write_tcp_counters(FILE *stream, uint64_t total,
                                const uint64_t profiles[RX_TCP_PROFILES])
{
    fprintf(stream,
        ", \"tcp_packets\": %" PRIu64 ", \"tcp_syn_packets\": %" PRIu64
        ", \"tcp_ack_packets\": %" PRIu64 ", \"tcp_syn_ack_packets\": %" PRIu64
        ", \"tcp_psh_ack_packets\": %" PRIu64 ", \"tcp_fin_ack_packets\": %" PRIu64
        ", \"tcp_rst_packets\": %" PRIu64 ", \"tcp_rst_ack_packets\": %" PRIu64,
        total, profiles[RX_TCP_SYN], profiles[RX_TCP_ACK], profiles[RX_TCP_SYN_ACK],
        profiles[RX_TCP_PSH_ACK], profiles[RX_TCP_FIN_ACK], profiles[RX_TCP_RST],
        profiles[RX_TCP_RST_ACK]);
}

static void write_live_counters(FILE *stream, const struct live_counters *s)
{
    fprintf(stream,
        "\"received_packets\": %" PRIu64 ", \"received_bytes\": %" PRIu64
        ", \"matched_packets\": %" PRIu64 ", \"matched_bytes\": %" PRIu64
        ", \"malformed_packets\": %" PRIu64 ", \"other_packets\": %" PRIu64
        ", \"checksum_samples\": %" PRIu64 ", \"checksum_errors\": %" PRIu64,
        s->packets, s->bytes, s->matched, s->matched_bytes, s->malformed, s->other,
        s->samples, s->checksum_errors);
    write_tcp_counters(stream, s->tcp, s->tcp_profiles);
}

static int write_live_snapshot(const char *state)
{
    struct live_counters snapshots[RX_MAX_QUEUES], total = {0};
    uint64_t oldest = UINT64_MAX;
    for (uint16_t q = 0; q < options.queues; ++q) {
        (void)pthread_mutex_lock(&live_queues[q].lock);
        snapshots[q] = live_queues[q].counters;
        uint64_t published = live_queues[q].monotonic_ns;
        (void)pthread_mutex_unlock(&live_queues[q].lock);
        if (!published) published = live_start_ns;
        if (published < oldest) oldest = published;
        const struct live_counters *s = &snapshots[q];
        total.packets += s->packets; total.bytes += s->bytes;
        total.matched += s->matched; total.matched_bytes += s->matched_bytes;
        total.malformed += s->malformed; total.other += s->other;
        total.samples += s->samples; total.checksum_errors += s->checksum_errors;
        total.udp += s->udp; total.tcp += s->tcp; total.icmp += s->icmp;
        for (unsigned p = 0; p < RX_TCP_PROFILES; ++p)
            total.tcp_profiles[p] += s->tcp_profiles[p];
    }
    uint64_t now = monotonic_ns();
    if (!now || !live_target_owned()) { errno = ESTALE; return -1; }
    char temporary[128];
    (void)snprintf(temporary, sizeof(temporary), ".packetgen-rx-%s-%" PRIu64 ".tmp",
                   live_session, live_sequence + 1u);
    int fd = openat(live_directory, temporary,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    FILE *stream = fdopen(fd, "w");
    if (!stream) {
        int saved = errno;
        (void)close(fd); (void)unlinkat(live_directory, temporary, 0);
        errno = saved; return -1;
    }
    fprintf(stream,
        "{\"schema_version\": 1, \"session_id\": \"%s\", \"snapshot_sequence\": %" PRIu64
        ", \"snapshot_unix_ns\": %" PRIu64 ", \"monotonic_ns\": %" PRIu64
        ", \"elapsed_seconds\": %.9f, \"status\": \"%s\", \"continuous\": %s, "
        "\"queue_count\": %u, \"counter_publish_interval_ms\": %u, "
        "\"oldest_queue_snapshot_age_ns\": %" PRIu64 ", ",
        live_session, live_sequence + 1u, realtime_ns(), now,
        live_start_ns && now >= live_start_ns ? (double)(now - live_start_ns) / 1e9 : 0.0,
        state, options.continuous ? "true" : "false", (unsigned)options.queues,
        RX_LIVE_PUBLISH_MS, now >= oldest ? now - oldest : 0);
    write_live_counters(stream, &total);
    fprintf(stream,
        ", \"udp_packets\": %" PRIu64
        ", \"icmp_packets\": %" PRIu64 ", \"checksum_sample_interval\": %" PRIu64
        ", \"rate_note\": \"Cumulative actual matched RX; interval rates use monotonic counter deltas. "
        "Per-queue publications are staggered. Frame bytes exclude FCS, preamble and IFG. "
        "Checksums are sampled; lengths and flow are checked on every frame.\", \"queues\": [",
        total.udp, total.icmp, RX_SAMPLE_INTERVAL);
    for (uint16_t q = 0; q < options.queues; ++q) {
        fprintf(stream, "%s{\"queue_id\": %u, ", q ? ", " : "", (unsigned)q);
        write_live_counters(stream, &snapshots[q]);
        fputc('}', stream);
    }
    fputs("]}\n", stream);
    struct stat replacement;
    int result = 0;
    if (fflush(stream) || ferror(stream) || fstat(fd, &replacement)) result = -1;
    if (fclose(stream)) result = -1;
    if (!result && !live_target_owned()) { errno = ESTALE; result = -1; }
    if (!result && renameat(live_directory, temporary, live_directory, live_name)) result = -1;
    if (result) { (void)unlinkat(live_directory, temporary, 0); return -1; }
    live_device = replacement.st_dev;
    live_inode = replacement.st_ino;
    ++live_sequence;
    return 0;
}

static void *live_monitor(void *argument)
{
    (void)argument;
    uint64_t next = live_start_ns;
    const struct timespec nap = {.tv_nsec = 100000000};
    while (!atomic_load_explicit(&live_finished, memory_order_acquire)) {
        uint64_t now = monotonic_ns();
        if (!now || now >= next) {
            if (write_live_snapshot("running")) {
                perror("Cannot update live receiver snapshot");
                atomic_store_explicit(&live_failed, true, memory_order_relaxed);
                atomic_store_explicit(&workers_stop, true, memory_order_relaxed);
                break;
            }
            next = now + UINT64_C(1000000000);
        }
        (void)nanosleep(&nap, NULL);
    }
    return NULL;
}

static int start_live_monitor(pthread_t *thread)
{
    pthread_attr_t attributes;
    int result = pthread_attr_init(&attributes);
    if (result) return result;
    if (have_original_affinity) {
        cpu_set_t spare = original_affinity;
        for (unsigned lcore = rte_get_next_lcore(UINT_MAX, 0, 0); lcore < RTE_MAX_LCORE;
             lcore = rte_get_next_lcore(lcore, 0, 0)) {
            rte_cpuset_t used = rte_lcore_cpuset(lcore);
            for (unsigned cpu = 0; cpu < CPU_SETSIZE; ++cpu)
                if (CPU_ISSET(cpu, &used)) CPU_CLR(cpu, &spare);
        }
        /* Small PCAP-only environments may have no spare CPU. In that case
         * restore the original process mask rather than EAL's main-core mask. */
        const cpu_set_t *affinity = CPU_COUNT(&spare) ? &spare : &original_affinity;
        result = pthread_attr_setaffinity_np(&attributes, sizeof(*affinity), affinity);
    }
    if (!result) result = pthread_create(thread, &attributes, live_monitor, NULL);
    (void)pthread_attr_destroy(&attributes);
    return result;
}

static double seconds(uint64_t ticks)
{
    return clock_hz ? (double)ticks / (double)clock_hz : 0.0;
}

static uint64_t difference(uint64_t end, uint64_t beginning)
{
    return end >= beginning ? end - beginning : 0;
}

static int write_report(FILE *stream, int status, uint64_t unix_start, uint64_t unix_end,
                        uint64_t rss_hf, uint16_t rx_desc, const struct rte_eth_stats *before,
                        const struct rte_eth_stats *after, int hw_baseline_result,
                        int hw_stats_result)
{
    struct rx_queue total = {0};
    uint64_t first = 0, last = 0;
    for (uint16_t q = 0; q < options.queues; ++q) {
        const struct rx_queue *s = &queue_stats[q];
        total.packets += s->packets; total.bytes += s->bytes;
        total.matched += s->matched; total.matched_bytes += s->matched_bytes;
        total.malformed += s->malformed; total.other += s->other;
        total.samples += s->samples; total.checksum_errors += s->checksum_errors;
        total.udp += s->udp; total.tcp += s->tcp; total.icmp += s->icmp;
        for (unsigned p = 0; p < RX_TCP_PROFILES; ++p)
            total.tcp_profiles[p] += s->tcp_profiles[p];
        if (s->first_tsc && (!first || s->first_tsc < first)) first = s->first_tsc;
        if (s->final_tsc > last) last = s->final_tsc;
    }
    double elapsed = seconds(end_tsc >= start_tsc ? end_tsc - start_tsc : 0);
    double active = first && last >= first ? seconds(last - first) : 0.0;
    bool hw_available = hw_baseline_result == 0 && hw_stats_result == 0;
    fprintf(stream,
        "{\n  \"schema_version\": 1,\n  \"status\": \"%s\",\n"
        "  \"stop_reason\": \"%s\",\n  \"port_id\": %u,\n  \"queue_count\": %u,\n"
        "  \"requested_rx_descriptors\": %u,\n  \"effective_rx_descriptors\": %u,\n"
        "  \"src_ip\": \"%u.%u.%u.%u\",\n  \"dst_ip\": \"%u.%u.%u.%u\",\n"
        "  \"continuous\": %s,\n  \"duration_limit_ms\": %" PRIu32 ",\n  \"idle_limit_ms\": %" PRIu32 ",\n"
        "  \"start_unix_ns\": %" PRIu64 ",\n  \"end_unix_ns\": %" PRIu64 ",\n"
        "  \"duration_seconds\": %.9f,\n  \"received_packets\": %" PRIu64 ",\n"
        "  \"received_bytes\": %" PRIu64 ",\n  \"matched_packets\": %" PRIu64 ",\n"
        "  \"matched_bytes\": %" PRIu64 ",\n  \"malformed_packets\": %" PRIu64 ",\n"
        "  \"other_packets\": %" PRIu64 ",\n  \"checksum_sample_interval\": %" PRIu64 ",\n"
        "  \"checksum_samples\": %" PRIu64 ",\n  \"checksum_errors\": %" PRIu64 ",\n"
        "  \"udp_packets\": %" PRIu64 ",\n"
        "  \"icmp_echo_packets\": %" PRIu64 ",\n  \"first_matched_seconds\": %.9f,\n"
        "  \"last_matched_seconds\": %.9f,\n  \"active_seconds\": %.9f,\n"
        "  \"matched_active_pps\": %.3f,\n  \"matched_active_l2_gbps\": %.9f,\n"
        "  \"matched_window_pps\": %.3f,\n  \"matched_window_l2_gbps\": %.9f,\n"
        "  \"received_window_pps\": %.3f,\n  \"received_window_l2_gbps\": %.9f,\n"
        "  \"rss_hf\": %" PRIu64 ",\n  \"hw_stats\": {\"available\": %s, \"baseline_result\": %d, \"result\": %d, "
        "\"ipackets\": %" PRIu64 ", \"ibytes\": %" PRIu64 ", \"imissed\": %" PRIu64 ", "
        "\"ierrors\": %" PRIu64 ", \"rx_nombuf\": %" PRIu64 "}",
        status ? "failure" : (!strcmp(stop_reason, "signal") ? "interrupted" : "success"),
        stop_reason, (unsigned)options.port, (unsigned)options.queues,
        (unsigned)options.descriptors, (unsigned)rx_desc,
        (unsigned)options.src_ip[0], (unsigned)options.src_ip[1], (unsigned)options.src_ip[2], (unsigned)options.src_ip[3],
        (unsigned)options.dst_ip[0], (unsigned)options.dst_ip[1], (unsigned)options.dst_ip[2], (unsigned)options.dst_ip[3],
        options.continuous ? "true" : "false", options.duration_ms, options.idle_ms,
        unix_start, unix_end, elapsed,
        total.packets, total.bytes, total.matched, total.matched_bytes, total.malformed, total.other,
        RX_SAMPLE_INTERVAL, total.samples, total.checksum_errors, total.udp, total.icmp,
        first ? seconds(first - start_tsc) : 0.0, last ? seconds(last - start_tsc) : 0.0, active,
        active > 0.0 ? (double)total.matched / active : 0.0,
        active > 0.0 ? (double)total.matched_bytes * 8.0 / active / 1e9 : 0.0,
        elapsed > 0.0 ? (double)total.matched / elapsed : 0.0,
        elapsed > 0.0 ? (double)total.matched_bytes * 8.0 / elapsed / 1e9 : 0.0,
        elapsed > 0.0 ? (double)total.packets / elapsed : 0.0,
        elapsed > 0.0 ? (double)total.bytes * 8.0 / elapsed / 1e9 : 0.0,
        rss_hf, hw_available ? "true" : "false", hw_baseline_result, hw_stats_result,
        hw_available ? difference(after->ipackets, before->ipackets) : 0,
        hw_available ? difference(after->ibytes, before->ibytes) : 0,
        hw_available ? difference(after->imissed, before->imissed) : 0,
        hw_available ? difference(after->ierrors, before->ierrors) : 0,
        hw_available ? difference(after->rx_nombuf, before->rx_nombuf) : 0);
    write_tcp_counters(stream, total.tcp, total.tcp_profiles);
    fputs(",\n  \"queues\": [\n", stream);
    for (uint16_t q = 0; q < options.queues; ++q) {
        const struct rx_queue *s = &queue_stats[q];
        fprintf(stream,
            "    {\"queue_id\": %u, \"lcore_id\": %u, \"received_packets\": %" PRIu64
            ", \"driver_rx_descriptors\": %u, \"descriptor_query_result\": %d"
            ", \"received_bytes\": %" PRIu64 ", \"matched_packets\": %" PRIu64
            ", \"matched_bytes\": %" PRIu64 ", \"malformed_packets\": %" PRIu64
            ", \"other_packets\": %" PRIu64 ", \"checksum_samples\": %" PRIu64
            ", \"checksum_errors\": %" PRIu64 ", \"window_pps\": %.3f, \"window_l2_gbps\": %.9f",
            (unsigned)q, s->lcore, s->packets, (unsigned)s->descriptors,
            s->descriptor_query_result, s->bytes, s->matched, s->matched_bytes,
            s->malformed, s->other, s->samples, s->checksum_errors,
            elapsed > 0.0 ? (double)s->matched / elapsed : 0.0,
            elapsed > 0.0 ? (double)s->matched_bytes * 8.0 / elapsed / 1e9 : 0.0);
        write_tcp_counters(stream, s->tcp, s->tcp_profiles);
        fprintf(stream, "}%s\n", q + 1u < options.queues ? "," : "");
    }
    fputs("  ],\n  \"timestamp_note\": \"First and last matched timestamps record RX batch processing completion, not hardware arrival timestamps. Unix clocks on separate VMs may differ.\",\n  \"rate_note\": \"L2 rates count received frame bytes without FCS, preamble or IFG. Active-span rates are diagnostics; align matched counts with the sender measurement duration for delivered throughput. Checksums are sampled, lengths and flow are checked on every frame.\"\n}\n", stream);
    return ferror(stream) ? -1 : 0;
}

int main(int argc, char **argv)
{
    int separator = -1;
    for (int i = 1; i < argc; ++i) if (!strcmp(argv[i], "--")) { separator = i; break; }
    int first = separator < 0 ? 1 : separator + 1;
    int parsed = parse_options(argc - first, argv + first);
    if (parsed == 1) { usage(stdout, argv[0]); return EXIT_SUCCESS; }
    if (parsed < 0 || separator < 0) {
        if (separator < 0) fprintf(stderr, "Separate EAL and receiver options with --\n");
        usage(stderr, argv[0]); return EXIT_FAILURE;
    }
    int fd = open(options.stats_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { perror("Cannot create receiver JSON report"); return EXIT_FAILURE; }
    FILE *report = fdopen(fd, "w");
    if (!report) { perror("Cannot open receiver report stream"); (void)close(fd); return EXIT_FAILURE; }
    int status = -1;
    bool eal_started = false, configured = false, start_attempted = false, safe_teardown = true;
    bool int_handler = false, term_handler = false;
    bool live_reserved = false, monitor_started = false, monitor_safe = true;
    unsigned live_lock_count = 0;
    pthread_t monitor;
    struct sigaction action = {0}, old_int = {0}, old_term = {0};
    struct rte_mempool *pools[RX_MAX_QUEUES] = {0};
    uint16_t rx_desc = options.descriptors, tx_desc = 1024;
    uint16_t effective_rx_desc = 0;
    struct rte_eth_stats hw_before = {0}, hw_after = {0};
    int hw_baseline_result = -1, hw_stats_result = -1;
    uint64_t rss_hf = 0, unix_start = 0, unix_end = 0;
    unsigned launched[RX_MAX_QUEUES] = {0};
    unsigned launch_count = 0;
    atomic_init(&workers_start, false);
    atomic_init(&workers_stop, false);
    atomic_init(&interrupted, false);
    atomic_init(&live_finished, false);
    atomic_init(&live_failed, false);
    for (uint16_t q = 0; q < options.queues; ++q) {
        queue_stats[q].id = q;
        queue_stats[q].descriptor_query_result = -1;
        atomic_init(&queue_stats[q].last_tsc, 0);
    }
    if (options.live_path) {
        for (uint16_t q = 0; q < options.queues; ++q) {
            int lock_result = pthread_mutex_init(&live_queues[q].lock, NULL);
            if (lock_result) {
                fprintf(stderr, "Cannot initialize live queue mutex: %s\n", strerror(lock_result));
                goto done;
            }
            ++live_lock_count;
        }
        if (prepare_live_file()) { perror("Cannot create live receiver snapshot"); goto done; }
        live_reserved = true;
        have_original_affinity = sched_getaffinity(0, sizeof(original_affinity), &original_affinity) == 0;
    }
    if (rte_eal_init(separator + 1, argv) < 0) {
        fprintf(stderr, "Receiver EAL initialization failed: %s\n", rte_strerror(rte_errno)); goto done;
    }
    eal_started = true;
    clock_hz = rte_get_timer_hz();
    if (!clock_hz || clock_hz > UINT64_MAX / 3600000u) {
        fprintf(stderr, "Unsupported timer frequency\n"); goto done;
    }
    if (rte_lcore_count() < options.queues) {
        fprintf(stderr, "Provide at least one EAL lcore for each RX queue\n"); goto done;
    }
    if (!rte_eth_dev_is_valid_port(options.port)) {
        fprintf(stderr, "Selected receiver port does not exist\n"); goto done;
    }
    struct rte_eth_dev_info info = {0};
    int result = rte_eth_dev_info_get(options.port, &info);
    if (result || info.max_rx_queues < options.queues) {
        fprintf(stderr, "Selected receiver port cannot provide requested RX queues\n"); goto done;
    }
    struct rte_eth_conf configuration = {0};
    if (options.queues > 1u) {
        rss_hf = info.flow_type_rss_offloads & (RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_NONFRAG_IPV4_TCP);
        if (rss_hf) {
            configuration.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
            configuration.rx_adv_conf.rss_conf.rss_hf = rss_hf;
        }
    }
    result = rte_eth_dev_configure(options.port, options.queues, 0, &configuration);
    if (result) { fprintf(stderr, "Receiver port configuration failed: %d\n", result); goto done; }
    configured = true;
    result = rte_eth_dev_adjust_nb_rx_tx_desc(options.port, &rx_desc, &tx_desc);
    if (result) { fprintf(stderr, "Receiver descriptor setup failed: %d\n", result); goto done; }
    effective_rx_desc = rx_desc;
    unsigned socket = rte_socket_id();
    if (socket > INT_MAX) { fprintf(stderr, "Invalid receiver EAL socket ID\n"); goto done; }
    struct rte_eth_rxconf rx_conf = info.default_rxconf;
    rx_conf.offloads = 0;
    int device_socket = rte_eth_dev_socket_id(options.port);
    unsigned queue_socket = device_socket < 0 ? socket : (unsigned)device_socket;
    for (uint16_t q = 0; q < options.queues; ++q) {
        char name[48];
        (void)snprintf(name, sizeof(name), "pg_receiver_pool_%u", (unsigned)q);
        /* Independent pools avoid cross-queue contention during bulk refill.
         * Reserve additional buffers for a burst, the lcore cache and refill. */
        pools[q] = rte_pktmbuf_pool_create(name, (uint32_t)rx_desc + 2048u, 256, 0,
                                         RTE_MBUF_DEFAULT_BUF_SIZE, (int)socket);
        if (!pools[q]) { fprintf(stderr, "Receiver pool creation failed: %s\n", rte_strerror(rte_errno)); goto done; }
        result = rte_eth_rx_queue_setup(options.port, q, rx_desc, queue_socket, &rx_conf, pools[q]);
        if (result) { fprintf(stderr, "RX queue %u setup failed: %d\n", (unsigned)q, result); goto done; }
        struct rte_eth_rxq_info queue_info = {0};
        queue_stats[q].descriptor_query_result = rte_eth_rx_queue_info_get(options.port, q, &queue_info);
        if (!queue_stats[q].descriptor_query_result) queue_stats[q].descriptors = queue_info.nb_desc;
    }
    start_attempted = true;
    result = rte_eth_dev_start(options.port);
    if (result) { fprintf(stderr, "Receiver port start failed: %d\n", result); goto done; }
    hw_baseline_result = rte_eth_stats_get(options.port, &hw_before);
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, &old_int)) { perror("Receiver SIGINT handler"); goto done; }
    int_handler = true;
    if (sigaction(SIGTERM, &action, &old_term)) { perror("Receiver SIGTERM handler"); goto done; }
    term_handler = true;
    uint16_t q = 1;
    for (unsigned lcore = rte_get_next_lcore(UINT_MAX, 1, 0); lcore < RTE_MAX_LCORE;
         lcore = rte_get_next_lcore(lcore, 1, 0)) {
        if (q >= options.queues) break;
        result = rte_eal_remote_launch(receive_queue, &queue_stats[q], lcore);
        if (result) { fprintf(stderr, "Receiver worker launch failed: %d\n", result); goto done; }
        launched[launch_count++] = lcore;
        ++q;
    }
    if (q != options.queues) { fprintf(stderr, "Receiver worker assignment failed\n"); goto done; }
    unix_start = realtime_ns();
    start_tsc = rte_get_timer_cycles();
    stop_reason = "running";
    if (options.live_path) {
        live_start_ns = monotonic_ns();
        if (!live_start_ns) { perror("Cannot read receiver monotonic clock"); goto done; }
        result = start_live_monitor(&monitor);
        if (result) {
            fprintf(stderr, "Cannot start live receiver monitor: %s\n", strerror(result)); goto done;
        }
        monitor_started = true;
    }
    puts("READY receiver configured; polling selected lab port");
    fflush(stdout);
    atomic_store_explicit(&workers_start, true, memory_order_release);
    (void)receive_queue(&queue_stats[0]);
    status = 0;
done:
    atomic_store_explicit(&workers_stop, true, memory_order_relaxed);
    for (unsigned i = 0; i < launch_count; ++i) {
        if (rte_eal_wait_lcore(launched[i])) status = -1;
    }
    if (start_tsc) {
        end_tsc = rte_get_timer_cycles();
        unix_end = realtime_ns();
    }
    if (monitor_started) {
        atomic_store_explicit(&live_finished, true, memory_order_release);
        if (pthread_join(monitor, NULL)) { status = -1; monitor_safe = false; }
    }
    if (atomic_load_explicit(&live_failed, memory_order_relaxed)) {
        stop_reason = "live_stats_failure";
        status = -1;
    }
    if (start_attempted) hw_stats_result = rte_eth_stats_get(options.port, &hw_after);
    for (uint16_t i = 0; i < options.queues; ++i) {
        if (queue_stats[i].malformed || queue_stats[i].checksum_errors) status = -1;
    }
    if (start_attempted && rte_eth_dev_stop(options.port)) {
        fprintf(stderr, "Receiver port stop failed; retaining driver memory\n"); safe_teardown = false; status = -1;
    }
    if (configured && safe_teardown && rte_eth_dev_close(options.port)) {
        fprintf(stderr, "Receiver port close failed; retaining driver memory\n"); safe_teardown = false; status = -1;
    }
    if (safe_teardown) for (uint16_t i = 0; i < options.queues; ++i)
        if (pools[i]) rte_mempool_free(pools[i]);
    if (eal_started && safe_teardown && rte_eal_cleanup()) {
        fprintf(stderr, "Receiver EAL cleanup failed\n"); status = -1;
    }
    if (term_handler) (void)sigaction(SIGTERM, &old_term, NULL);
    if (int_handler) (void)sigaction(SIGINT, &old_int, NULL);
    if (live_reserved && monitor_safe) {
        /* All RX owners have joined: publish their exact final counters before
         * the final snapshot, including queues that never entered their loop. */
        for (uint16_t i = 0; i < options.queues; ++i) publish_queue(&queue_stats[i], true);
        if (atomic_load_explicit(&live_failed, memory_order_relaxed)) {
            stop_reason = "live_stats_failure";
            status = -1;
        }
        const char *state = status ? "failure" :
            (!strcmp(stop_reason, "signal") ? "interrupted" : "complete");
        if (write_live_snapshot(state)) {
            perror("Cannot finish live receiver snapshot");
            stop_reason = "live_stats_failure";
            status = -1;
        }
    }
    if (write_report(report, status, unix_start, unix_end, rss_hf, effective_rx_desc, &hw_before, &hw_after,
                     hw_baseline_result, hw_stats_result)) status = -1;
    if (fclose(report)) { perror("Cannot finish receiver report"); status = -1; }
    if (monitor_safe) {
        for (unsigned i = 0; i < live_lock_count; ++i) (void)pthread_mutex_destroy(&live_queues[i].lock);
        if (live_directory >= 0) (void)close(live_directory);
        free(live_name);
    }
    return status ? EXIT_FAILURE : EXIT_SUCCESS;
}
