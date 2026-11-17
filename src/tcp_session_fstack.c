/* Bounded TCP echo sessions over F-Stack's real FreeBSD TCP/IP stack and DPDK.
 * API baseline: F-Stack v1.25, commit 761639943bdda33103aa98241ca6a3079f1c1b7e.
 * https://github.com/F-Stack/f-stack/blob/v1.25/lib/ff_api.h
 *
 * F-Stack options precede --; application options follow it. This deliberately
 * separate executable never treats raw TCP flag templates as TCP connections.
 * Completed means: correct application bytes and orderly receive EOF, with a
 * local write shutdown. It does not claim that the peer ACKed the final FIN.
 * The stack remains running for two seconds after closing application sockets.
 * Multiple workers use separate F-Stack processes, each with one DPDK lcore.
 * A supervising process gates their start and stops secondaries before primary.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <ff_api.h>
#include <ff_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#define SESSION_MAX 1024u
#define CONNECTION_BUDGET 64u
#define CPS_MAX UINT32_C(1000000000)
#define PAYLOAD_MAX 1400u
#define PG_TCP_NS_PER_S UINT64_C(1000000000)
#define DRAIN_NS (UINT64_C(2) * PG_TCP_NS_PER_S)
#define WORKER_MAX 8u
#define SESSION_JSON_SIZE 12288u

struct session_options {
    bool server, coordinated, software_dispatch;
    const char *local_text, *peer_text, *stats_path, *live_path;
    struct in_addr local_ip, peer_ip;
    uint32_t connections, concurrency, cps, duration_s, timeout_s, payload_size;
    uint32_t worker_index, worker_count;
    uint8_t ttl_min, ttl_max;
    uint16_t port;
};

struct output_file {
    int parent_fd, fd;
    char name[NAME_MAX + 1];
    dev_t device;
    ino_t inode;
};

struct connection {
    int fd;
    bool connecting, write_shutdown, read_eof;
    uint64_t id, opened;
    size_t sent, received;
    uint8_t bytes[PAYLOAD_MAX];
};

struct measurement_snapshot {
    uint64_t monotonic_ns, completed, attempted, failed, verified_bytes;
};

struct session_app {
    struct session_options o;
    struct output_file stats, live;
    struct connection c[SESSION_MAX];
    int listener;
    uint32_t next_slot;
    uint64_t started, now, next_attempt, next_live, drain_until;
    uint64_t attempted, connected, completed, failed, active;
    uint64_t bytes_sent, bytes_received, verified_bytes, rejected_peers;
    uint64_t connect_errors, io_errors, protocol_errors, timeouts, aborted;
    struct measurement_snapshot measurement_start, measurement_end;
    uint8_t dispatch_owner[UINT16_MAX + 1u];
    const char *dispatch_key;
    uint16_t dispatch_reta_size;
    uint64_t ttl_rng, ttl_selections, ttl_callback_errors, ttl_histogram[256];
    const struct rte_eth_rxtx_callback *ttl_callback;
    bool stopping, fatal, live_failed;
    const char *reason;
};

static volatile sig_atomic_t interrupted;
static volatile sig_atomic_t start_requested;
static struct session_app *dispatch_context;

static void on_signal(int signum)
{
    (void)signum;
    interrupted = 1;
}

static void on_start(int signum)
{
    (void)signum;
    start_requested = 1;
}

static uint64_t monotonic_ns(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)value.tv_sec * PG_TCP_NS_PER_S + (uint64_t)value.tv_nsec;
}

static void usage(FILE *f)
{
    fputs("Usage: tcp-session-fstack F-STACK-OPTIONS -- APP-OPTIONS\n"
          "  --role client|server       Required; real TCP echo session role\n"
          "  --local-ip IP --peer-ip IP  Required, opposite 198.18.0.1/.2 lab IPs\n"
          "  --port N                   TCP service port 1024..65535 (9000)\n"
          "  --connections N            Attempt/accept quota 1..4294967295 (200)\n"
          "  --concurrency N            Maximum active sockets 1..1024 (16)\n"
          "  --cps N                    0=maximum, or 1..1000000000 attempts/s (100)\n"
          "  --duration-s N             Run deadline 1..3600 seconds (30)\n"
          "  --timeout-s N              Per-connection deadline 1..30 seconds (5)\n"
          "  --payload-size N           Application echo bytes 1..1400 (64)\n"
          "  --ttl-min N --ttl-max N    Inclusive outgoing per-packet IPv4 TTL 1..255 (64/64)\n"
          "  --worker-index N           Process index 0..worker-count-1 (0)\n"
          "  --worker-count N           Separate F-Stack process contexts 1..8 (1)\n"
          "  --coordinated 0|1          Wait SIGUSR1; hold stack until SIGINT (0)\n"
          "  --software-dispatch 0|1    Redistribute TCP to native stack owners (0)\n"
          "  --stats-json PATH          Required, new file in private absolute directory\n"
          "  --live-json PATH           Optional, new atomically refreshed JSON file\n"
          "  --help                     Print help without starting DPDK\n"
          "Defaults are finite. CPS is connection attempts/s, not packets/s.\n"
          "The server must use the same payload size and a sufficient accept quota.\n"
          "Worker quota, concurrency and CPS are local shares, not global totals.\n"
          "Multiple workers require a supervisor; stop secondary processes first.\n"
          "Only 198.18.0.1 <-> 198.18.0.2 is supported by this lab integration.\n",
          f);
}

static bool number(const char *s, uint32_t minimum, uint32_t maximum,
                   uint32_t *out)
{
    uint64_t n = 0;
    if (s == NULL || *s == '\0') return false;
    for (; *s != '\0'; ++s) {
        if (*s < '0' || *s > '9') return false;
        n = n * 10u + (uint64_t)(*s - '0');
        if (n > maximum) return false;
    }
    if (n < minimum) return false;
    *out = (uint32_t)n;
    return true;
}

static int parse_options(int argc, char **argv, struct session_options *o)
{
    bool role_seen = false;
    uint32_t seen = 0;
    *o = (struct session_options){.connections = 200, .concurrency = 16,
        .cps = 100, .duration_s = 30, .timeout_s = 5, .payload_size = 64,
        .port = 9000, .worker_count = 1, .ttl_min = 64, .ttl_max = 64};
    for (int i = 0; i < argc; ++i) {
        const char *key = argv[i], *value;
        unsigned index;
        uint32_t parsed;
        if (strcmp(key, "--help") == 0) { usage(stdout); return 1; }
        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for %s\n", key); return -1;
        }
        value = argv[++i];
        if (strcmp(key, "--role") == 0) index = 0;
        else if (strcmp(key, "--local-ip") == 0) index = 1;
        else if (strcmp(key, "--peer-ip") == 0) index = 2;
        else if (strcmp(key, "--port") == 0) index = 3;
        else if (strcmp(key, "--connections") == 0) index = 4;
        else if (strcmp(key, "--concurrency") == 0) index = 5;
        else if (strcmp(key, "--cps") == 0) index = 6;
        else if (strcmp(key, "--duration-s") == 0) index = 7;
        else if (strcmp(key, "--timeout-s") == 0) index = 8;
        else if (strcmp(key, "--payload-size") == 0) index = 9;
        else if (strcmp(key, "--stats-json") == 0) index = 10;
        else if (strcmp(key, "--live-json") == 0) index = 11;
        else if (strcmp(key, "--worker-index") == 0) index = 12;
        else if (strcmp(key, "--worker-count") == 0) index = 13;
        else if (strcmp(key, "--coordinated") == 0) index = 14;
        else if (strcmp(key, "--software-dispatch") == 0) index = 15;
        else if (strcmp(key, "--ttl-min") == 0) index = 16;
        else if (strcmp(key, "--ttl-max") == 0) index = 17;
        else { fprintf(stderr, "Unknown option: %s\n", key); return -1; }
        if ((seen & (UINT32_C(1) << index)) != 0) {
            fprintf(stderr, "Duplicate option: %s\n", key); return -1;
        }
        seen |= UINT32_C(1) << index;
        switch (index) {
        case 0:
            if (strcmp(value, "client") != 0 && strcmp(value, "server") != 0)
                goto invalid;
            o->server = strcmp(value, "server") == 0; role_seen = true; break;
        case 1: o->local_text = value; break;
        case 2: o->peer_text = value; break;
        case 3:
            if (!number(value, 1024, 65535, &parsed)) goto invalid;
            o->port = (uint16_t)parsed; break;
        case 4:
            if (!number(value, 1, UINT32_MAX, &o->connections)) goto invalid;
            break;
        case 5:
            if (!number(value, 1, SESSION_MAX, &o->concurrency)) goto invalid;
            break;
        case 6:
            if (!number(value, 0, CPS_MAX, &o->cps)) goto invalid;
            break;
        case 7:
            if (!number(value, 1, 3600, &o->duration_s)) goto invalid;
            break;
        case 8:
            if (!number(value, 1, 30, &o->timeout_s)) goto invalid;
            break;
        case 9:
            if (!number(value, 1, PAYLOAD_MAX, &o->payload_size)) goto invalid;
            break;
        case 10: o->stats_path = value; break;
        case 11: o->live_path = value; break;
        case 12:
            if (!number(value, 0, WORKER_MAX - 1, &o->worker_index)) goto invalid;
            break;
        case 13:
            if (!number(value, 1, WORKER_MAX, &o->worker_count)) goto invalid;
            break;
        case 14:
            if (!number(value, 0, 1, &parsed)) goto invalid;
            o->coordinated = parsed != 0; break;
        case 15:
            if (!number(value, 0, 1, &parsed)) goto invalid;
            o->software_dispatch = parsed != 0; break;
        case 16:
        case 17:
            if (!number(value, 1, 255, &parsed)) goto invalid;
            if (index == 16) o->ttl_min = (uint8_t)parsed;
            else o->ttl_max = (uint8_t)parsed;
            break;
        default: return -1;
        }
        continue;
invalid:
        fprintf(stderr, "Invalid value for %s: %s\n", key, value); return -1;
    }
    if (!role_seen || o->local_text == NULL || o->peer_text == NULL ||
        o->stats_path == NULL) {
        fputs("Role, local/peer lab IPs and stats path are required.\n", stderr);
        return -1;
    }
    if (o->worker_index >= o->worker_count || (o->worker_count > 1 && !o->coordinated)) {
        fputs("Worker index must be within its count; multiple workers require coordinated mode.\n", stderr);
        return -1;
    }
    if (((seen >> 16) & 1u) != ((seen >> 17) & 1u) || o->ttl_min > o->ttl_max) {
        fputs("Specify both TTL bounds with 1 <= ttl-min <= ttl-max <= 255.\n", stderr);
        return -1;
    }
    if (!((strcmp(o->local_text, "198.18.0.1") == 0 &&
           strcmp(o->peer_text, "198.18.0.2") == 0) ||
          (strcmp(o->local_text, "198.18.0.2") == 0 &&
           strcmp(o->peer_text, "198.18.0.1") == 0)) ||
        inet_pton(AF_INET, o->local_text, &o->local_ip) != 1 ||
        inet_pton(AF_INET, o->peer_text, &o->peer_ip) != 1) {
        fputs("Use the exact opposite 198.18.0.1/.2 lab addresses.\n", stderr);
        return -1;
    }
    if (o->stats_path[0] != '/' ||
        (o->live_path != NULL && (o->live_path[0] != '/' ||
         strcmp(o->stats_path, o->live_path) == 0))) {
        fputs("Output paths must be distinct absolute paths.\n", stderr); return -1;
    }
    return 0;
}

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static bool ttl_override(const struct session_app *app)
{
    return app->o.ttl_min != 64 || app->o.ttl_max != 64;
}

static uint8_t choose_ttl(struct session_app *app)
{
    if (app->o.ttl_min == app->o.ttl_max) return app->o.ttl_min;
    uint64_t value = app->ttl_rng;
    value ^= value >> 12; value ^= value << 25; value ^= value >> 27;
    app->ttl_rng = value;
    uint64_t random = (value * UINT64_C(2685821657736338717)) >> 32;
    uint64_t width = (uint64_t)app->o.ttl_max - app->o.ttl_min + 1u;
    /* Constant-time range scaling: lab variation, not cryptographic randomness.
     * The32-bit scaling has at most one count of rounding bias per2^32 draws. */
    return (uint8_t)((uint64_t)app->o.ttl_min + ((random * width) >> 32));
}

static void ttl_error(struct session_app *app)
{
    ++app->ttl_callback_errors;
    app->fatal = true;
}

/* Validate every segment touched before changing any bytes. Header fragments
 * may span segments, but shared/indirect/external buffers are never modified.
 * No allocation or linearization occurs in the transmit callback. */
static bool ttl_write_span(struct rte_mbuf *packet, uint32_t offset,
                           const uint8_t *bytes, uint32_t length, bool write)
{
    struct rte_mbuf *segment = packet;
    for (unsigned i = 0; segment != NULL && i < packet->nb_segs && i < 64u; ++i) {
        if (offset >= segment->data_len) {
            offset -= segment->data_len; segment = segment->next; continue;
        }
        uint32_t count = (uint32_t)segment->data_len - offset;
        if (count > length) count = length;
        if (rte_mbuf_refcnt_read(segment) != 1 || !RTE_MBUF_DIRECT(segment) ||
            RTE_MBUF_HAS_EXTBUF(segment)) return false;
        if (write) memcpy(rte_pktmbuf_mtod_offset(segment, uint8_t *, offset), bytes, count);
        bytes += count; length -= count; offset = 0;
        if (length == 0) return true;
        segment = segment->next;
    }
    return false;
}

static void ttl_packet(struct session_app *app, struct rte_mbuf *packet)
{
    uint8_t ethernet[14], header[60], tcp[20];
    const uint8_t *view;
    if (packet == NULL || (view = rte_pktmbuf_read(packet, 0, 14, ethernet)) == NULL) {
        ttl_error(app); return;
    }
    if (read_be16(view + 12) != UINT16_C(0x0800)) return;
    view = rte_pktmbuf_read(packet, 14, 20, header);
    if (view == NULL) { ttl_error(app); return; }
    if (view[9] != IPPROTO_TCP) return;
    bool addresses =
        (memcmp(view + 12, &app->o.local_ip.s_addr, 4) == 0 &&
         memcmp(view + 16, &app->o.peer_ip.s_addr, 4) == 0) ||
        (memcmp(view + 12, &app->o.peer_ip.s_addr, 4) == 0 &&
         memcmp(view + 16, &app->o.local_ip.s_addr, 4) == 0);
    if (!addresses) return;
    uint32_t ihl = (uint32_t)(view[0] & 15u) * 4u;
    uint32_t total = read_be16(view + 2);
    if ((view[0] >> 4) != 4 || ihl < 20 || ihl > sizeof(header) ||
        total < ihl + sizeof(tcp) || packet->pkt_len < 14u + total ||
        (read_be16(view + 6) & UINT16_C(0x3fff)) != 0) {
        ttl_error(app); return;
    }
    view = rte_pktmbuf_read(packet, 14u + ihl, (uint32_t)sizeof(tcp), tcp);
    if (view == NULL) { ttl_error(app); return; }
    if (read_be16(view) != app->o.port && read_be16(view + 2) != app->o.port) return;
    uint32_t tcp_length = (uint32_t)(view[12] >> 4) * 4u;
    if (tcp_length < sizeof(tcp) || tcp_length > total - ihl ||
        (packet->ol_flags & RTE_MBUF_F_TX_TCP_SEG) != 0) {
        ttl_error(app); return;
    }
    view = rte_pktmbuf_read(packet, 14, ihl, header);
    if (view == NULL) { ttl_error(app); return; }
    /* rte_pktmbuf_read may return the original contiguous data, not scratch. */
    if (view != header) memcpy(header, view, ihl);
    uint8_t ttl = choose_ttl(app);
    bool offload = (packet->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) != 0;
    if (header[8] != ttl || offload) {
        uint16_t checksum;
        if (offload) {
            header[8] = ttl; header[10] = header[11] = 0;
            uint32_t sum = 0;
            for (uint32_t i = 0; i < ihl; i += 2u) sum += read_be16(header + i);
            sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
            sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
            checksum = (uint16_t)~sum;
        } else {
            uint16_t old_word = (uint16_t)((uint16_t)header[8] << 8);
            uint16_t new_word = (uint16_t)((uint16_t)ttl << 8);
            uint32_t sum = (uint32_t)(uint16_t)~read_be16(header + 10) +
                           (uint32_t)(uint16_t)~old_word + new_word;
            sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
            sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
            checksum = (uint16_t)~sum;
        }
        const uint8_t patch[4] = {ttl, header[9], (uint8_t)(checksum >> 8), (uint8_t)checksum};
        if (!ttl_write_span(packet, 22, patch, 4, false) ||
            !ttl_write_span(packet, 22, patch, 4, true)) {
            ttl_error(app); return;
        }
        if (offload) packet->ol_flags &= ~((uint64_t)RTE_MBUF_F_TX_IP_CKSUM);
    }
    ++app->ttl_selections; ++app->ttl_histogram[ttl];
}

static uint16_t ttl_tx_callback(uint16_t port, uint16_t queue,
                                struct rte_mbuf *packets[], uint16_t count,
                                void *context)
{
    struct session_app *app = context;
    if (port != 0 || queue != app->o.worker_index || (count != 0 && packets == NULL)) {
        ttl_error(app); return count;
    }
    for (uint16_t i = 0; i < count; ++i) ttl_packet(app, packets[i]);
    return count;
}

static int prepare_ttl_callback(struct session_app *app)
{
    if (!ttl_override(app)) return 0;
    struct rte_eth_dev_info info;
    memset(&info, 0, sizeof(info));
    if (ff_global_cfg.dpdk.nb_ports != 1 || ff_global_cfg.dpdk.portid_list == NULL ||
        ff_global_cfg.dpdk.portid_list[0] != 0 || rte_eth_dev_info_get(0, &info) != 0 ||
        info.nb_tx_queues != app->o.worker_count || info.max_tx_queues < app->o.worker_count) {
        fputs("Per-packet TTL needs the owned initialized TX queue group.\n", stderr);
        ttl_error(app); return -1;
    }
    app->ttl_rng = monotonic_ns() ^ ((uint64_t)(unsigned)getpid() << 32) ^
        ((uint64_t)app->o.worker_index * UINT64_C(0x9e3779b97f4a7c15));
    if (app->ttl_rng == 0) app->ttl_rng = UINT64_C(0xd1b54a32d192ed03);
    app->ttl_callback = rte_eth_add_tx_callback(0, (uint16_t)app->o.worker_index,
                                               ttl_tx_callback, app);
    if (app->ttl_callback == NULL) {
        fputs("Could not install the owned per-packet TTL TX callback.\n", stderr);
        ttl_error(app); return -1;
    }
    return 0;
}

static void remove_ttl_callback(struct session_app *app)
{
    if (app->ttl_callback == NULL) return;
    if (rte_eth_remove_tx_callback(0, (uint16_t)app->o.worker_index, app->ttl_callback) != 0) {
        fputs("Could not unlink the owned TTL TX callback before EAL cleanup.\n", stderr);
        ttl_error(app);
        /* A still-linked callback must never be freed; EAL teardown owns it. */
    } else rte_free((void *)app->ttl_callback);
    app->ttl_callback = NULL;
}

/* A 12-byte IPv4/TCP tuple depends only on the first 16 RSS-key bytes.
 * These prefixes and their selection mirror the pinned F-Stack init_port_start
 * and ff_rss_check, not a NIC's unrelated default hash policy.
 * https://github.com/F-Stack/f-stack/blob/761639943bdda33103aa98241ca6a3079f1c1b7e/lib/ff_dpdk_if.c */
static uint32_t rss_tuple_hash(const uint8_t key[16], const uint8_t tuple[12])
{
    uint32_t window = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
                      ((uint32_t)key[2] << 8) | key[3];
    uint32_t hash = 0;
    for (unsigned i = 0; i < 12; ++i) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            if ((tuple[i] & (UINT32_C(0x80) >> bit)) != 0) hash ^= window;
            window = (window << 1) | (((uint32_t)key[i + 4] >> (7u - bit)) & UINT32_C(1));
        }
    }
    return hash;
}

static int dispatch_tcp(void *data, uint16_t *length, uint16_t queue,
                        uint16_t queues)
{
    const struct session_app *app = dispatch_context;
    if (app == NULL || data == NULL || length == NULL || queues == 0 ||
        queues != app->o.worker_count || queue >= queues)
        return FF_DISPATCH_ERROR;
    const uint8_t *frame = data;
    size_t available = *length;
    if (available < 14) return FF_DISPATCH_ERROR;
    /* Leave ARP and other Ethernet protocols on their original queue. This
     * preserves the library's ARP clone/broadcast handling. Generated sessions
     * use untagged IPv4; the dispatcher does not reinterpret VLAN frames. */
    if (read_be16(frame + 12) != UINT16_C(0x0800)) return (int)queue;
    if (available < 34) return FF_DISPATCH_ERROR;
    const uint8_t *ip = frame + 14;
    size_t header = (size_t)(ip[0] & 15u) * 4u;
    if ((ip[0] >> 4) != 4 || header < 20 || header > available - 14)
        return FF_DISPATCH_ERROR;
    if (ip[9] != IPPROTO_TCP) return (int)queue;
    size_t total = read_be16(ip + 2);
    if (total < header + 20 || (read_be16(ip + 6) & UINT16_C(0x3fff)) != 0 ||
        available - 14 - header < 20)
        return FF_DISPATCH_ERROR;
    const uint8_t *tcp = ip + header;
    size_t tcp_header = (size_t)(tcp[12] >> 4) * 4u;
    if (tcp_header < 20 || tcp_header > total - header) return FF_DISPATCH_ERROR;
    /* length describes only the first mbuf segment. Payload may be chained;
     * the FreeBSD stack validates the complete frame and checksums. Every byte
     * inspected here is within the bounded contiguous IPv4/TCP headers. */
    const struct in_addr *client = app->o.server ? &app->o.peer_ip : &app->o.local_ip;
    const struct in_addr *server = app->o.server ? &app->o.local_ip : &app->o.peer_ip;
    uint16_t client_port;
    if (memcmp(ip + 12, &client->s_addr, 4) == 0 &&
        memcmp(ip + 16, &server->s_addr, 4) == 0 && read_be16(tcp + 2) == app->o.port)
        client_port = read_be16(tcp);
    else if (memcmp(ip + 12, &server->s_addr, 4) == 0 &&
             memcmp(ip + 16, &client->s_addr, 4) == 0 && read_be16(tcp) == app->o.port)
        client_port = read_be16(tcp + 2);
    else return (int)queue;
    if (client_port == 0) return FF_DISPATCH_ERROR;
    /* Returning another queue uses F-Stack's existing shared dispatch ring.
     * Ring-delivered packets bypass this callback, preventing redispatch. */
    return (int)app->dispatch_owner[client_port];
}

static int prepare_software_dispatch(struct session_app *app)
{
    static const uint8_t key40[16] = {0xd1,0x81,0xc6,0x2c,0xf7,0xf4,0xdb,0x5b,
        0x19,0x83,0xa2,0xfc,0x94,0x3e,0x1a,0xdb};
    static const uint8_t key52[16] = {0x44,0x39,0x79,0x6b,0xb5,0x4c,0x50,0x23,
        0xb6,0x75,0xea,0x5b,0x12,0x4f,0x9f,0x30};
    static const uint8_t symmetric[16] = {0x6d,0x5a,0x6d,0x5a,0x6d,0x5a,0x6d,0x5a,
        0x6d,0x5a,0x6d,0x5a,0x6d,0x5a,0x6d,0x5a};
    struct rte_eth_dev_info info;
    memset(&info, 0, sizeof(info));
    /* Validate the initialized public device queue counts. ff_port_cfg's
     * private layout depends on the dependency's INET6 build flag. */
    if (ff_global_cfg.dpdk.nb_ports != 1 || ff_global_cfg.dpdk.portid_list == NULL ||
        ff_global_cfg.dpdk.portid_list[0] != 0 ||
        rte_eth_dev_info_get(0, &info) != 0 ||
        info.nb_rx_queues != app->o.worker_count || info.nb_tx_queues != app->o.worker_count ||
        info.max_rx_queues < app->o.worker_count ||
        info.max_tx_queues < app->o.worker_count ||
        (info.reta_size != 0 && info.reta_size < app->o.worker_count) ||
        (info.reta_size != 0 && (info.reta_size & (info.reta_size - 1u)) != 0)) {
        fputs("Software TCP dispatch needs one matching port/queue group and valid device RSS information.\n", stderr);
        return -1;
    }
    const uint8_t *key = key40;
    app->dispatch_key = "default40";
    if (info.flow_type_rss_offloads != 0) {
        if (info.hash_key_size == 52) { key = key52; app->dispatch_key = "default52"; }
        if (ff_global_cfg.dpdk.symmetric_rss) { key = symmetric; app->dispatch_key = "symmetric"; }
    }
    app->dispatch_reta_size = info.reta_size;
    uint8_t tuple[12] = {0};
    const struct in_addr *client = app->o.server ? &app->o.peer_ip : &app->o.local_ip;
    const struct in_addr *server = app->o.server ? &app->o.local_ip : &app->o.peer_ip;
    memcpy(tuple, &server->s_addr, 4); memcpy(tuple + 4, &client->s_addr, 4);
    tuple[8] = (uint8_t)(app->o.port >> 8); tuple[9] = (uint8_t)(app->o.port & 255u);
    uint32_t base = rss_tuple_hash(key, tuple), high[256], low[256];
    for (unsigned value = 0; value < 256; ++value) {
        tuple[10] = (uint8_t)value; tuple[11] = 0;
        high[value] = rss_tuple_hash(key, tuple) ^ base;
        tuple[10] = 0; tuple[11] = (uint8_t)value;
        low[value] = rss_tuple_hash(key, tuple) ^ base;
    }
    uint32_t mask = (uint32_t)info.reta_size - UINT32_C(1);
    for (uint32_t port = 0; port <= UINT16_MAX; ++port) {
        uint32_t hash = base ^ high[port >> 8] ^ low[port & 255u];
        app->dispatch_owner[port] = (uint8_t)((hash & mask) % app->o.worker_count);
    }
    dispatch_context = app;
    ff_regist_packet_dispatcher(dispatch_tcp);
    return 0;
}

/* Traverse pinned directory descriptors so no ancestor symlink can redirect a
 * root-run report. Writable root-owned sticky ancestors (/tmp) are permitted;
 * the immediate parent must be private and owned by the effective user. */
static int private_parent(const char *path, char name[NAME_MAX + 1])
{
    char copy[PATH_MAX];
    char *component, *next;
    int current;
    struct stat st;
    size_t length = strlen(path);
    if (length == 0 || length >= sizeof(copy) || path[0] != '/' ||
        path[length - 1] == '/') { errno = EINVAL; return -1; }
    memcpy(copy, path, length + 1);
    current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) return -1;
    component = copy + 1;
    for (;;) {
        next = strchr(component, '/');
        if (next == NULL) break;
        *next = '\0';
        if (*component == '\0' || strcmp(component, ".") == 0 ||
            strcmp(component, "..") == 0) { errno = EINVAL; goto bad; }
        int child = openat(current, component,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0) goto bad;
        (void)close(current); current = child;
        if (fstat(current, &st) != 0) goto bad;
        if ((st.st_uid != 0 && st.st_uid != geteuid()) ||
            ((st.st_mode & 0022) != 0 &&
             !(st.st_uid == 0 && (st.st_mode & S_ISVTX) != 0))) {
            errno = EPERM; goto bad;
        }
        component = next + 1;
    }
    if (*component == '\0' || strlen(component) > NAME_MAX ||
        strcmp(component, ".") == 0 || strcmp(component, "..") == 0) {
        errno = EINVAL; goto bad;
    }
    if (fstat(current, &st) != 0) goto bad;
    if (st.st_uid != geteuid() || (st.st_mode & 0022) != 0) {
        errno = EPERM; goto bad;
    }
    memcpy(name, component, strlen(component) + 1);
    return current;
bad:
    { int saved = errno; (void)close(current); errno = saved; }
    return -1;
}

static int open_output(struct output_file *out, const char *path)
{
    struct stat st;
    out->parent_fd = private_parent(path, out->name);
    if (out->parent_fd < 0) return -1;
    out->fd = openat(out->parent_fd, out->name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out->fd < 0) return -1;
    if (fstat(out->fd, &st) != 0) return -1;
    out->device = st.st_dev; out->inode = st.st_ino;
    return 0;
}

static void close_output(struct output_file *out)
{
    if (out->fd >= 0) { (void)close(out->fd); out->fd = -1; }
    if (out->parent_fd >= 0) {
        (void)close(out->parent_fd); out->parent_fd = -1;
    }
}

static int write_all(int fd, const char *data, size_t length)
{
    while (length > 0) {
        ssize_t n = write(fd, data, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        data += (size_t)n; length -= (size_t)n;
    }
    return 0;
}

static int format_json(const struct session_app *app, char *out, size_t size,
                       bool final)
{
    const struct session_options *o = &app->o;
    const struct measurement_snapshot *start = &app->measurement_start;
    const struct measurement_snapshot *end = &app->measurement_end;
    double elapsed = app->started != 0 ?
        (double)(app->now - app->started) / (double)PG_TCP_NS_PER_S : 0.0;
    char histogram[6144];
    size_t used = 0;
    histogram[used++] = '[';
    for (unsigned i = 0; i < 256; ++i) {
        int length = snprintf(histogram + used, sizeof(histogram) - used,
                              "%s%" PRIu64, i != 0 ? "," : "", app->ttl_histogram[i]);
        if (length < 0 || (size_t)length >= sizeof(histogram) - used) return -1;
        used += (size_t)length;
    }
    if (used + 2u > sizeof(histogram)) return -1;
    histogram[used++] = ']'; histogram[used] = '\0';
    int n = snprintf(out, size,
        "{\"mode\":\"tcp-sessions\",\"backend\":\"f-stack\","
        "\"fstack_commit\":\"761639943bdda33103aa98241ca6a3079f1c1b7e\","
        "\"role\":\"%s\",\"state\":\"%s\",\"stop_reason\":\"%s\","
        "\"local_ip\":\"%s\",\"peer_ip\":\"%s\",\"port\":%u,"
        "\"connections\":%u,\"concurrency\":%u,\"requested_cps\":%u,\"unpaced\":%s,"
        "\"worker_index\":%u,\"worker_count\":%u,\"coordinated\":%s,"
        "\"software_dispatch\":%s,\"software_dispatch_key\":\"%s\",\"software_dispatch_reta_size\":%u,"
        "\"ttl_min\":%u,\"ttl_max\":%u,\"ttl_policy\":\"per-packet\",\"ttl_callback_active\":%s,"
        "\"ttl_selections\":%" PRIu64 ",\"ttl_callback_errors\":%" PRIu64 ",\"ttl_histogram\":%s,"
        "\"payload_bytes\":%u,\"elapsed_seconds\":%.9f,"
        "\"attempted\":%" PRIu64 ",\"connected\":%" PRIu64 ","
        "\"completed\":%" PRIu64 ",\"failed\":%" PRIu64 ","
        "\"active\":%" PRIu64 ",\"bytes_sent\":%" PRIu64 ","
        "\"bytes_received\":%" PRIu64 ",\"verified_bytes\":%" PRIu64 ","
        "\"rejected_peers\":%" PRIu64 ",\"connect_errors\":%" PRIu64 ","
        "\"io_errors\":%" PRIu64 ",\"protocol_errors\":%" PRIu64 ","
        "\"timeouts\":%" PRIu64 ",\"aborted\":%" PRIu64 ","
        "\"live_report_error\":%s,\"measurement\":{"
        "\"application_started_monotonic_ns\":%" PRIu64 ","
        "\"nominal_start_after_seconds\":1,\"nominal_end_after_seconds\":11,"
        "\"start\":{\"available\":%s,\"monotonic_ns\":%" PRIu64 ","
        "\"completed\":%" PRIu64 ",\"attempted\":%" PRIu64 ","
        "\"failed\":%" PRIu64 ",\"verified_bytes\":%" PRIu64 "},"
        "\"end\":{\"available\":%s,\"monotonic_ns\":%" PRIu64 ","
        "\"completed\":%" PRIu64 ",\"attempted\":%" PRIu64 ","
        "\"failed\":%" PRIu64 ",\"verified_bytes\":%" PRIu64 "}}}\n",
        o->server ? "server" : "client",
        final || app->fatal ? (app->fatal ? "error" : "stopped") :
            (app->stopping ? (o->coordinated && app->now >= app->drain_until &&
             app->active == 0 && !interrupted && !app->fatal ? "quiescent" : "draining") :
             (app->started == 0 ? "waiting" : "running")),
        app->reason, o->local_text, o->peer_text, (unsigned)o->port,
        o->connections, o->concurrency, o->cps, o->cps == 0 ? "true" : "false",
        o->worker_index, o->worker_count, o->coordinated ? "true" : "false",
        o->software_dispatch ? "true" : "false", app->dispatch_key,
        (unsigned)app->dispatch_reta_size,
        (unsigned)o->ttl_min, (unsigned)o->ttl_max, ttl_override(app) ? "true" : "false",
        app->ttl_selections, app->ttl_callback_errors, histogram,
        o->payload_size, elapsed,
        app->attempted, app->connected, app->completed, app->failed, app->active,
        app->bytes_sent, app->bytes_received, app->verified_bytes,
        app->rejected_peers, app->connect_errors, app->io_errors,
        app->protocol_errors, app->timeouts, app->aborted,
        app->live_failed ? "true" : "false", app->started,
        start->monotonic_ns != 0 ? "true" : "false", start->monotonic_ns,
        start->completed, start->attempted, start->failed, start->verified_bytes,
        end->monotonic_ns != 0 ? "true" : "false", end->monotonic_ns,
        end->completed, end->attempted, end->failed, end->verified_bytes);
    return n >= 0 && (size_t)n < size ? n : -1;
}

static int publish_live(struct session_app *app, bool final)
{
    struct output_file *out = &app->live;
    struct stat current, pinned, replacement;
    char data[SESSION_JSON_SIZE], temp[NAME_MAX + 1];
    int n, fd, result = -1;
    if (out->parent_fd < 0) return 0;
    n = format_json(app, data, sizeof(data), final);
    if (n < 0) return -1;
    /* Keep the currently published inode open. A numeric inode check alone
     * permits ABA if another file replaces an unlinked report and reuses its
     * inode number. The held descriptor prevents that inode from being reused. */
    if (out->fd < 0 || fstat(out->fd, &pinned) != 0 ||
        fstatat(out->parent_fd, out->name, &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(current.st_mode) || !S_ISREG(pinned.st_mode) ||
        current.st_uid != geteuid() || pinned.st_uid != geteuid() ||
        pinned.st_dev != out->device || pinned.st_ino != out->inode ||
        current.st_dev != pinned.st_dev || current.st_ino != pinned.st_ino) {
        errno = ESTALE; return -1;
    }
    int temp_length = snprintf(temp, sizeof(temp), ".pg-tcp-live-%ld.tmp", (long)getpid());
    if (temp_length < 0 || (size_t)temp_length >= sizeof(temp)) return -1;
    fd = openat(out->parent_fd, temp,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (write_all(fd, data, (size_t)n) == 0 && fstat(fd, &replacement) == 0 &&
        renameat(out->parent_fd, temp, out->parent_fd, out->name) == 0) {
        out->device = replacement.st_dev; out->inode = replacement.st_ino;
        (void)close(out->fd);
        out->fd = fd; fd = -1;
        result = 0;
    }
    if (fd >= 0) (void)close(fd);
    if (result != 0) (void)unlinkat(out->parent_fd, temp, 0);
    return result;
}

static uint8_t payload_byte(uint64_t id, size_t offset)
{
    static const uint8_t tag[8] = {'P', 'G', 'T', 'C', 'P', 'v', '1', 0};
    if (offset < sizeof(tag)) return tag[offset];
    if (offset < 16) return (uint8_t)(id >> ((15u - offset) * 8u));
    uint64_t value = id ^ ((uint64_t)offset * UINT64_C(0x9e3779b97f4a7c15));
    value ^= value >> 29; value *= UINT64_C(0xbf58476d1ce4e5b9);
    return (uint8_t)(value ^ (value >> 32));
}

static bool valid_request(const uint8_t *data, size_t length)
{
    uint64_t id = 0;
    for (size_t i = 0; i < length && i < 8; ++i)
        if (data[i] != payload_byte(0, i)) return false;
    if (length < 16) return true;
    for (size_t i = 8; i < 16; ++i) id = (id << 8) | data[i];
    for (size_t i = 16; i < length; ++i)
        if (data[i] != payload_byte(id, i)) return false;
    return true;
}

static bool would_block(void)
{
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

static int new_socket(void)
{
    int fd = ff_socket(AF_INET, SOCK_STREAM, 0), enabled = 1;
    if (fd < 0) return -1;
    if (ff_ioctl(fd, FIONBIO, &enabled) != 0 ||
        ff_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled,
                      (socklen_t)sizeof(enabled)) != 0) {
        int saved = errno; (void)ff_close(fd); errno = saved; return -1;
    }
    return fd;
}

static struct sockaddr_in address(struct in_addr ip, uint16_t port)
{
    struct sockaddr_in out;
    memset(&out, 0, sizeof(out));
    out.sin_family = AF_INET; out.sin_addr = ip; out.sin_port = htons(port);
    return out;
}

static void finish_connection(struct session_app *app, struct connection *c,
                              uint64_t *failure)
{
    (void)ff_close(c->fd); c->fd = -1;
    --app->active;
    if (failure != NULL) { ++*failure; ++app->failed; }
    else { ++app->completed; app->verified_bytes += app->o.payload_size; }
}

static struct connection *free_slot(struct session_app *app)
{
    for (uint32_t i = 0; i < app->o.concurrency; ++i) {
        uint32_t index = app->next_slot;
        if (++app->next_slot == app->o.concurrency) app->next_slot = 0;
        if (app->c[index].fd < 0) return &app->c[index];
    }
    return NULL;
}

static void start_client(struct session_app *app)
{
    struct connection *c = free_slot(app);
    struct sockaddr_in local = address(app->o.local_ip, 0);
    struct sockaddr_in peer = address(app->o.peer_ip, app->o.port);
    if (c == NULL) return;
    ++app->attempted;
    *c = (struct connection){.fd = -1, .id = app->attempted, .opened = app->now};
    c->fd = new_socket();
    if (c->fd < 0) { ++app->connect_errors; ++app->failed; return; }
    ++app->active;
    for (size_t i = 0; i < app->o.payload_size; ++i)
        c->bytes[i] = payload_byte(c->id, i);
    if (ff_bind(c->fd, (const struct linux_sockaddr *)(const void *)&local,
                (socklen_t)sizeof(local)) != 0) {
        finish_connection(app, c, &app->connect_errors); return;
    }
    int result = ff_connect(c->fd,
        (const struct linux_sockaddr *)(const void *)&peer, (socklen_t)sizeof(peer));
    if (result == 0) ++app->connected;
    else if (errno == EINPROGRESS || errno == EALREADY || would_block())
        c->connecting = true;
    else finish_connection(app, c, &app->connect_errors);
}

static void accept_clients(struct session_app *app)
{
    /* A callback has a fixed accept budget and never starves established I/O. */
    for (unsigned budget = 0; budget < CONNECTION_BUDGET &&
         app->active < app->o.concurrency &&
         app->attempted < app->o.connections; ++budget) {
        struct sockaddr_in peer;
        socklen_t length = (socklen_t)sizeof(peer);
        memset(&peer, 0, sizeof(peer));
        int fd = ff_accept(app->listener,
            (struct linux_sockaddr *)(void *)&peer, &length);
        if (fd < 0) {
            if (!would_block()) { ++app->io_errors; app->fatal = true; }
            break;
        }
        if (length != sizeof(peer) || peer.sin_family != AF_INET ||
            peer.sin_addr.s_addr != app->o.peer_ip.s_addr) {
            ++app->rejected_peers; (void)ff_close(fd); continue;
        }
        struct connection *c = free_slot(app);
        if (c == NULL) { (void)ff_close(fd); break; }
        ++app->attempted; ++app->connected; ++app->active;
        *c = (struct connection){.fd = fd, .id = app->attempted, .opened = app->now};
        int enabled = 1;
        if (ff_ioctl(fd, FIONBIO, &enabled) != 0 ||
            ff_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled,
                          (socklen_t)sizeof(enabled)) != 0)
            finish_connection(app, c, &app->io_errors);
    }
}

static bool connected_client(struct session_app *app, struct connection *c)
{
    struct pollfd pollfd = {.fd = c->fd, .events = POLLOUT};
    int ready = ff_poll(&pollfd, 1, 0);
    if (ready < 0 && would_block()) return false;
    if (ready < 0) { finish_connection(app, c, &app->connect_errors); return false; }
    if (ready == 0) return false;
    int error = 0;
    socklen_t error_length = (socklen_t)sizeof(error);
    struct sockaddr_in peer;
    socklen_t peer_length = (socklen_t)sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    if ((pollfd.revents & POLLNVAL) != 0 ||
        ff_getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &error, &error_length) != 0 ||
        error_length != sizeof(error) || error != 0 ||
        ff_getpeername(c->fd, (struct linux_sockaddr *)(void *)&peer,
                       &peer_length) != 0 || peer_length != sizeof(peer) ||
        peer.sin_family != AF_INET ||
        peer.sin_addr.s_addr != app->o.peer_ip.s_addr ||
        peer.sin_port != htons(app->o.port)) {
        finish_connection(app, c, &app->connect_errors); return false;
    }
    c->connecting = false; ++app->connected; return true;
}

static void service_connection(struct session_app *app, struct connection *c)
{
    size_t payload = app->o.payload_size;
    if (app->now - c->opened >= (uint64_t)app->o.timeout_s * PG_TCP_NS_PER_S) {
        finish_connection(app, c, &app->timeouts); return;
    }
    if (c->connecting && !connected_client(app, c)) return;
    /* The client half-closes after its request. The server waits for that EOF
     * before echoing, so truncated/oversized requests cannot count as success. */
    if ((!app->o.server || c->read_eof) && c->sent < payload) {
        ssize_t n = ff_send(c->fd, c->bytes + c->sent, payload - c->sent, 0);
        if (n > 0 && (size_t)n <= payload - c->sent) {
            c->sent += (size_t)n; app->bytes_sent += (uint64_t)n;
        } else if (n == 0 || (n < 0 && !would_block()) ||
                   (n > 0 && (size_t)n > payload - c->sent)) {
            finish_connection(app, c, &app->io_errors); return;
        }
    }
    if (c->sent == payload && !c->write_shutdown) {
        if (ff_shutdown(c->fd, SHUT_WR) != 0) {
            if (would_block()) return;
            finish_connection(app, c, &app->io_errors); return;
        }
        c->write_shutdown = true;
    }
    for (unsigned budget = 0; budget < 4 && !c->read_eof; ++budget) {
        uint8_t received[PAYLOAD_MAX];
        size_t room = payload - c->received;
        /* A one-byte read after the expected length detects unexpected tails. */
        ssize_t n = ff_recv(c->fd, received, room > 0 ? room : 1, 0);
        if (n < 0) {
            if (would_block()) break;
            finish_connection(app, c, &app->io_errors); return;
        }
        if (n == 0) {
            c->read_eof = true;
            if (c->received != payload ||
                (app->o.server && !valid_request(c->bytes, payload))) {
                finish_connection(app, c, &app->protocol_errors); return;
            }
            break;
        }
        app->bytes_received += (uint64_t)n;
        if ((size_t)n > room) {
            finish_connection(app, c, &app->protocol_errors); return;
        }
        if (app->o.server) memcpy(c->bytes + c->received, received, (size_t)n);
        else if (memcmp(c->bytes + c->received, received, (size_t)n) != 0) {
            finish_connection(app, c, &app->protocol_errors); return;
        }
        c->received += (size_t)n;
    }
    if (c->read_eof && c->write_shutdown && c->sent == payload)
        finish_connection(app, c, NULL);
}

static void request_stop(struct session_app *app, const char *reason)
{
    if (app->stopping) return;
    app->stopping = true; app->reason = reason;
    app->drain_until = app->now + DRAIN_NS;
    if (app->listener >= 0) { (void)ff_close(app->listener); app->listener = -1; }
}

static void periodic_live(struct session_app *app)
{
    if (app->now < app->next_live) return;
    if (publish_live(app, false) != 0 && !app->live_failed) {
        perror("live JSON publication"); app->live_failed = true;
    }
    app->next_live = app->now + PG_TCP_NS_PER_S;
}

static void capture_measurement(struct session_app *app)
{
    if (app->started == 0 || app->stopping) return;
    bool need_start = app->measurement_start.monotonic_ns == 0 &&
        app->now - app->started >= PG_TCP_NS_PER_S;
    bool need_end = app->measurement_end.monotonic_ns == 0 &&
        app->now - app->started >= 11u * PG_TCP_NS_PER_S;
    if (!need_start && !need_end) return;
    struct measurement_snapshot snapshot = {.monotonic_ns = app->now,
        .completed = app->completed, .attempted = app->attempted,
        .failed = app->failed, .verified_bytes = app->verified_bytes};
    if (need_start) app->measurement_start = snapshot;
    if (need_end) app->measurement_end = snapshot;
}

static int session_loop(void *argument)
{
    struct session_app *app = argument;
    app->now = monotonic_ns();
    if (app->started == 0 && !interrupted && !app->fatal) {
        if (!start_requested) { periodic_live(app); return 0; }
        app->started = app->now; app->next_attempt = app->now;
        app->next_live = app->now; app->reason = "running";
    }
    if (interrupted) request_stop(app, "signal");
    else if (app->fatal) request_stop(app, "io-error");
    else if (app->now - app->started >= (uint64_t)app->o.duration_s * PG_TCP_NS_PER_S)
        request_stop(app, "duration");

    /* Service established sockets before admitting another bounded batch, so
     * maximum-rate connection starts cannot starve payload/FIN processing.
     * F-Stack regains control after every callback to run its TCP timers/I/O. */
    for (uint32_t i = 0; i < app->o.concurrency; ++i)
        if (app->c[i].fd >= 0) service_connection(app, &app->c[i]);
    app->now = monotonic_ns();
    capture_measurement(app);
    if (!app->stopping) {
        if (interrupted) request_stop(app, "signal");
        else if (app->now - app->started >= (uint64_t)app->o.duration_s * PG_TCP_NS_PER_S)
            request_stop(app, "duration");
    }
    if (!app->stopping) {
        if (app->o.server) accept_clients(app);
        else for (unsigned budget = 0; budget < CONNECTION_BUDGET &&
                  app->attempted < app->o.connections &&
                  app->active < app->o.concurrency; ++budget) {
            app->now = monotonic_ns();
            if (interrupted) { request_stop(app, "signal"); break; }
            if (app->now - app->started >= (uint64_t)app->o.duration_s * PG_TCP_NS_PER_S) {
                request_stop(app, "duration"); break;
            }
            if (app->o.cps != 0 && app->now < app->next_attempt) break;
            start_client(app);
            /* Positive rates schedule from the actual attempt; missed slots
             * never accumulate into catch-up bursts. Zero explicitly removes
             * pacing, without division by zero or a one-start-per-loop cap. */
            if (app->o.cps != 0)
                app->next_attempt = app->now + PG_TCP_NS_PER_S / app->o.cps;
        }
    }
    if (!app->stopping && app->attempted >= app->o.connections && app->active == 0)
        request_stop(app, "quota");
    app->now = monotonic_ns();
    periodic_live(app);
    if (app->stopping && app->now >= app->drain_until) {
        for (uint32_t i = 0; i < app->o.concurrency; ++i)
            if (app->c[i].fd >= 0) finish_connection(app, &app->c[i], &app->aborted);
        /* Each process owns its TCP context, but secondary DPDK processes
         * share the primary's NIC and memory. The supervisor keeps completed
         * workers polling until it can stop secondaries before the primary. */
        if (!app->o.coordinated || interrupted) {
            /* ff_run tears down EAL before it returns. Only this polling
             * thread uses the queue, so unlink/free its callback right here. */
            remove_ttl_callback(app);
            ff_stop_run();
        }
    }
    return 0;
}

static int listen_server(struct session_app *app)
{
    struct sockaddr_in local = address(app->o.local_ip, app->o.port);
    app->listener = new_socket();
    if (app->listener < 0) return -1;
    if (ff_bind(app->listener,
                (const struct linux_sockaddr *)(const void *)&local,
                (socklen_t)sizeof(local)) != 0 ||
        ff_listen(app->listener, (int)app->o.concurrency) != 0) return -1;
    return 0;
}

int main(int argc, char **argv)
{
    int separator = -1, exit_status = EXIT_FAILURE;
    bool initialized = false, loop_entered = false;
    struct session_app *app = calloc(1, sizeof(*app));
    if (app == NULL) { perror("allocate sessions"); return EXIT_FAILURE; }
    app->listener = -1; app->reason = "initialization"; app->dispatch_key = "disabled";
    app->stats.fd = app->stats.parent_fd = app->live.fd = app->live.parent_fd = -1;
    for (unsigned i = 0; i < SESSION_MAX; ++i) app->c[i].fd = -1;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) { separator = i; break; }
        if (strcmp(argv[i], "--help") == 0) {
            usage(stdout); free(app); return EXIT_SUCCESS;
        }
    }
    if (separator < 0) { usage(stderr); goto done; }
    int parsed = parse_options(argc - separator - 1, argv + separator + 1, &app->o);
    if (parsed != 0) { exit_status = parsed > 0 ? EXIT_SUCCESS : EXIT_FAILURE; goto done; }
    if (open_output(&app->stats, app->o.stats_path) != 0) {
        perror("create exclusive statistics report"); goto done;
    }
    if (app->o.live_path != NULL && open_output(&app->live, app->o.live_path) != 0) {
        perror("create exclusive live report"); app->fatal = true; goto report;
    }
    /* Application arguments never reach F-Stack's config/EAL argument parser. */
    argv[separator] = NULL;
    if (ff_init(separator, argv) != 0) {
        fputs("F-Stack initialization failed.\n", stderr); app->fatal = true; goto report;
    }
    initialized = true;
    if (rte_lcore_count() != 1) {
        fputs("TCP session mode requires exactly one enabled DPDK lcore.\n", stderr);
        app->fatal = true; goto report;
    }
    if (ff_global_cfg.dpdk.proc_id < 0 || ff_global_cfg.dpdk.nb_procs < 1 ||
        (uint32_t)ff_global_cfg.dpdk.proc_id != app->o.worker_index ||
        (uint32_t)ff_global_cfg.dpdk.nb_procs != app->o.worker_count ||
        ff_global_cfg.dpdk.proc_lcore == NULL ||
        ff_global_cfg.dpdk.proc_lcore[app->o.worker_index] != rte_lcore_id()) {
        fputs("F-Stack process index/count/core does not match this application worker.\n", stderr);
        app->fatal = true; goto report;
    }
    /* Install after dependency initialization so its defaults cannot replace
     * the application's bounded graceful-stop handlers. */
    struct sigaction action;
    memset(&action, 0, sizeof(action)); action.sa_handler = on_signal;
    (void)sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        perror("install signal handlers"); app->fatal = true; goto report;
    }
    action.sa_handler = on_start;
    if (sigaction(SIGUSR1, &action, NULL) != 0) {
        perror("install coordinated start handler"); app->fatal = true; goto report;
    }
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL) != 0) {
        perror("ignore SIGPIPE"); app->fatal = true; goto report;
    }
    if (app->o.software_dispatch && prepare_software_dispatch(app) != 0) {
        app->fatal = true; goto report;
    }
    if (prepare_ttl_callback(app) != 0) goto report;
    if (app->o.server && listen_server(app) != 0) {
        perror("F-Stack listen"); app->fatal = true;
        if (app->listener >= 0) { (void)ff_close(app->listener); app->listener = -1; }
        goto report;
    }
    app->now = monotonic_ns();
    app->started = app->o.coordinated ? 0 : app->now; app->next_attempt = app->now;
    app->next_live = app->now; app->reason = app->o.coordinated ? "waiting" : "running";
    if (publish_live(app, false) != 0) { perror("initial live JSON"); app->live_failed = true; }
    printf("READY role=%s backend=F-Stack local=%s peer=%s port=%u "
           "quota=%u concurrency=%u cps=%u unpaced=%s payload=%u worker=%u/%u coordinated=%s\n",
        app->o.server ? "server" : "client", app->o.local_text, app->o.peer_text,
        (unsigned)app->o.port, app->o.connections, app->o.concurrency,
        app->o.cps, app->o.cps == 0 ? "true" : "false", app->o.payload_size,
        app->o.worker_index, app->o.worker_count, app->o.coordinated ? "true" : "false");
    (void)fflush(stdout);
    loop_entered = true;
    ff_run(session_loop, app);
    app->now = monotonic_ns();
    if (app->listener >= 0) { (void)ff_close(app->listener); app->listener = -1; }
    for (unsigned i = 0; i < SESSION_MAX; ++i)
        if (app->c[i].fd >= 0) finish_connection(app, &app->c[i], &app->aborted);
    /* A duration is a legitimate stopping bound. It need not consume the
     * larger safety quota, but every attempted session must still complete. */
    exit_status = !app->fatal && !app->live_failed && app->failed == 0 &&
        app->active == 0 && app->completed == app->attempted &&
        (app->completed == app->o.connections || strcmp(app->reason, "duration") == 0 ||
         (app->o.coordinated && strcmp(app->reason, "signal") == 0))
        ? EXIT_SUCCESS : EXIT_FAILURE;
report:
    {
        char data[SESSION_JSON_SIZE];
        /* The pinned ff_run() cleans up EAL before returning. Setup failures
         * after a successful ff_init() never enter that function, so release
         * only our F-Stack descriptors first and clean up EAL here instead. */
        if (initialized && !loop_entered) {
            if (app->listener >= 0) {
                (void)ff_close(app->listener); app->listener = -1;
            }
            for (unsigned i = 0; i < SESSION_MAX; ++i)
                if (app->c[i].fd >= 0)
                    finish_connection(app, &app->c[i], &app->aborted);
            remove_ttl_callback(app);
            if (rte_eal_cleanup() != 0) {
                fputs("DPDK EAL cleanup failed after TCP setup failure.\n", stderr);
                app->fatal = true; exit_status = EXIT_FAILURE;
            }
        }
        if (publish_live(app, true) != 0) {
            perror("final live JSON publication"); app->live_failed = true;
            exit_status = EXIT_FAILURE;
        }
        int length = format_json(app, data, sizeof(data), true);
        if (length < 0 || write_all(app->stats.fd, data, (size_t)length) != 0) {
            perror("write final statistics report"); exit_status = EXIT_FAILURE;
        }
        printf("TCP sessions: attempted=%" PRIu64 " connected=%" PRIu64
               " completed=%" PRIu64 " failed=%" PRIu64
               " verified-bytes=%" PRIu64 " stop=%s\n",
            app->attempted, app->connected, app->completed, app->failed,
            app->verified_bytes, app->reason);
    }
done:
    if (dispatch_context == app) {
        ff_regist_packet_dispatcher(NULL); dispatch_context = NULL;
    }
    close_output(&app->live); close_output(&app->stats); free(app);
    return exit_status;
}
