#define _GNU_SOURCE
#include "options.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_pause.h>

#define STREAM_BURST 256u
#define STREAM_HISTORY 256u
#define CONTROL_CLIENTS 8u
static volatile sig_atomic_t stream_interrupted;
static void stream_signal(int number) { (void)number; stream_interrupted = 1; }

struct stream_summary {
    struct pg_stream_spec spec;
    uint64_t id, submitted, released, bytes, tx_calls, backpressure, allocation_retries;
    uint32_t sequence;
    bool removed, tx_stalled;
};

/* The main lcore exclusively owns every stream, command and pending mbuf.
 * Control is serviced between bounded bursts; no application state is shared
 * with a control thread and no packet-path locks or allocations are needed. */
struct stream_tx {
    struct stream_summary sum;
    struct pg_packet_template *templates;
    struct rte_mbuf *pending[STREAM_BURST];
    uint16_t pending_count, offset, frame_length;
    uint64_t rng, next_due, retry_at, last_progress;
    double fractional_ticks;
    bool used, allocation_stalled;
};

struct stream_context {
    const struct pg_options *options;
    struct pg_packet_config base;
    struct rte_mempool *pool;
    struct stream_tx streams[PG_MAX_STREAMS];
    struct stream_summary history[STREAM_HISTORY];
    unsigned history_count, additions, cursor;
    uint64_t hz, next_id, submitted, released, bytes, commands;
    uint64_t start, end, start_unix, end_unix, deadline;
    int listener, parent_fd, clients[CONTROL_CLIENTS];
    char socket_name[108];
    unsigned lcore;
    uint64_t client_deadline[CONTROL_CLIENTS];
    dev_t socket_device;
    ino_t socket_inode;
    bool socket_owned, stop, failed;
    bool hardware_available;
    uint16_t effective_descriptors;
    struct rte_eth_stats hardware;
    const char *reason;
};

static uint64_t stream_unix_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static const char *protocol_name(enum pg_protocol protocol)
{ return protocol == PG_UDP ? "udp" : protocol == PG_TCP ? "tcp" : "icmp"; }

static void summary_json(FILE *out, const struct stream_summary *s)
{
    bool complete = s->submitted >= s->spec.count;
    const char *state = s->removed ? "removed" : s->spec.paused ? "paused" :
                        complete ? "complete" : s->tx_stalled ? "backpressure" : "running";
    fprintf(out, "{\"id\":%" PRIu64 ",\"name\":\"%s\",\"protocol\":\"%s\","
            "\"pps\":%" PRIu64 ",\"unlimited\":%s,\"quota\":%" PRIu64 ","
            "\"submitted\":%" PRIu64 ",\"released\":%" PRIu64 ",\"bytes\":%" PRIu64 ","
            "\"paused\":%s,\"complete\":%s,\"state\":\"%s\","
            "\"payload_bytes\":%u,\"ttl_min\":%u,\"ttl_max\":%u,\"seed\":%" PRIu64 ","
            "\"tx_calls\":%" PRIu64 ",\"backpressure_events\":%" PRIu64 ","
            "\"allocation_retries\":%" PRIu64 ",\"tcp_profile\":\"%s\",\"tcp_ack\":%" PRIu32 "}",
            s->id, s->spec.name, protocol_name(s->spec.protocol), s->spec.pps,
            s->spec.unlimited ? "true" : "false", s->spec.count, s->submitted,
            s->released, s->bytes, s->spec.paused ? "true" : "false",
            complete ? "true" : "false", state, (unsigned)s->spec.payload_size,
            (unsigned)s->spec.ttl_min, (unsigned)s->spec.ttl_max, s->spec.seed,
            s->tx_calls, s->backpressure, s->allocation_retries,
            s->spec.protocol == PG_TCP ? pg_tcp_flags_name(s->spec.tcp_flags) : "",
            s->spec.tcp_ack);
}

static void streams_json(FILE *out, const struct stream_context *c, bool retired)
{
    bool comma = false;
    fputc('[', out);
    if (retired) for (unsigned i = 0; i < c->history_count; ++i) {
        if (comma) fputc(',', out);
        summary_json(out, &c->history[i]);
        comma = true;
    }
    for (unsigned i = 0; i < PG_MAX_STREAMS; ++i) if (c->streams[i].used) {
        if (comma) fputc(',', out);
        summary_json(out, &c->streams[i].sum);
        comma = true;
    }
    fputc(']', out);
}

static void release_pending(struct stream_context *c, struct stream_tx *s)
{
    if (s->pending_count > s->offset) {
        uint16_t count = (uint16_t)(s->pending_count - s->offset);
        rte_pktmbuf_free_bulk(s->pending + s->offset, count);
        s->sum.released += count;
        c->released += count;
    }
    s->pending_count = s->offset = 0;
    s->allocation_stalled = false;
}

static struct pg_packet_template *make_templates(const struct stream_context *c,
                                                 const struct pg_stream_spec *spec)
{
    size_t count = (size_t)spec->ttl_max - spec->ttl_min + 1u;
    struct pg_packet_template *templates = calloc(count, sizeof(*templates));
    if (!templates) return NULL;
    struct pg_packet_config packet = c->base;
    packet.protocol = spec->protocol;
    packet.tcp_flags = spec->tcp_flags;
    packet.tcp_ack = spec->tcp_ack;
    packet.payload_size = spec->payload_size;
    for (size_t i = 0; i < count; ++i) {
        packet.ttl = (uint8_t)(spec->ttl_min + i);
        if (pg_packet_template_init(&templates[i], &packet, NULL, 0)) {
            free(templates);
            return NULL;
        }
    }
    return templates;
}

static struct stream_tx *find_stream(struct stream_context *c, const char *name)
{
    for (unsigned i = 0; i < PG_MAX_STREAMS; ++i)
        if (c->streams[i].used && !strcmp(c->streams[i].sum.spec.name, name))
            return &c->streams[i];
    return NULL;
}

static const char *add_stream(struct stream_context *c, const struct pg_stream_spec *spec, uint64_t now)
{
    if (find_stream(c, spec->name)) return "Stream name already exists";
    if (c->additions == STREAM_HISTORY) return "Session limit of 256 stream generations reached";
    struct stream_tx *slot = NULL;
    for (unsigned i = 0; i < PG_MAX_STREAMS; ++i)
        if (!c->streams[i].used) { slot = &c->streams[i]; break; }
    if (!slot) return "At most 16 streams can be active";
    struct pg_stream_spec prepared = *spec;
    if (!prepared.explicit_ttl) {
        prepared.ttl_min = c->options->ttl_min;
        prepared.ttl_max = c->options->ttl_max;
    }
    if (!prepared.explicit_seed && c->options->explicit_seed) {
        prepared.seed = c->options->seed + c->additions;
        if (!prepared.seed) prepared.seed = 1;
    }
    struct pg_packet_template *templates = make_templates(c, &prepared);
    if (!templates) return "Cannot prepare stream templates";
    memset(slot, 0, sizeof(*slot));
    slot->sum.spec = prepared;
    slot->sum.id = ++c->next_id;
    slot->templates = templates;
    slot->frame_length = (uint16_t)templates[0].length;
    slot->rng = prepared.seed;
    slot->next_due = slot->last_progress = now;
    slot->used = true;
    ++c->additions;
    return NULL;
}

static int create_control(struct stream_context *c)
{
    const char *path = c->options->control_socket;
    if (!path) return 0;
    struct sockaddr_un address = {0};
    if (strlen(path) >= sizeof(address.sun_path)) return -1;
    char parent[sizeof(address.sun_path)];
    strcpy(parent, path);
    char *slash = strrchr(parent, '/');
    if (!slash) return -1;
    strcpy(c->socket_name, slash + 1);
    if (!c->socket_name[0] || !strcmp(c->socket_name, ".") || !strcmp(c->socket_name, "..")) return -1;
    if (slash == parent) parent[1] = '\0'; else *slash = '\0';
    struct stat info;
    int directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return -1;
    char *part = parent + 1;
    while (*part) {
        char *next = strchr(part, '/');
        if (next) *next = '\0';
        if (!*part || !strcmp(part, ".") || !strcmp(part, "..")) { close(directory); return -1; }
        int child = openat(directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(directory);
        if (child < 0) return -1;
        directory = child;
        if (fstat(directory, &info) ||
            (info.st_uid != 0 && info.st_uid != geteuid()) ||
            ((info.st_mode & 0022) && !(info.st_uid == 0 && (info.st_mode & S_ISVTX)))) {
            close(directory);
            return -1;
        }
        if (!next) break;
        part = next + 1;
    }
    c->parent_fd = directory;
    if (fstat(directory, &info) || info.st_uid != geteuid() ||
        (info.st_mode & 0022)) {
        fprintf(stderr, "Control parent must be owned by the process user and not group/world writable\n");
        return -1;
    }
    if (!fstatat(directory, c->socket_name, &info, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) {
        fprintf(stderr, "Control path already exists or cannot be inspected\n");
        return -1;
    }
    c->listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (c->listener < 0) return -1;
    address.sun_family = AF_UNIX;
    int written = snprintf(address.sun_path, sizeof(address.sun_path), "/proc/self/fd/%d/%s",
                           directory, c->socket_name);
    if (written < 0 || (size_t)written >= sizeof(address.sun_path)) return -1;
    mode_t mask = umask(0177);
    int result = bind(c->listener, (struct sockaddr *)&address, sizeof(address));
    umask(mask);
    if (result) return -1;
    if (fstatat(directory, c->socket_name, &info, AT_SYMLINK_NOFOLLOW) ||
        !S_ISSOCK(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0777) != 0600)
        return -1;
    c->socket_owned = true;
    c->socket_device = info.st_dev;
    c->socket_inode = info.st_ino;
    if (listen(c->listener, CONTROL_CLIENTS)) return -1;
    return 0;
}

static void close_control(struct stream_context *c)
{
    for (unsigned i = 0; i < CONTROL_CLIENTS; ++i)
        if (c->clients[i] >= 0) close(c->clients[i]);
    if (c->listener >= 0) close(c->listener);
    if (c->socket_owned) {
        struct stat info;
        if (!fstatat(c->parent_fd, c->socket_name, &info, AT_SYMLINK_NOFOLLOW) && S_ISSOCK(info.st_mode) &&
            info.st_dev == c->socket_device && info.st_ino == c->socket_inode)
            (void)unlinkat(c->parent_fd, c->socket_name, 0);
    }
    if (c->parent_fd >= 0) close(c->parent_fd);
}

static const char *apply_command(struct stream_context *c, const struct pg_stream_command *cmd, uint64_t now)
{
    if (cmd->kind == PG_STREAM_CMD_STATUS || cmd->kind == PG_STREAM_CMD_HELP) return NULL;
    if (cmd->kind == PG_STREAM_CMD_STOP) { c->stop = true; c->reason = "command"; return NULL; }
    if (cmd->kind == PG_STREAM_CMD_ADD) return add_stream(c, &cmd->value.add, now);
    struct stream_tx *s = find_stream(c, cmd->name);
    if (!s) return "Unknown stream";
    struct pg_packet_template *replacement = NULL;
    struct pg_stream_spec next = s->sum.spec;
    if (cmd->kind == PG_STREAM_CMD_COUNT && cmd->value.count < s->sum.submitted)
        return "Count target is below packets already submitted";
    if (cmd->kind == PG_STREAM_CMD_TTL) {
        next.ttl_min = cmd->value.ttl.min;
        next.ttl_max = cmd->value.ttl.max;
        next.explicit_ttl = true;
        replacement = make_templates(c, &next);
        if (!replacement) return "Cannot prepare TTL templates";
    }
    release_pending(c, s);
    s->next_due = s->last_progress = now;
    s->retry_at = 0;
    s->fractional_ticks = 0;
    switch (cmd->kind) {
    case PG_STREAM_CMD_PAUSE: s->sum.spec.paused = true; break;
    case PG_STREAM_CMD_RESUME: s->sum.spec.paused = false; break;
    case PG_STREAM_CMD_RATE:
        s->sum.spec.pps = cmd->value.rate.pps;
        s->sum.spec.unlimited = cmd->value.rate.unlimited;
        break;
    case PG_STREAM_CMD_COUNT: s->sum.spec.count = cmd->value.count; break;
    case PG_STREAM_CMD_TTL:
        free(s->templates);
        s->templates = replacement;
        s->sum.spec = next;
        break;
    case PG_STREAM_CMD_REMOVE:
        s->sum.removed = true;
        c->history[c->history_count++] = s->sum;
        free(s->templates);
        s->templates = NULL;
        s->used = false;
        break;
    default: return "Unsupported command";
    }
    return NULL;
}

static void json_string(FILE *out, const char *text)
{
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') { fputc('\\', out); fputc(*p, out); }
        else if (*p < 32u) fprintf(out, "\\u%04x", (unsigned)*p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

static void control_reply(struct stream_context *c, int fd, const char *error, bool help)
{
    char *text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&text, &length);
    if (!out) return;
    fprintf(out, "{\"ok\":%s,\"message\":", error ? "false" : "true");
    json_string(out, error ? error : "Command applied");
    fprintf(out, ",\"submitted\":%" PRIu64 ",\"streams\":", c->submitted);
    streams_json(out, c, false);
    if (help) fputs(",\"commands\":[\"status\",\"pause NAME\",\"resume NAME\","
        "\"rate NAME PPS|unlimited\",\"count NAME TOTAL\",\"ttl NAME MIN MAX\","
        "\"add STREAMSPEC\",\"remove NAME\",\"stop\"]", out);
    fputs("}\n", out);
    if (fclose(out) == 0) (void)send(fd, text, length, MSG_DONTWAIT | MSG_NOSIGNAL);
    free(text);
}

static void service_control(struct stream_context *c, uint64_t now)
{
    if (c->listener < 0) return;
    for (unsigned attempts = 0; attempts < CONTROL_CLIENTS; ++attempts) {
        int fd = accept4(c->listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) break;
        struct ucred peer;
        socklen_t size = sizeof(peer);
        unsigned i;
        for (i = 0; i < CONTROL_CLIENTS; ++i) if (c->clients[i] < 0) break;
        if (i == CONTROL_CLIENTS || getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) ||
            size != sizeof(peer) || peer.uid != geteuid()) { close(fd); continue; }
        c->clients[i] = fd;
        c->client_deadline[i] = now + c->hz;
    }
    for (unsigned i = 0; i < CONTROL_CLIENTS; ++i) if (c->clients[i] >= 0) {
        char line[PG_STREAM_LINE_MAX + 1u];
        struct iovec vector = {line, PG_STREAM_LINE_MAX};
        struct msghdr message = {0};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        ssize_t received = recvmsg(c->clients[i], &message, MSG_DONTWAIT);
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && now < c->client_deadline[i])
            continue;
        const char *error = NULL;
        char diagnostic[192];
        struct pg_stream_command command = {0};
        if (received <= 0) error = "Empty command or receive timeout";
        else if ((message.msg_flags & MSG_TRUNC) || memchr(line, '\0', (size_t)received))
            error = "Command is oversized or contains NUL";
        else {
            line[received] = '\0';
            if (pg_stream_command_parse(line, &command, diagnostic, sizeof(diagnostic))) error = diagnostic;
            else {
                error = apply_command(c, &command, now);
                if (!error) ++c->commands;
            }
        }
        control_reply(c, c->clients[i], error, !error && command.kind == PG_STREAM_CMD_HELP);
        close(c->clients[i]);
        c->clients[i] = -1;
    }
}

static bool send_stream(struct stream_context *c, struct stream_tx *s, uint64_t now)
{
    if (!s->used || s->sum.spec.paused || s->sum.submitted >= s->sum.spec.count ||
        now < s->next_due || now < s->retry_at) return false;
    if (!s->pending_count) {
        uint64_t remaining = s->sum.spec.count - s->sum.submitted;
        uint16_t size = c->options->burst;
        if (!s->sum.spec.unlimited) {
            uint64_t paced = s->sum.spec.pps / UINT64_C(10000);
            if (!paced) paced = 1;
            if (paced < size) size = (uint16_t)paced;
        }
        if (remaining < size) size = (uint16_t)remaining;
        if (rte_pktmbuf_alloc_bulk(c->pool, s->pending, size)) {
            if (!s->allocation_stalled) s->last_progress = now;
            s->allocation_stalled = true;
            ++s->sum.allocation_retries;
            (void)rte_eth_tx_done_cleanup(c->options->port_id, 0, 0);
            if (now - s->last_progress > c->hz) c->failed = true;
            s->retry_at = now + c->hz / UINT64_C(1000000) + 1u;
            return false;
        }
        s->allocation_stalled = false;
        s->last_progress = now;
        s->pending_count = size;
        s->offset = 0;
        uint8_t ttl_min = s->sum.spec.ttl_min, ttl_max = s->sum.spec.ttl_max;
        for (uint16_t i = 0; i < size; ++i) {
            uint8_t ttl = ttl_min == ttl_max ? ttl_min : pg_stream_random_ttl(&s->rng, ttl_min, ttl_max);
            const struct pg_packet_template *packet = &s->templates[ttl - ttl_min];
            uint8_t *data = rte_pktmbuf_mtod(s->pending[i], uint8_t *);
            if (c->options->template_mode == PG_TEMPLATE_STATIC)
                rte_memcpy(data, packet->frame, packet->length);
            else if (pg_packet_template_write(packet, s->sum.sequence++, data, s->frame_length)) {
                c->failed = true;
                return false;
            }
            s->pending[i]->data_len = s->frame_length;
            s->pending[i]->pkt_len = s->frame_length;
        }
    }
    /* Build time is outside this fresh deadline/signal admission check. */
    now = rte_get_tsc_cycles();
    if (stream_interrupted || (c->deadline && now >= c->deadline)) return false;
    ++s->sum.tx_calls;
    uint16_t offered = (uint16_t)(s->pending_count - s->offset);
    uint16_t accepted = rte_eth_tx_burst(c->options->port_id, 0, s->pending + s->offset, offered);
    s->offset = (uint16_t)(s->offset + accepted);
    s->sum.submitted += accepted;
    c->submitted += accepted;
    uint64_t bytes = (uint64_t)accepted * s->frame_length;
    s->sum.bytes += bytes;
    c->bytes += bytes;
    if (accepted) {
        s->sum.tx_stalled = false;
        s->last_progress = now;
        if (!s->sum.spec.unlimited) {
            double ticks = s->fractional_ticks + (double)accepted * (double)c->hz / (double)s->sum.spec.pps;
            uint64_t whole = (uint64_t)ticks;
            s->fractional_ticks = ticks - (double)whole;
            if (s->next_due < now) s->next_due = now;
            if (whole > UINT64_MAX - s->next_due) { c->failed = true; return true; }
            s->next_due += whole;
        }
    }
    if (accepted < offered) {
        ++s->sum.backpressure;
        if ((s->sum.backpressure & UINT64_C(255)) == 0)
            (void)rte_eth_tx_done_cleanup(c->options->port_id, 0, 0);
        /* A full virtual TX queue is ordinary backpressure, for example when
         * the peer has not started its DPDK receiver. Keep the bounded pending
         * batch and service local controls until the peer drains or we stop. */
        if (now - s->last_progress > c->hz && !s->sum.tx_stalled) {
            s->sum.tx_stalled = true;
            fprintf(stderr, "TX backpressure on stream %s: no packets accepted for one second; "
                    "start/check the peer receiver. Local controls remain available.\n", s->sum.spec.name);
        }
        if (!accepted) s->retry_at = now + c->hz / UINT64_C(1000000) + 1u;
    }
    if (s->offset == s->pending_count) s->pending_count = s->offset = 0;
    return accepted != 0;
}

static void run_streams(struct stream_context *c)
{
    uint64_t control_at = c->start;
    while (!c->stop && !c->failed && !stream_interrupted) {
        uint64_t now = rte_get_tsc_cycles();
        if (c->deadline && now >= c->deadline) { c->reason = "duration"; break; }
        if (now >= control_at) {
            service_control(c, now);
            control_at = now + c->hz / 1000u + 1u;
        }
        if (c->stop) break;
        bool unfinished = false, progress = false;
        unsigned first_offer = PG_MAX_STREAMS;
        for (unsigned n = 0; n < PG_MAX_STREAMS; ++n) {
            unsigned i = (c->cursor + n) % PG_MAX_STREAMS;
            struct stream_tx *s = &c->streams[i];
            if (!s->used) continue;
            if (s->sum.submitted < s->sum.spec.count) unfinished = true;
            if (first_offer == PG_MAX_STREAMS && !s->sum.spec.paused &&
                s->sum.submitted < s->sum.spec.count && now >= s->next_due && now >= s->retry_at)
                first_offer = i;
            progress |= send_stream(c, s, now);
            if (c->failed || stream_interrupted) break;
        }
        /* Start after the first eligible offer on the next sweep. Empty,
         * paused, completed or not-yet-due slots cannot bias this rotation. */
        if (first_offer != PG_MAX_STREAMS) c->cursor = (first_offer + 1u) % PG_MAX_STREAMS;
        if (!unfinished && c->listener < 0) { c->reason = "counts"; break; }
        if (!progress) {
            /* Sleep only when every runnable stream is far from eligibility.
             * Ring backpressure keeps short pause/retry polling instead. */
            bool soon = false;
            uint64_t margin = c->hz / UINT64_C(5000);
            for (unsigned i = 0; i < PG_MAX_STREAMS; ++i) {
                struct stream_tx *s = &c->streams[i];
                if (s->used && !s->sum.spec.paused && s->sum.submitted < s->sum.spec.count &&
                    (s->pending_count || s->next_due <= now + margin)) soon = true;
            }
            if (soon) rte_pause();
            else { struct timespec delay = {0, 100000}; (void)nanosleep(&delay, NULL); }
        }
    }
    if (c->failed) c->reason = "error";
    else if (stream_interrupted) c->reason = "signal";
    c->end = rte_get_tsc_cycles();
    c->end_unix = stream_unix_ns();
    for (unsigned i = 0; i < PG_MAX_STREAMS; ++i) if (c->streams[i].used)
        release_pending(c, &c->streams[i]);
}

int pg_dpdk_stream_run(int eal_argc, char **eal_argv, const struct pg_options *o)
{
    int status = -1;
    bool eal = false, configured = false, started = false, safe = true;
    bool have_int = false, have_term = false;
    struct sigaction action = {0}, old_int = {0}, old_term = {0};
    struct stream_context *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    c->options = o;
    c->base = o->packet;
    c->listener = -1;
    c->parent_fd = -1;
    c->reason = "error";
    for (unsigned i = 0; i < CONTROL_CLIENTS; ++i) c->clients[i] = -1;
    FILE *json = NULL;
    if (create_control(c)) goto done;
    if (o->stats_json) {
        json = fopen(o->stats_json, "wx");
        if (!json) { perror("Cannot create statistics"); goto done; }
    }
    if (rte_eal_init(eal_argc, eal_argv) < 0) goto done;
    eal = true;
    c->lcore = rte_get_main_lcore();
    if (!rte_eth_dev_is_valid_port(o->port_id)) { fprintf(stderr, "Selected port does not exist\n"); goto done; }
    c->hz = rte_get_tsc_hz();
    if (!c->hz || c->hz > UINT64_MAX / UINT64_C(3600000)) goto done;
    struct rte_eth_dev_info device = {0};
    struct rte_ether_addr mac;
    if (rte_eth_dev_info_get(o->port_id, &device) || !device.max_tx_queues ||
        rte_eth_macaddr_get(o->port_id, &mac)) goto done;
    memcpy(c->base.src_mac, mac.addr_bytes, sizeof(c->base.src_mac));
    struct rte_eth_conf conf = {0};
    if (device.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    if (rte_eth_dev_configure(o->port_id, 0, 1, &conf)) goto done;
    configured = true;
    uint16_t rx_desc = 128, tx_desc = o->tx_descriptors;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(o->port_id, &rx_desc, &tx_desc)) goto done;
    c->effective_descriptors = tx_desc;
    int socket_id = rte_eth_dev_socket_id(o->port_id);
    if (socket_id < 0) socket_id = (int)rte_socket_id();
    if (socket_id < 0) goto done;
    size_t room = RTE_PKTMBUF_HEADROOM + PG_MAX_FRAME_SIZE;
    room = (room + RTE_CACHE_LINE_SIZE - 1u) / RTE_CACHE_LINE_SIZE * RTE_CACHE_LINE_SIZE;
    c->pool = rte_pktmbuf_pool_create("pg_stream_pool", (uint32_t)tx_desc + 12288u,
                                    256, 0, (uint16_t)room, socket_id);
    if (!c->pool) goto done;
    struct rte_eth_txconf tx = device.default_txconf;
    tx.offloads = conf.txmode.offloads;
    if (rte_eth_tx_queue_setup(o->port_id, 0, tx_desc, (unsigned)socket_id, &tx)) goto done;
    if (o->stream_count) {
        for (uint16_t i = 0; i < o->stream_count; ++i)
            if (add_stream(c, &o->streams[i], 0)) goto done;
    } else {
        struct pg_stream_spec spec = {0};
        strcpy(spec.name, "main");
        spec.protocol = o->packet.protocol;
        spec.tcp_flags = o->packet.tcp_flags;
        spec.tcp_ack = o->packet.tcp_ack;
        spec.payload_size = (uint16_t)o->packet.payload_size;
        spec.pps = o->pps;
        spec.unlimited = o->unlimited;
        spec.count = o->count;
        spec.ttl_min = o->ttl_min;
        spec.ttl_max = o->ttl_max;
        spec.seed = o->seed;
        if (o->rate_mbps) {
            size_t header = spec.protocol == PG_TCP ? 54u : 42u;
            size_t frame = header + spec.payload_size;
            if (frame < 60) frame = 60;
            spec.pps = o->rate_mbps * UINT64_C(1000000) / (frame * 8u);
        }
        if (!spec.unlimited && (!spec.pps || spec.pps > PG_STREAM_MAX_PPS)) goto done;
        if (add_stream(c, &spec, 0)) goto done;
    }
    started = true;
    if (rte_eth_dev_start(o->port_id)) goto done;
    struct rte_eth_stats before = {0}, after = {0};
    bool baseline = true;
    if (rte_eth_stats_reset(o->port_id)) baseline = rte_eth_stats_get(o->port_id, &before) == 0;
    stream_interrupted = 0;
    action.sa_handler = stream_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, &old_int)) goto done;
    have_int = true;
    if (sigaction(SIGTERM, &action, &old_term)) goto done;
    have_term = true;
    c->start = rte_get_tsc_cycles();
    c->start_unix = stream_unix_ns();
    if (o->duration_ms) c->deadline = c->start + c->hz * o->duration_ms / 1000u;
    for (unsigned i = 0; i < PG_MAX_STREAMS; ++i) if (c->streams[i].used)
        c->streams[i].next_due = c->streams[i].last_progress = c->start;
    c->reason = "counts";
    printf("READY streams=%u control=%s lcore=%u queue=0\n",
           (unsigned)o->stream_count, o->control_socket ? o->control_socket : "disabled", rte_lcore_id());
    fflush(stdout);
    run_streams(c);
    status = c->failed ? -1 : 0;
    /* A bounded drain is independent of a Ctrl+C or control stop request. */
    if (c->submitted) {
        uint64_t until = rte_get_tsc_cycles() + c->hz / 5u;
        do {
            (void)rte_eth_tx_done_cleanup(o->port_id, 0, 0);
            struct timespec delay = {0, 1000000};
            (void)nanosleep(&delay, NULL);
        } while (rte_get_tsc_cycles() < until);
    }
    c->hardware_available = baseline && rte_eth_stats_get(o->port_id, &after) == 0;
    if (c->hardware_available) {
        after.opackets = after.opackets >= before.opackets ? after.opackets - before.opackets : 0;
        after.obytes = after.obytes >= before.obytes ? after.obytes - before.obytes : 0;
        after.oerrors = after.oerrors >= before.oerrors ? after.oerrors - before.oerrors : 0;
    }
    c->hardware = after;
    double elapsed = c->end >= c->start ? (double)(c->end - c->start) / (double)c->hz : 0;
    printf("Submitted: %" PRIu64 "; elapsed: %.6f s; %.3f Mpps; frame data %.3f Gbps\n",
           c->submitted, elapsed, elapsed ? (double)c->submitted / elapsed / 1e6 : 0,
           elapsed ? (double)c->bytes * 8.0 / elapsed / 1e9 : 0);
done:
    if (started && rte_eth_dev_stop(o->port_id)) { status = -1; safe = false; }
    if (configured && safe && rte_eth_dev_close(o->port_id)) { status = -1; safe = false; }
    close_control(c);
    for (unsigned i = 0; i < PG_MAX_STREAMS; ++i) {
        if (c->streams[i].used && c->pool) release_pending(c, &c->streams[i]);
        free(c->streams[i].templates);
    }
    if (safe && c->pool) rte_mempool_free(c->pool);
    if (safe && eal && rte_eal_cleanup()) status = -1;
    if (have_term) (void)sigaction(SIGTERM, &old_term, NULL);
    if (have_int) (void)sigaction(SIGINT, &old_int, NULL);
    if (json) {
        double seconds = c->hz && c->start && c->end >= c->start ?
            (double)(c->end - c->start) / (double)c->hz : 0;
        fprintf(json, "{\"schema_version\":1,\"mode\":\"streams\",\"status\":\"%s\","
                "\"stop_reason\":\"%s\",\"workers\":1,\"lcore\":%u,\"queue\":0,"
                "\"submitted\":%" PRIu64 ",\"not_submitted\":%" PRIu64 ",\"frame_bytes_total\":%" PRIu64 ","
                "\"elapsed_seconds\":%.9f,\"start_unix_ns\":%" PRIu64 ",\"end_unix_ns\":%" PRIu64 ","
                "\"burst\":%u,\"tx_descriptors\":%u,\"template\":\"%s\",\"commands_applied\":%" PRIu64 ","
                "\"hardware_stats_available\":%s,\"hardware_opackets\":%" PRIu64 ","
                "\"hardware_obytes\":%" PRIu64 ",\"hardware_oerrors\":%" PRIu64 ",\"streams\":",
                status ? "error" : stream_interrupted ? "interrupted" : "complete", c->reason,
                c->lcore, c->submitted, c->released, c->bytes, seconds,
                c->start_unix, c->end_unix, (unsigned)o->burst, (unsigned)c->effective_descriptors,
                o->template_mode == PG_TEMPLATE_STATIC ? "static" : "sequence", c->commands,
                c->hardware_available ? "true" : "false",
                c->hardware.opackets, c->hardware.obytes, c->hardware.oerrors);
        streams_json(json, c, true);
        fputs("}\n", json);
        if (ferror(json)) status = -1;
        if (fclose(json)) status = -1;
    }
    if (status) fprintf(stderr, "Stream session failed (%s)\n", c->reason);
    free(c);
    return status;
}
