#include "options.h"
#include <inttypes.h>
#include <string.h>

static int fail(char *error, size_t size, const char *message)
{
    if (error && size) snprintf(error, size, "%s", message);
    return -1;
}

static int number(const char *text, uint64_t low, uint64_t high, uint64_t *result)
{
    uint64_t value = 0;
    if (!text || !*text) return -1;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9') return -1;
        uint64_t digit = (uint64_t)(*text - '0');
        if (value > high / 10 || (value == high / 10 && digit > high % 10)) return -1;
        value = value * 10 + digit;
    }
    if (value < low) return -1;
    *result = value;
    return 0;
}

static int ipv4(const char *text, uint8_t ip[4])
{
    if (!text) return -1;
    for (size_t i = 0; i < 4; ++i) {
        unsigned value = 0, digits = 0;
        while (*text >= '0' && *text <= '9') {
            if (++digits > 3) return -1;
            value = value * 10 + (unsigned)(*text++ - '0');
        }
        if (!digits || value > 255) return -1;
        ip[i] = (uint8_t)value;
        if (i < 3) { if (*text++ != '.') return -1; }
        else if (*text) return -1;
    }
    return 0;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int mac(const char *text, uint8_t bytes[6])
{
    if (!text || strlen(text) != 17) return -1;
    for (size_t i = 0; i < 6; ++i) {
        int a = hex_digit(text[3 * i]), b = hex_digit(text[3 * i + 1]);
        if (a < 0 || b < 0 || (i < 5 && text[3 * i + 2] != ':')) return -1;
        bytes[i] = (uint8_t)((a << 4) | b);
    }
    return 0;
}

bool pg_is_lab_ip(const uint8_t ip[4])
{
    return ip && (ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31)
           || (ip[0] == 192 && ip[1] == 168) || (ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)));
}

void pg_options_default(struct pg_options *o)
{
    memset(o, 0, sizeof(*o));
    o->packet.protocol = PG_UDP;
    const uint8_t source[4] = {198, 18, 0, 1}, destination[4] = {198, 18, 0, 2};
    const uint8_t smac[6] = {2, 0, 0, 0, 0, 1}, dmac[6] = {2, 0, 0, 0, 0, 2};
    memcpy(o->packet.src_ip, source, 4); memcpy(o->packet.dst_ip, destination, 4);
    memcpy(o->packet.src_mac, smac, 6); memcpy(o->packet.dst_mac, dmac, 6);
    o->packet.src_port = 49152; o->packet.dst_port = 9000;
    o->packet.payload_size = 32;
    o->mode = PG_MODE_PCAP; o->output = "packets.pcap";
    o->count = 10; o->pps = 100;
    o->workers = 1; o->burst = 64; o->flows = 1;
    o->tx_descriptors = 1024;
    o->template_mode = PG_TEMPLATE_SEQUENCE;
    o->pacing_mode = PG_PACING_SMOOTH;
    o->packet.ttl = 64;
    o->ttl_min = o->ttl_max = 64;
    o->seed = 1;
    o->replay_loops = 1;
}

int pg_options_parse(int argc, char *const argv[], struct pg_options *o,
                     char *error, size_t error_size)
{
    static const char *const names[] = {"--protocol", "--mode", "--output", "--count", "--pps",
        "--port-id", "--src-ip", "--dst-ip", "--src-mac", "--dst-mac", "--src-port", "--dst-port", "--payload-size",
        "--rate-mbps", "--unlimited", "--duration-ms", "--workers", "--burst", "--flows", "--stats-json", "--template",
        "--tx-descriptors", "--pacing", "--stream", "--control-socket",
        "--ttl-min", "--ttl-max", "--seed", "--ttl", "--replay", "--replay-loops", "--replay-timing"};
    _Static_assert(sizeof(names) / sizeof(names[0]) <= 32, "Option mask is too small");
    uint32_t seen = 0;
    if (!o || argc < 0 || (argc && !argv)) return fail(error, error_size, "Invalid parser arguments");
    for (int i = 0; i < argc; ++i) {
        if (!argv[i]) return fail(error, error_size, "Missing argument");
        if (!strcmp(argv[i], "--help")) return 1;
        size_t key;
        for (key = 0; key < sizeof(names) / sizeof(names[0]); ++key)
            if (!strcmp(argv[i], names[key])) break;
        if (key == sizeof(names) / sizeof(names[0])) return fail(error, error_size, "Unknown option; see --help");
        if (key != 23 && (seen & (UINT32_C(1) << key))) return fail(error, error_size, "Duplicate option");
        seen |= UINT32_C(1) << key;
        if (key == 14) { o->unlimited = true; continue; }
        if (++i == argc || !argv[i]) return fail(error, error_size, "Option requires a value");
        const char *value = argv[i];
        uint64_t parsed;
        switch (key) {
        case 0:
            if (!strcmp(value, "udp")) o->packet.protocol = PG_UDP;
            else if (!strcmp(value, "tcp")) o->packet.protocol = PG_TCP;
            else if (!strcmp(value, "icmp")) o->packet.protocol = PG_ICMP;
            else return fail(error, error_size, "Protocol must be udp, tcp, or icmp");
            break;
        case 1:
            if (!strcmp(value, "pcap")) o->mode = PG_MODE_PCAP;
            else if (!strcmp(value, "dpdk")) o->mode = PG_MODE_DPDK;
            else return fail(error, error_size, "Mode must be pcap or dpdk");
            break;
        case 2:
            if (!*value) return fail(error, error_size, "Output path is empty");
            o->output = value; break;
        case 3:
            if (number(value, 1, UINT64_MAX, &o->count)) return fail(error, error_size, "Count must be 1..18446744073709551615");
            o->explicit_count = true;
            break;
        case 4:
            if (number(value, 1, UINT64_C(1000000000), &o->pps)) return fail(error, error_size, "PPS must be 1..1000000000");
            break;
        case 5:
            if (number(value, 0, 65535, &parsed)) return fail(error, error_size, "Invalid DPDK port ID");
            o->port_id = (uint16_t)parsed; o->explicit_port = true; break;
        case 6:
            if (ipv4(value, o->packet.src_ip)) return fail(error, error_size, "Invalid source IPv4 address");
            o->explicit_src_ip = true; break;
        case 7:
            if (ipv4(value, o->packet.dst_ip)) return fail(error, error_size, "Invalid destination IPv4 address");
            o->explicit_dst_ip = true; break;
        case 8:
            if (mac(value, o->packet.src_mac)) return fail(error, error_size, "Invalid source MAC address");
            break;
        case 9:
            if (mac(value, o->packet.dst_mac)) return fail(error, error_size, "Invalid destination MAC address");
            o->explicit_dst_mac = true; break;
        case 10: case 11:
            if (number(value, 1, 65535, &parsed)) return fail(error, error_size, "Ports must be 1..65535 with decimal digits only");
            if (key == 10) o->packet.src_port = (uint16_t)parsed;
            else o->packet.dst_port = (uint16_t)parsed;
            break;
        case 12:
            if (number(value, 0, PG_MAX_PAYLOAD, &parsed)) return fail(error, error_size, "Payload size must be 0..1400");
            o->packet.payload_size = (size_t)parsed; break;
        case 13:
            if (number(value, 1, UINT64_C(1000000), &o->rate_mbps)) return fail(error, error_size, "Frame Mbps must be 1..1000000");
            break;
        case 15:
            if (number(value, 1, UINT64_C(3600000), &parsed)) return fail(error, error_size, "Duration must be 1..3600000 ms");
            o->duration_ms = (uint32_t)parsed; break;
        case 16:
            if (number(value, 1, 16, &parsed)) return fail(error, error_size, "Workers must be 1..16");
            o->workers = (uint16_t)parsed; break;
        case 17:
            if (number(value, 1, 256, &parsed)) return fail(error, error_size, "Burst must be 1..256");
            o->burst = (uint16_t)parsed; break;
        case 18:
            if (number(value, 1, 1024, &parsed)) return fail(error, error_size, "Flows must be 1..1024");
            o->flows = (uint16_t)parsed; break;
        case 19:
            if (!*value) return fail(error, error_size, "Statistics path is empty");
            o->stats_json = value; break;
        case 20:
            if (!strcmp(value, "sequence")) o->template_mode = PG_TEMPLATE_SEQUENCE;
            else if (!strcmp(value, "static")) o->template_mode = PG_TEMPLATE_STATIC;
            else return fail(error, error_size, "Template must be sequence or static");
            break;
        case 21:
            if (number(value, 64, 4096, &parsed) || (parsed & (parsed - 1u)))
                return fail(error, error_size, "TX descriptors must be a power of two from 64..4096");
            o->tx_descriptors = (uint16_t)parsed; break;
        case 22:
            if (!strcmp(value, "smooth")) o->pacing_mode = PG_PACING_SMOOTH;
            else if (!strcmp(value, "catch-up")) o->pacing_mode = PG_PACING_CATCH_UP;
            else return fail(error, error_size, "Pacing must be smooth or catch-up");
            break;
        case 23:
            if (o->stream_count == PG_MAX_STREAMS)
                return fail(error, error_size, "At most 16 simultaneous streams are supported");
            if (pg_stream_parse(value, &o->streams[o->stream_count], error, error_size)) return -1;
            for (uint16_t s = 0; s < o->stream_count; ++s)
                if (!strcmp(o->streams[s].name, o->streams[o->stream_count].name))
                    return fail(error, error_size, "Stream names must be unique");
            ++o->stream_count;
            break;
        case 24:
            if (value[0] != '/' || strlen(value) > 100)
                return fail(error, error_size, "Control socket requires an absolute path of at most 100 bytes");
            o->control_socket = value;
            break;
        case 25: case 26: case 28:
            if (number(value, 1, 255, &parsed)) return fail(error, error_size, "TTL must be 1..255");
            o->ttl_override = true;
            if (key == 25) o->ttl_min = (uint8_t)parsed;
            else if (key == 26) o->ttl_max = (uint8_t)parsed;
            else o->ttl_min = o->ttl_max = (uint8_t)parsed;
            break;
        case 27:
            if (number(value, 1, UINT64_MAX, &o->seed)) return fail(error, error_size, "Seed must be 1..UINT64_MAX");
            o->explicit_seed = true;
            break;
        case 29:
            if (!*value) return fail(error, error_size, "Replay path is empty");
            o->replay_input = value;
            break;
        case 30:
            if (number(value, 0, UINT64_MAX, &o->replay_loops)) return fail(error, error_size, "Replay loops must be 0..UINT64_MAX");
            break;
        case 31:
            if (!strcmp(value, "original")) o->replay_original_timing = true;
            else if (!strcmp(value, "rate")) o->replay_original_timing = false;
            else return fail(error, error_size, "Replay timing must be original or rate");
            break;
        default: return fail(error, error_size, "Internal option error");
        }
    }
    if (((seen >> 25) & 3u) != 0u && ((seen >> 25) & 3u) != 3u)
        return fail(error, error_size, "Specify both --ttl-min and --ttl-max");
    if ((seen & (UINT32_C(1) << 28)) && (seen & (UINT32_C(3) << 25)))
        return fail(error, error_size, "Choose --ttl or --ttl-min/--ttl-max");
    if (o->ttl_min > o->ttl_max) return fail(error, error_size, "TTL minimum exceeds maximum");
    if (!o->replay_input && (seen & (UINT32_C(3) << 30)))
        return fail(error, error_size, "Replay loops/timing require --replay");
    if (o->replay_input) {
        if (o->mode != PG_MODE_DPDK)
            return fail(error, error_size, "Replay requires dpdk mode");
        uint32_t generated = (UINT32_C(1) << 0) | (UINT32_C(3) << 10) |
            (UINT32_C(1) << 12) | (UINT32_C(1) << 20) | (UINT32_C(3) << 23);
        if ((seen & generated) || o->workers != 1 || o->flows != 1 || o->pacing_mode != PG_PACING_SMOOTH)
            return fail(error, error_size, "Replay uses capture packets, one worker and no stream/control/template options");
        if (o->replay_original_timing && ((seen & ((UINT32_C(1) << 4) | (UINT32_C(3) << 13)))))
            return fail(error, error_size, "Original replay timing cannot be combined with a sending rate");
    }
    o->packet.ttl = o->ttl_min;
    for (uint16_t s = 0; s < o->stream_count; ++s) {
        if (!o->streams[s].explicit_ttl) {
            o->streams[s].ttl_min = o->ttl_min;
            o->streams[s].ttl_max = o->ttl_max;
        }
        if (!o->streams[s].explicit_seed && (seen & (UINT32_C(1) << 27))) {
            o->streams[s].seed = o->seed + s;
            if (!o->streams[s].seed) o->streams[s].seed = 1;
        }
    }
    if (o->mode == PG_MODE_DPDK) {
        if (!o->explicit_src_ip || !o->explicit_dst_ip || !o->explicit_dst_mac || !o->explicit_port)
            return fail(error, error_size, "DPDK mode requires explicit --port-id, --src-ip, --dst-ip, and --dst-mac");
        if (!pg_is_lab_ip(o->packet.src_ip) || !pg_is_lab_ip(o->packet.dst_ip))
            return fail(error, error_size, "Live addresses must be RFC1918 or 198.18.0.0/15 lab addresses");
        const uint8_t zero[6] = {0};
        if ((o->packet.dst_mac[0] & 1) || !memcmp(o->packet.dst_mac, zero, sizeof(zero)))
            return fail(error, error_size, "Live destination MAC must be nonzero and unicast");
        if (seen & (UINT32_C(1) << 2)) return fail(error, error_size, "--output is only available in pcap mode");
        if (seen & (UINT32_C(1) << 8)) return fail(error, error_size, "Live source MAC comes from the selected NIC");
        if (((seen & (UINT32_C(1) << 4)) != 0) + (o->rate_mbps != 0) + o->unlimited > 1)
            return fail(error, error_size, "Choose exactly one of --pps, --rate-mbps, or --unlimited");
        if (o->packet.protocol != PG_ICMP && (uint32_t)o->packet.src_port + o->flows - 1u > UINT16_MAX)
            return fail(error, error_size, "Source port plus flow range exceeds 65535");
        if (o->packet.protocol == PG_ICMP && o->flows > 1)
            return fail(error, error_size, "ICMP supports one flow; source ports apply to UDP/TCP");
        if (o->duration_ms && !(seen & (UINT32_C(1) << 3))) o->count = UINT64_MAX;
        if (o->stream_count) {
            uint32_t ambiguous = (UINT32_C(1) << 0) | (UINT32_C(1) << 3) |
                (UINT32_C(1) << 4) | (UINT32_C(1) << 12) | (UINT32_C(3) << 13);
            if (seen & ambiguous)
                return fail(error, error_size, "Use protocol, count, pps/unlimited and payload inside each --stream");
        }
        if (o->stream_count || o->control_socket || o->ttl_min != o->ttl_max) {
            if (o->workers != 1 || o->flows != 1 || o->pacing_mode != PG_PACING_SMOOTH)
                return fail(error, error_size, "Stream/control/random-TTL mode uses one worker, one flow per stream and smooth pacing");
        }
    } else {
        if (o->stream_count || o->control_socket)
            return fail(error, error_size, "Streams and live controls require dpdk mode");
        if (o->explicit_port) return fail(error, error_size, "--port-id is only available in dpdk mode");
        if (seen & (UINT32_C(0x3ff) << 13)) return fail(error, error_size, "Rate, duration, workers, burst, flows, statistics, template, descriptors, and pacing options require dpdk mode");
        if (o->count > UINT64_C(10000)) return fail(error, error_size, "PCAP count must be 1..10000");
        if (o->pps > UINT64_C(1000000)) return fail(error, error_size, "PCAP PPS must be 1..1000000 for microsecond timestamps");
    }
    if (error && error_size) *error = '\0';
    return 0;
}

void pg_usage(FILE *stream, const char *program)
{
    fprintf(stream,
        "Usage: %s [application options]\n"
        "DPDK:  %s [EAL options] -- --mode dpdk [application options]\n"
        "  --protocol udp|tcp|icmp     IPv4 UDP, TCP SYN probe, or ICMP echo\n"
        "  --mode pcap|dpdk           Default pcap: writes a file, sends no traffic\n"
        "  --output PATH              New PCAP file; default packets.pcap\n"
        "  --count N                  Default 10; live 1..UINT64_MAX; PCAP 1..10000\n"
        "  --pps N                    Default 100; live 1..1000000000; PCAP 1..1000000\n"
        "  --rate-mbps N              Live Ethernet frame Mbps, 1..1000000; excludes FCS/IFG\n"
        "  --unlimited                Live maximum offered rate; count/duration still stop\n"
        "  --duration-ms 1..3600000    Live duration; with count, stop at whichever comes first\n"
        "  --workers 1..16            Live TX workers; default 1\n"
        "  --burst 1..256             Live packets per burst; default 64\n"
        "  --flows 1..1024            Live source-port flows; default 1\n"
        "  --tx-descriptors 64..4096  Live TX ring; power of two; default 1024; PMD may adjust\n"
        "  --pacing smooth|catch-up   Live rate schedule; default smooth discards overdue debt\n"
        "  --template sequence|static Live sequence updates or identical frames; default sequence\n"
        "  --stats-json PATH          New live statistics JSON file\n"
        "  --payload-size 0..1400      Default 32 bytes\n"
        "  --src-ip A.B.C.D --dst-ip A.B.C.D\n"
        "  --src-mac XX:XX:XX:XX:XX:XX --dst-mac XX:XX:XX:XX:XX:XX\n"
        "  --src-port 1..65535 --dst-port 1..65535\n"
        "  --port-id ID               Explicit device for live DPDK mode\n"
        "  --ttl 1..255               Fixed IPv4 TTL; default 64\n"
        "  --ttl-min N --ttl-max N    Inclusive random IPv4 TTL range, all protocols\n"
        "  --seed 1..UINT64_MAX       Reproducible TTL seed; default 1\n"
        "  --stream SPEC             Repeat: name=u,protocol=udp,pps=1000,count=10000,ttl-min=4,ttl-max=7\n"
        "  --control-socket PATH     Owner-only local live controls; keeps session open\n"
        "  --replay PATH             Validated classic Ethernet/IPv4 PCAP, lab direction only\n"
        "  --replay-loops N          Replay passes; default 1; 0 until stopped\n"
        "  --replay-timing rate|original  Configured rate (default) or capture timestamps\n"
        "Live mode requires explicit lab IPs, destination MAC, and port ID.\n",
        program, program);
}
