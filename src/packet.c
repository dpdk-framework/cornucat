#include "packet.h"

#include <stdio.h>
#include <string.h>

enum {
    PG_ETH_HEADER_SIZE = 14,
    PG_IPV4_HEADER_SIZE = 20,
    PG_UDP_HEADER_SIZE = 8,
    PG_TCP_HEADER_SIZE = 20,
    PG_ICMP_HEADER_SIZE = 8,
    PG_MIN_FRAME_SIZE = 60
};

static void write_be16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void write_be32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint16_t read_be16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint32_t checksum_add(uint32_t sum, const uint8_t *data, size_t length)
{
    while (length >= 2u) {
        sum += ((uint32_t)data[0] << 8) | (uint32_t)data[1];
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
        data += 2;
        length -= 2u;
    }
    if (length != 0u) {
        sum += (uint32_t)data[0] << 8;
    }
    return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
    while ((sum >> 16) != 0u) {
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
    }
    return (uint16_t)(~sum & UINT32_C(0xffff));
}

uint16_t pg_checksum(const uint8_t *data, size_t length)
{
    if (data == NULL && length != 0u) {
        return 0;
    }
    return checksum_finish(checksum_add(0, data, length));
}

int pg_packet_set_ttl(uint8_t *frame, size_t length, uint8_t ttl)
{
    if (frame == NULL || ttl == 0 ||
        length < PG_ETH_HEADER_SIZE + PG_IPV4_HEADER_SIZE) return -1;
    if (read_be16(frame + 12) != UINT16_C(0x0800)) return -1;
    uint8_t *ip = frame + PG_ETH_HEADER_SIZE;
    size_t header_size = (size_t)(ip[0] & 15u) * 4u;
    size_t available = length - PG_ETH_HEADER_SIZE;
    size_t ip_size = read_be16(ip + 2);
    if ((ip[0] >> 4) != 4u || header_size < PG_IPV4_HEADER_SIZE ||
        header_size > available || ip_size < header_size || ip_size > available)
        return -1;
    pg_packet_set_ttl_unchecked(frame, ttl);
    return 0;
}

static int fail(char *error, size_t error_size, const char *message)
{
    if (error != NULL && error_size != 0u) {
        (void)snprintf(error, error_size, "%s", message);
    }
    return -1;
}

const char *pg_tcp_flags_name(uint8_t flags)
{
    switch (flags) {
    case 0: /* Legacy callers leave the appended field zero initialized. */
    case 0x02: return "syn";
    case 0x10: return "ack";
    case 0x12: return "syn-ack";
    case 0x18: return "psh-ack";
    case 0x11: return "fin-ack";
    case 0x04: return "rst";
    case 0x14: return "rst-ack";
    default: return NULL;
    }
}

int pg_tcp_flags_parse(const char *name, uint8_t *flags)
{
    static const uint8_t profiles[] = {0x02, 0x10, 0x12, 0x18, 0x11, 0x04, 0x14};
    if (name == NULL || flags == NULL) return -1;
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i) {
        if (!strcmp(name, pg_tcp_flags_name(profiles[i]))) {
            *flags = profiles[i];
            return 0;
        }
    }
    return -1;
}

static uint16_t transport_checksum(const struct pg_packet_config *config,
                                   const uint8_t *transport,
                                   size_t transport_size)
{
    uint8_t pseudo_header[12] = {0};
    uint32_t sum;

    memcpy(pseudo_header, config->src_ip, sizeof(config->src_ip));
    memcpy(pseudo_header + 4, config->dst_ip, sizeof(config->dst_ip));
    pseudo_header[9] = (uint8_t)config->protocol;
    write_be16(pseudo_header + 10, (uint16_t)transport_size);
    sum = checksum_add(0, pseudo_header, sizeof(pseudo_header));
    return checksum_finish(checksum_add(sum, transport, transport_size));
}

int pg_packet_build(const struct pg_packet_config *config,
                    uint32_t sequence,
                    uint8_t *out,
                    size_t capacity,
                    size_t *length,
                    char *error,
                    size_t error_size)
{
    size_t transport_header_size;
    size_t transport_size;
    size_t ip_size;
    size_t frame_size;
    uint8_t *ip;
    uint8_t *transport;
    uint8_t *payload;
    uint16_t checksum;

    if (length != NULL) {
        *length = 0;
    }
    if (config == NULL || out == NULL || length == NULL) {
        return fail(error, error_size, "config, output, and length are required");
    }
    switch (config->protocol) {
    case PG_UDP:
        transport_header_size = PG_UDP_HEADER_SIZE;
        break;
    case PG_TCP:
        if (pg_tcp_flags_name(config->tcp_flags) == NULL) {
            return fail(error, error_size, "unsupported raw TCP flag profile");
        }
        transport_header_size = PG_TCP_HEADER_SIZE;
        break;
    case PG_ICMP:
        transport_header_size = PG_ICMP_HEADER_SIZE;
        break;
    default:
        return fail(error, error_size, "protocol must be UDP, TCP, or ICMP");
    }
    if (config->payload_size > PG_MAX_PAYLOAD) {
        return fail(error, error_size, "payload exceeds the 1400-byte limit");
    }
    if ((config->protocol == PG_UDP || config->protocol == PG_TCP) &&
        (config->src_port == 0u || config->dst_port == 0u)) {
        return fail(error, error_size, "UDP and TCP ports must be between 1 and 65535");
    }

    /* The payload bound above makes these additions and 16-bit casts safe. */
    transport_size = transport_header_size + config->payload_size;
    ip_size = PG_IPV4_HEADER_SIZE + transport_size;
    frame_size = PG_ETH_HEADER_SIZE + ip_size;
    if (frame_size < PG_MIN_FRAME_SIZE) {
        frame_size = PG_MIN_FRAME_SIZE;
    }
    if (frame_size > PG_MAX_FRAME_SIZE || capacity < frame_size) {
        return fail(error, error_size, "output buffer is too small for the frame");
    }

    memset(out, 0, frame_size);
    memcpy(out, config->dst_mac, sizeof(config->dst_mac));
    memcpy(out + 6, config->src_mac, sizeof(config->src_mac));
    write_be16(out + 12, UINT16_C(0x0800));

    ip = out + PG_ETH_HEADER_SIZE;
    ip[0] = 0x45; /* IPv4, five 32-bit header words. */
    write_be16(ip + 2, (uint16_t)ip_size);
    write_be16(ip + 4, (uint16_t)sequence);
    write_be16(ip + 6, UINT16_C(0x4000)); /* Do not fragment. */
    ip[8] = config->ttl ? config->ttl : (uint8_t)64;
    ip[9] = (uint8_t)config->protocol;
    memcpy(ip + 12, config->src_ip, sizeof(config->src_ip));
    memcpy(ip + 16, config->dst_ip, sizeof(config->dst_ip));
    write_be16(ip + 10, pg_checksum(ip, PG_IPV4_HEADER_SIZE));

    transport = ip + PG_IPV4_HEADER_SIZE;
    payload = transport + transport_header_size;
    for (size_t i = 0; i < config->payload_size; ++i) {
        unsigned shift = (unsigned)(i % 4u) * 8u;
        payload[i] = (uint8_t)((uint8_t)(sequence >> shift) ^ (uint8_t)i);
    }

    switch (config->protocol) {
    case PG_UDP:
        write_be16(transport, config->src_port);
        write_be16(transport + 2, config->dst_port);
        write_be16(transport + 4, (uint16_t)transport_size);
        checksum = transport_checksum(config, transport, transport_size);
        /* Zero means "no checksum" in IPv4 UDP, so encode it as all ones. */
        write_be16(transport + 6, checksum == 0u ? UINT16_C(0xffff) : checksum);
        break;
    case PG_TCP:
        write_be16(transport, config->src_port);
        write_be16(transport + 2, config->dst_port);
        write_be32(transport + 4, sequence);
        if (config->tcp_flags & 0x10u)
            write_be32(transport + 8, config->tcp_ack);
        transport[12] = 0x50; /* Five 32-bit header words; no options. */
        transport[13] = config->tcp_flags ? config->tcp_flags : (uint8_t)0x02;
        write_be16(transport + 14, UINT16_C(1024));
        write_be16(transport + 16, transport_checksum(config, transport, transport_size));
        break;
    case PG_ICMP:
        transport[0] = 8; /* Echo request. Code is zero. */
        write_be16(transport + 4, UINT16_C(0x5047));
        write_be16(transport + 6, (uint16_t)sequence);
        write_be16(transport + 2, pg_checksum(transport, transport_size));
        break;
    default:
        /* The protocol was validated before any output was written. */
        break;
    }

    *length = frame_size;
    if (error != NULL && error_size != 0u) {
        error[0] = '\0';
    }
    return 0;
}

int pg_packet_template_init(struct pg_packet_template *template,
                            const struct pg_packet_config *config,
                            char *error, size_t error_size)
{
    struct pg_packet_template prepared;

    if (template == NULL) return fail(error, error_size, "template is required");
    memset(&prepared, 0, sizeof(prepared));
    if (pg_packet_build(config, 0, prepared.frame, sizeof(prepared.frame),
                         &prepared.length, error, error_size)) return -1;
    prepared.protocol = config->protocol;
    prepared.payload_size = config->payload_size;
    *template = prepared;
    return 0;
}

/* RFC 1624: HC' = ~(~HC + ~m + m'). Accumulate replacements, then fold once.
 * The payload bound keeps the sum below UINT32_MAX (at most 703 words). */
static uint32_t checksum_replace(uint32_t sum, uint16_t old, uint16_t next)
{
    return sum + (uint32_t)(uint16_t)~old + next;
}

int pg_packet_template_write(const struct pg_packet_template *template,
                             uint32_t sequence, uint8_t *out, size_t capacity)
{
    size_t header_size;
    size_t checksum_offset;
    uint8_t *ip;
    uint8_t *transport;
    uint8_t *payload;
    uint32_t sum;
    uint16_t checksum;

    if (template == NULL || out == NULL || template->payload_size > PG_MAX_PAYLOAD)
        return -1;
    switch (template->protocol) {
    case PG_UDP: header_size = PG_UDP_HEADER_SIZE; checksum_offset = 6; break;
    case PG_TCP: header_size = PG_TCP_HEADER_SIZE; checksum_offset = 16; break;
    case PG_ICMP: header_size = PG_ICMP_HEADER_SIZE; checksum_offset = 2; break;
    default: return -1;
    }
    size_t expected_size = PG_ETH_HEADER_SIZE + PG_IPV4_HEADER_SIZE + header_size + template->payload_size;
    if (expected_size < PG_MIN_FRAME_SIZE) expected_size = PG_MIN_FRAME_SIZE;
    if (template->length != expected_size || capacity < template->length) return -1;
    memcpy(out, template->frame, template->length);
    if (sequence == 0) return 0;

    ip = out + PG_ETH_HEADER_SIZE;
    transport = ip + PG_IPV4_HEADER_SIZE;
    payload = transport + header_size;
    sum = (uint32_t)(uint16_t)~read_be16(ip + 10);
    sum = checksum_replace(sum, read_be16(ip + 4), (uint16_t)sequence);
    write_be16(ip + 4, (uint16_t)sequence);
    write_be16(ip + 10, checksum_finish(sum));

    sum = (uint32_t)(uint16_t)~read_be16(transport + checksum_offset);
    if (template->protocol == PG_TCP) {
        sum = checksum_replace(sum, read_be16(transport + 4), (uint16_t)(sequence >> 16));
        sum = checksum_replace(sum, read_be16(transport + 6), (uint16_t)sequence);
        write_be32(transport + 4, sequence);
    } else if (template->protocol == PG_ICMP) {
        sum = checksum_replace(sum, read_be16(transport + 6), (uint16_t)sequence);
        write_be16(transport + 6, (uint16_t)sequence);
    }
    /* Four payload bytes repeat the same sequence-byte positions. Fixed
     * shifts and two complete checksum words avoid a variable shift and an
     * odd-byte branch for every word. Byte helpers keep alignment and host
     * endianness independent; only the final zero to three bytes need tails. */
    const uint8_t sequence_byte0 = (uint8_t)sequence;
    const uint8_t sequence_byte1 = (uint8_t)(sequence >> 8);
    const uint8_t sequence_byte2 = (uint8_t)(sequence >> 16);
    const uint8_t sequence_byte3 = (uint8_t)(sequence >> 24);
    size_t full_bytes = template->payload_size & ~(size_t)3u;
    size_t i = 0;
    for (; i < full_bytes; i += 4u) {
        uint16_t old_first = read_be16(payload + i);
        uint16_t old_second = read_be16(payload + i + 2u);
        uint16_t next_first = (uint16_t)(
            ((uint16_t)(sequence_byte0 ^ (uint8_t)i) << 8) |
            (uint16_t)(sequence_byte1 ^ (uint8_t)(i + 1u)));
        uint16_t next_second = (uint16_t)(
            ((uint16_t)(sequence_byte2 ^ (uint8_t)(i + 2u)) << 8) |
            (uint16_t)(sequence_byte3 ^ (uint8_t)(i + 3u)));
        sum = checksum_replace(sum, old_first, next_first);
        sum = checksum_replace(sum, old_second, next_second);
        write_be16(payload + i, next_first);
        write_be16(payload + i + 2u, next_second);
    }
    if (template->payload_size - i >= 2u) {
        uint16_t old = read_be16(payload + i);
        uint16_t next = (uint16_t)(
            ((uint16_t)(sequence_byte0 ^ (uint8_t)i) << 8) |
            (uint16_t)(sequence_byte1 ^ (uint8_t)(i + 1u)));
        sum = checksum_replace(sum, old, next);
        write_be16(payload + i, next);
        i += 2u;
    }
    if (i < template->payload_size) {
        uint8_t sequence_byte = (i & 2u) ? sequence_byte2 : sequence_byte0;
        uint8_t next = (uint8_t)(sequence_byte ^ (uint8_t)i);
        sum = checksum_replace(sum, (uint16_t)((uint16_t)payload[i] << 8),
                               (uint16_t)((uint16_t)next << 8));
        payload[i] = next;
    }
    checksum = checksum_finish(sum);
    if (template->protocol == PG_UDP && checksum == 0) checksum = UINT16_C(0xffff);
    write_be16(transport + checksum_offset, checksum);
    return 0;
}
