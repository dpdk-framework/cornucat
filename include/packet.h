#ifndef PG_PACKET_H
#define PG_PACKET_H

#include <stddef.h>
#include <stdint.h>

#define PG_MAX_PAYLOAD 1400u
#define PG_MAX_FRAME_SIZE 1514u

enum pg_protocol {
    PG_ICMP = 1,
    PG_TCP = 6,
    PG_UDP = 17
};

struct pg_packet_config {
    enum pg_protocol protocol;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t src_port;
    uint16_t dst_port;
    size_t payload_size;
    uint8_t ttl; /* IPv4 TTL; zero selects the backward-compatible default 64. */
    uint8_t tcp_flags; /* A supported raw TCP profile; zero selects SYN. */
    uint32_t tcp_ack; /* Serialized only for profiles that include ACK. */
};

/* Initialized immutable frame template. Use a separate output buffer per TX
 * packet; transferring an mbuf to a NIC must never transfer this storage. */
struct pg_packet_template {
    uint8_t frame[PG_MAX_FRAME_SIZE];
    size_t length;
    enum pg_protocol protocol;
    size_t payload_size;
};

/*
 * Build an Ethernet/IPv4 UDP datagram, raw TCP segment, or ICMP echo request.
 * The frame excludes the Ethernet FCS and includes zero padding to 60 bytes.
 * Raw TCP profiles do not implement a handshake or establish connection state.
 * Supported profiles are SYN, ACK, SYN-ACK, PSH-ACK, FIN-ACK, RST and RST-ACK.
 * A zero tcp_flags value preserves the SYN default. ACK profiles serialize
 * config->tcp_ack; other profiles have a zero acknowledgment field. Ports are
 * ignored for ICMP, and TCP fields are ignored for non-TCP packets.
 * IPv4 TTL is config->ttl, with zero selecting the default value 64.
 *
 * Returns 0 on success and -1 on invalid arguments or insufficient capacity.
 * On failure, *length is zero when length is non-NULL; out is not modified.
 * error may be NULL. A supplied error buffer is always NUL terminated when
 * error_size is nonzero. Input, output, length, and error storage must not
 * overlap.
 */
int pg_packet_build(const struct pg_packet_config *config,
                    uint32_t sequence,
                    uint8_t *out,
                    size_t capacity,
                    size_t *length,
                    char *error,
                    size_t error_size);

/* Cache a valid sequence-zero frame, including software checksums. On failure
 * template is not modified. Input and template/error storage must not overlap. */
int pg_packet_template_init(struct pg_packet_template *template,
                            const struct pg_packet_config *config,
                            char *error, size_t error_size);

/* Copy a cached template and apply the same sequence fields/payload as the
 * reference builder, updating checksums incrementally. Returns 0 on success,
 * -1 for invalid arguments/capacity, without modifying output on failure.
 * template must have been initialized and must not overlap output. Identical
 * static packets can instead copy template->frame[0..template->length).
 * The sequence payload requires O(payload_size) updates; static copying avoids
 * both rebuilding headers and recalculating checksums. */
int pg_packet_template_write(const struct pg_packet_template *template,
                             uint32_t sequence, uint8_t *out, size_t capacity);

/* Change TTL on an owned, valid, untagged Ethernet/IPv4 frame with a valid
 * existing IPv4 checksum. ttl must be 1..255. The caller must establish these
 * preconditions and a complete header before using this unchecked hot-path
 * helper. It updates only TTL and the IPv4 checksum; transport bytes and
 * checksums are unchanged. Byte access supports unaligned frames and either
 * host endianness. Never modify a frame after transferring it to a PMD. */
static inline void pg_packet_set_ttl_unchecked(uint8_t *frame, uint8_t ttl)
{
    uint8_t *ip = frame + 14u;
    if (ip[8] == ttl) return;
    uint16_t checksum = (uint16_t)(((uint16_t)ip[10] << 8) | ip[11]);
    uint16_t old_word = (uint16_t)((uint16_t)ip[8] << 8);
    uint16_t new_word = (uint16_t)((uint16_t)ttl << 8);
    /* RFC 1624. Protocol is the unchanged low byte of this word and cancels
     * from the replacement. Fold twice, including the checksum-zero case. */
    uint32_t sum = (uint32_t)(uint16_t)~checksum +
                   (uint32_t)(uint16_t)~old_word + new_word;
    sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
    sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
    checksum = (uint16_t)~sum;
    ip[8] = ttl;
    ip[10] = (uint8_t)(checksum >> 8);
    ip[11] = (uint8_t)checksum;
}

/* Bounds-checked TTL update. Returns 0 on success, -1 for NULL, TTL zero,
 * non-IPv4 Ethernet, invalid IHL, or a truncated/inconsistent IPv4 packet.
 * Failure leaves the frame unchanged. Existing checksum validity remains a
 * caller precondition; this function does not rescan the IPv4 header. */
int pg_packet_set_ttl(uint8_t *frame, size_t length, uint8_t ttl);

/*
 * Internet checksum over bytes, returned as a host-order integer. Serialize
 * its most significant byte first. An odd final byte occupies the high byte
 * of the last word. NULL with nonzero length returns zero.
 */
uint16_t pg_checksum(const uint8_t *data, size_t length);

/* Canonical raw TCP profile names: syn, ack, syn-ack, psh-ack, fin-ack, rst,
 * rst-ack. Parse returns 0 on success; -1 leaves *flags unchanged. Names are
 * case-sensitive and arbitrary bit combinations are not accepted. name returns
 * NULL for unsupported flags; zero names the backward-compatible SYN default.
 * These describe packet headers, not an established TCP connection. */
int pg_tcp_flags_parse(const char *name, uint8_t *flags);
const char *pg_tcp_flags_name(uint8_t flags);

#endif
