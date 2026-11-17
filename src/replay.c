#include "replay.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static int fail(char *error, size_t error_size, const char *message)
{
    if (error != NULL && error_size != 0u)
        (void)snprintf(error, error_size, "%s", message);
    return -1;
}

static uint16_t be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static uint16_t file16(const uint8_t *data, bool little)
{
    if (little) return (uint16_t)(((uint16_t)data[1] << 8) | data[0]);
    return be16(data);
}

static uint32_t file32(const uint8_t *data, bool little)
{
    if (little)
        return ((uint32_t)data[3] << 24) | ((uint32_t)data[2] << 16) |
               ((uint32_t)data[1] << 8) | data[0];
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) | data[3];
}

static uint32_t checksum_sum(uint32_t sum, const uint8_t *data, size_t size)
{
    while (size >= 2u) {
        sum += be16(data);
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
        data += 2;
        size -= 2u;
    }
    if (size != 0u) sum += (uint32_t)data[0] << 8;
    return sum;
}

static bool checksum_valid(uint32_t sum)
{
    while (sum >> 16) sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
    return sum == UINT32_C(0xffff);
}

static bool options_valid(const uint8_t *options, size_t length)
{
    for (size_t position = 0; position < length;) {
        uint8_t kind = options[position];
        if (kind == 0u) {
            /* IPv4 option padding after End of Option List is zero. */
            while (++position < length)
                if (options[position] != 0u) return false;
            return true;
        }
        if (kind == 1u) {
            ++position;
            continue;
        }
        if (length - position < 2u) return false;
        size_t option_length = options[position + 1u];
        if (option_length < 2u || option_length > length - position) return false;
        position += option_length;
    }
    return true;
}

static int frame_validate(const uint8_t *frame, uint32_t length,
                          enum pg_protocol *protocol,
                          char *error, size_t error_size)
{
    if (frame == NULL || length < 34u || length > PG_MAX_FRAME_SIZE)
        return fail(error, error_size, "frame length is outside supported Ethernet bounds");
    if (be16(frame + 12u) != UINT16_C(0x0800))
        return fail(error, error_size, "only untagged Ethernet IPv4 frames are supported");
    const uint8_t *ip = frame + 14u;
    size_t available = (size_t)length - 14u;
    size_t header_length = (size_t)(ip[0] & 15u) * 4u;
    size_t ip_length = be16(ip + 2u);
    if ((ip[0] >> 4) != 4u || header_length < 20u ||
        header_length > available || ip_length < header_length ||
        ip_length > available)
        return fail(error, error_size, "IPv4 header or total length is invalid");
    if (ip[8] == 0u)
        return fail(error, error_size, "IPv4 TTL must be nonzero for replay");
    if ((be16(ip + 6u) & UINT16_C(0xbfff)) != 0u)
        return fail(error, error_size, "fragmented or reserved-flag IPv4 frames are unsupported");
    if (!options_valid(ip + 20u, header_length - 20u))
        return fail(error, error_size, "IPv4 options have invalid lengths or padding");
    if (!checksum_valid(checksum_sum(0u, ip, header_length)))
        return fail(error, error_size, "IPv4 header checksum is invalid");

    const uint8_t *transport = ip + header_length;
    size_t transport_length = ip_length - header_length;
    uint32_t sum = 0;
    if (ip[9] == PG_UDP || ip[9] == PG_TCP) {
        sum = checksum_sum(0u, ip + 12u, 8u);
        sum += ip[9];
        sum += (uint32_t)transport_length;
    }
    switch (ip[9]) {
    case PG_UDP:
        if (transport_length < 8u || be16(transport + 4u) != transport_length)
            return fail(error, error_size, "UDP length is invalid");
        if (be16(transport + 6u) != 0u &&
            !checksum_valid(checksum_sum(sum, transport, transport_length)))
            return fail(error, error_size, "UDP checksum is invalid");
        *protocol = PG_UDP;
        break;
    case PG_TCP:
        if (transport_length < 20u || (transport[12] >> 4) < 5u ||
            (size_t)(transport[12] >> 4) * 4u > transport_length)
            return fail(error, error_size, "TCP header length is invalid");
        if (!checksum_valid(checksum_sum(sum, transport, transport_length)))
            return fail(error, error_size, "TCP checksum is invalid");
        *protocol = PG_TCP;
        break;
    case PG_ICMP:
        if (transport_length < 8u)
            return fail(error, error_size, "ICMP message is shorter than eight bytes");
        if (!checksum_valid(checksum_sum(0u, transport, transport_length)))
            return fail(error, error_size, "ICMP checksum is invalid");
        *protocol = PG_ICMP;
        break;
    default:
        return fail(error, error_size, "only IPv4 TCP, UDP, and ICMP are supported");
    }
    return 0;
}

void pg_replay_free(struct pg_replay_capture *capture)
{
    if (capture == NULL) return;
    for (size_t i = 0; i < capture->count; ++i) free(capture->frames[i].data);
    free(capture->frames);
    memset(capture, 0, sizeof(*capture));
}

int pg_replay_load_file(FILE *file, struct pg_replay_capture *capture,
                        char *error, size_t error_size)
{
    struct pg_replay_capture loaded = {0};
    uint8_t global[24], record[16];
    uint64_t consumed = sizeof(global), first = 0, previous = 0;
    bool little, nano;
    const char *failure = NULL;
    size_t capacity = 0;
    if (file == NULL || capture == NULL)
        return fail(error, error_size, "PCAP stream and output capture are required");
    if (fread(global, 1u, sizeof(global), file) != sizeof(global))
        return fail(error, error_size, "PCAP global header is missing or truncated");
    if (memcmp(global, "\xd4\xc3\xb2\xa1", 4u) == 0) {
        little = true; nano = false;
    } else if (memcmp(global, "\xa1\xb2\xc3\xd4", 4u) == 0) {
        little = false; nano = false;
    } else if (memcmp(global, "\x4d\x3c\xb2\xa1", 4u) == 0) {
        little = true; nano = true;
    } else if (memcmp(global, "\xa1\xb2\x3c\x4d", 4u) == 0) {
        little = false; nano = true;
    } else {
        return fail(error, error_size, "unsupported capture format; classic PCAP is required");
    }
    if (file16(global + 4u, little) != 2u || file16(global + 6u, little) != 4u)
        return fail(error, error_size, "PCAP version must be 2.4");
    uint32_t snaplen = file32(global + 16u, little);
    if (snaplen == 0u || file32(global + 20u, little) != 1u)
        return fail(error, error_size, "PCAP requires positive snaplen and Ethernet link type 1");

    for (;;) {
        /* A one-byte lookahead distinguishes exact EOF from oversized input. */
        int first_byte = fgetc(file);
        if (first_byte == EOF) {
            if (ferror(file)) failure = "error reading PCAP stream";
            break;
        }
        if (consumed >= PG_REPLAY_MAX_INPUT_BYTES) {
            failure = "PCAP exceeds the 64 MiB input limit"; break;
        }
        ++consumed;
        record[0] = (uint8_t)first_byte;
        if (PG_REPLAY_MAX_INPUT_BYTES - consumed < sizeof(record) - 1u) {
            failure = "PCAP exceeds the 64 MiB input limit"; break;
        }
        size_t got = fread(record + 1u, 1u, sizeof(record) - 1u, file);
        consumed += got;
        if (got != sizeof(record) - 1u) {
            failure = "PCAP record header is truncated"; break;
        }
        if (loaded.count >= PG_REPLAY_MAX_FRAMES) {
            failure = "PCAP exceeds the 100000-frame limit"; break;
        }
        uint32_t seconds = file32(record, little);
        uint32_t fraction = file32(record + 4u, little);
        uint32_t included = file32(record + 8u, little);
        uint32_t original = file32(record + 12u, little);
        if (fraction >= (nano ? UINT32_C(1000000000) : UINT32_C(1000000))) {
            failure = "PCAP timestamp fraction is outside its resolution"; break;
        }
        uint64_t timestamp = (uint64_t)seconds * UINT64_C(1000000000) +
                             (uint64_t)fraction * (nano ? 1u : 1000u);
        if (loaded.count != 0u && timestamp < previous) {
            failure = "PCAP timestamps must be monotonic"; break;
        }
        if (included != original || included > snaplen || included < 34u ||
            included > PG_MAX_FRAME_SIZE) {
            failure = "PCAP record length is truncated or outside supported frame bounds"; break;
        }
        if ((uint64_t)included > PG_REPLAY_MAX_INPUT_BYTES - consumed) {
            failure = "PCAP exceeds the 64 MiB input limit"; break;
        }
        if (loaded.count == capacity) {
            size_t next = capacity == 0u ? 64u : capacity * 2u;
            if (next > PG_REPLAY_MAX_FRAMES) next = PG_REPLAY_MAX_FRAMES;
            struct pg_replay_frame *frames = realloc(loaded.frames, next * sizeof(*frames));
            if (frames == NULL) { failure = "cannot allocate PCAP frame table"; break; }
            loaded.frames = frames;
            capacity = next;
        }
        uint8_t *data = malloc(included);
        if (data == NULL) { failure = "cannot allocate PCAP frame bytes"; break; }
        got = fread(data, 1u, included, file);
        consumed += got;
        if (got != included) {
            free(data); failure = "PCAP frame bytes are truncated"; break;
        }
        enum pg_protocol protocol;
        if (frame_validate(data, included, &protocol, error, error_size) != 0) {
            free(data);
            pg_replay_free(&loaded);
            return -1;
        }
        if (loaded.count == 0u) first = timestamp;
        previous = timestamp;
        struct pg_replay_frame frame = {data, included, timestamp - first, protocol};
        loaded.frames[loaded.count++] = frame;
        loaded.captured_bytes += included;
        loaded.frame_bytes += included < PG_REPLAY_MIN_TX_FRAME ? PG_REPLAY_MIN_TX_FRAME : included;
        loaded.duration_ns = timestamp - first;
        if (protocol == PG_UDP) ++loaded.udp_packets;
        else if (protocol == PG_TCP) ++loaded.tcp_packets;
        else ++loaded.icmp_packets;
    }
    if (failure == NULL && loaded.count == 0u) failure = "PCAP contains no frames";
    if (failure != NULL) {
        pg_replay_free(&loaded);
        return fail(error, error_size, failure);
    }
    pg_replay_free(capture);
    *capture = loaded;
    if (error != NULL && error_size != 0u) error[0] = '\0';
    return 0;
}

int pg_replay_load(const char *path, struct pg_replay_capture *capture,
                   char *error, size_t error_size)
{
    if (path == NULL || path[0] == '\0' || capture == NULL)
        return fail(error, error_size, "PCAP path and output capture are required");
    FILE *file = fopen(path, "rb");
    if (file == NULL) return fail(error, error_size, "cannot open PCAP file");
    struct pg_replay_capture loaded = {0};
    int result = pg_replay_load_file(file, &loaded, error, error_size);
    if (fclose(file) != 0 && result == 0)
        result = fail(error, error_size, "cannot close PCAP input file");
    if (result != 0) {
        pg_replay_free(&loaded);
        return -1;
    }
    pg_replay_free(capture);
    *capture = loaded;
    return 0;
}

int pg_replay_validate_lab(const struct pg_replay_capture *capture,
                           const uint8_t source_ip[4],
                           const uint8_t destination_ip[4],
                           char *error, size_t error_size)
{
    if (capture == NULL || source_ip == NULL || destination_ip == NULL ||
        capture->frames == NULL || capture->count == 0u ||
        capture->count > PG_REPLAY_MAX_FRAMES)
        return fail(error, error_size, "nonempty capture and both lab fixture addresses are required");
    if (source_ip[0] != 198u || (source_ip[1] & 254u) != 18u ||
        destination_ip[0] != 198u || (destination_ip[1] & 254u) != 18u ||
        memcmp(source_ip, destination_ip, 4u) == 0)
        return fail(error, error_size, "distinct lab fixture addresses in 198.18.0.0/15 are required");
    for (size_t i = 0; i < capture->count; ++i) {
        const struct pg_replay_frame *frame = &capture->frames[i];
        enum pg_protocol protocol;
        if (frame_validate(frame->data, frame->length, &protocol, error, error_size) != 0)
            return -1;
        if (memcmp(frame->data + 26u, source_ip, 4u) != 0 ||
            memcmp(frame->data + 30u, destination_ip, 4u) != 0)
            return fail(error, error_size, "capture frame addresses do not match the declared lab direction");
    }
    if (error != NULL && error_size != 0u) error[0] = '\0';
    return 0;
}
