#include "streams.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int fail(char *error, size_t size, const char *format, ...)
{
    if (error && size) {
        va_list arguments;
        va_start(arguments, format);
        (void)vsnprintf(error, size, format, arguments);
        va_end(arguments);
        error[size - 1u] = '\0';
    }
    return -1;
}

static void clear_error(char *error, size_t size)
{
    if (error && size) error[0] = '\0';
}

static size_t bounded_length(const char *text)
{
    size_t length = 0;
    while (length <= PG_STREAM_LINE_MAX && text[length]) ++length;
    return length;
}

static bool name_valid(const char *name)
{
    size_t length = 0;
    for (; name[length]; ++length) {
        unsigned char c = (unsigned char)name[length];
        if (length == PG_STREAM_NAME_MAX ||
            !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
    }
    return length != 0;
}

static int decimal(const char *text, uint64_t minimum, uint64_t maximum,
                   uint64_t *value)
{
    uint64_t result = 0;
    if (!*text) return -1;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return -1;
        uint64_t digit = (uint64_t)(*p - '0');
        if (result > maximum / 10u ||
            (result == maximum / 10u && digit > maximum % 10u)) return -1;
        result = result * 10u + digit;
    }
    if (result < minimum) return -1;
    *value = result;
    return 0;
}

static uint64_t default_seed(const char *name)
{
    uint64_t result = UINT64_C(14695981039346656037);
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
        result ^= (uint64_t)*p;
        result *= UINT64_C(1099511628211);
    }
    return result ? result : UINT64_C(0x9e3779b97f4a7c15);
}

int pg_stream_parse(const char *text, struct pg_stream_spec *out,
                    char *error, size_t error_size)
{
    enum { NAME, PROTOCOL, PPS, UNLIMITED, COUNT, PAYLOAD, TTL_MIN, TTL_MAX,
           SEED, PAUSE, TCP_FLAGS, TCP_ACK, KEYS };
    static const char *const keys[KEYS] = {
        "name", "protocol", "pps", "unlimited", "count", "payload",
        "ttl-min", "ttl-max", "seed", "pause", "tcp-flags", "tcp-ack"
    };
    char copy[PG_STREAM_LINE_MAX + 1u];
    struct pg_stream_spec prepared = {0};
    uint32_t seen = 0;
    if (!text || !out) return fail(error, error_size, "Stream input/output is required");
    size_t length = bounded_length(text);
    if (!length || length > PG_STREAM_LINE_MAX)
        return fail(error, error_size, "Stream spec must contain 1..1024 bytes");
    for (size_t i = 0; i < length; ++i)
        if ((unsigned char)text[i] < 33u || (unsigned char)text[i] > 126u)
            return fail(error, error_size, "Stream spec must be printable ASCII without whitespace");
    memcpy(copy, text, length + 1u);
    prepared.count = UINT64_MAX;
    prepared.ttl_min = prepared.ttl_max = 64;
    char *field = copy;
    while (*field) {
        char *next = strchr(field, ',');
        if (next) *next = '\0';
        char *equals = strchr(field, '=');
        if (!equals || equals == field || !equals[1] || strchr(equals + 1, '='))
            return fail(error, error_size, "Every stream field must be key=value");
        *equals = '\0';
        char *value = equals + 1;
        unsigned key = 0;
        while (key < KEYS && strcmp(field, keys[key])) ++key;
        if (key == KEYS) return fail(error, error_size, "Unknown stream key: %s", field);
        uint32_t bit = UINT32_C(1) << key;
        if (seen & bit) return fail(error, error_size, "Duplicate stream key: %s", field);
        seen |= bit;
        uint64_t number = 0;
        switch (key) {
        case NAME:
            if (!name_valid(value)) return fail(error, error_size, "Stream name must contain 1..31 ASCII letters/digits/_/-");
            memcpy(prepared.name, value, strlen(value) + 1u);
            break;
        case PROTOCOL:
            if (!strcmp(value, "udp")) prepared.protocol = PG_UDP;
            else if (!strcmp(value, "tcp")) prepared.protocol = PG_TCP;
            else if (!strcmp(value, "icmp")) prepared.protocol = PG_ICMP;
            else return fail(error, error_size, "Stream protocol must be udp, tcp or icmp");
            break;
        case PPS:
            if (decimal(value, 1, PG_STREAM_MAX_PPS, &prepared.pps))
                return fail(error, error_size, "Stream pps must be 1..1000000000");
            break;
        case UNLIMITED:
            if (strcmp(value, "1")) return fail(error, error_size, "Use unlimited=1 or an explicit pps");
            prepared.unlimited = true;
            break;
        case COUNT:
            if (decimal(value, 1, UINT64_MAX, &prepared.count))
                return fail(error, error_size, "Stream count must be 1..UINT64_MAX");
            break;
        case PAYLOAD:
            if (decimal(value, 0, PG_MAX_PAYLOAD, &number))
                return fail(error, error_size, "Stream payload must be 0..1400");
            prepared.payload_size = (uint16_t)number;
            break;
        case TTL_MIN:
        case TTL_MAX:
            if (decimal(value, 1, 255, &number))
                return fail(error, error_size, "Stream TTL must be 1..255");
            if (key == TTL_MIN) prepared.ttl_min = (uint8_t)number;
            else prepared.ttl_max = (uint8_t)number;
            break;
        case SEED:
            if (decimal(value, 1, UINT64_MAX, &prepared.seed))
                return fail(error, error_size, "Stream seed must be 1..UINT64_MAX");
            break;
        case PAUSE:
            if (strcmp(value, "0") && strcmp(value, "1"))
                return fail(error, error_size, "Stream pause must be 0 or 1");
            prepared.paused = !strcmp(value, "1");
            break;
        case TCP_FLAGS:
            if (pg_tcp_flags_parse(value, &prepared.tcp_flags))
                return fail(error, error_size, "Unsupported raw TCP flag profile");
            break;
        case TCP_ACK:
            if (decimal(value, 0, UINT32_MAX, &number))
                return fail(error, error_size, "TCP acknowledgment must be 0..4294967295");
            prepared.tcp_ack = (uint32_t)number;
            break;
        default:
            return fail(error, error_size, "Unexpected stream key");
        }
        if (!next) break;
        field = next + 1;
        if (!*field) return fail(error, error_size, "Stream spec has an empty trailing field");
    }
    uint32_t required = (UINT32_C(1) << NAME) | (UINT32_C(1) << PROTOCOL);
    if ((seen & required) != required)
        return fail(error, error_size, "Stream name and protocol are required");
    if (((seen >> PPS) & 1u) == ((seen >> UNLIMITED) & 1u))
        return fail(error, error_size, "Choose exactly one of stream pps or unlimited=1");
    if (((seen >> TTL_MIN) & 1u) != ((seen >> TTL_MAX) & 1u) || prepared.ttl_min > prepared.ttl_max)
        return fail(error, error_size, "Specify both TTL bounds with ttl-min<=ttl-max");
    if (prepared.protocol != PG_TCP &&
        (seen & ((UINT32_C(1) << TCP_FLAGS) | (UINT32_C(1) << TCP_ACK))))
        return fail(error, error_size, "TCP flag/acknowledgment fields require protocol=tcp");
    if (prepared.tcp_ack != 0 && !(prepared.tcp_flags & 0x10u))
        return fail(error, error_size, "A nonzero TCP acknowledgment requires an ACK profile");
    prepared.explicit_ttl = (seen & (UINT32_C(1) << TTL_MIN)) != 0;
    prepared.explicit_seed = (seen & (UINT32_C(1) << SEED)) != 0;
    if (!(seen & (UINT32_C(1) << PAYLOAD))) prepared.payload_size = prepared.protocol == PG_TCP ? 6 : 18;
    if (!(seen & (UINT32_C(1) << SEED))) prepared.seed = default_seed(prepared.name);
    *out = prepared;
    clear_error(error, error_size);
    return 0;
}

static char *token(char **cursor)
{
    char *start = *cursor;
    while (*start == ' ') ++start;
    if (!*start) { *cursor = start; return NULL; }
    char *end = start;
    while (*end && *end != ' ') ++end;
    if (*end) *end++ = '\0';
    *cursor = end;
    return start;
}

int pg_stream_command_parse(const char *text, struct pg_stream_command *out,
                            char *error, size_t error_size)
{
    char copy[PG_STREAM_LINE_MAX + 1u];
    struct pg_stream_command prepared = {0};
    if (!text || !out) return fail(error, error_size, "Command input/output is required");
    size_t length = bounded_length(text);
    if (!length || length > PG_STREAM_LINE_MAX)
        return fail(error, error_size, "Command must contain 1..1024 bytes");
    if (text[length - 1u] == '\n') {
        --length;
        if (length && text[length - 1u] == '\r') --length;
    }
    for (size_t i = 0; i < length; ++i)
        if ((unsigned char)text[i] < 32u || (unsigned char)text[i] > 126u)
            return fail(error, error_size, "Command must be one printable ASCII line");
    memcpy(copy, text, length);
    copy[length] = '\0';
    char *cursor = copy;
    char *verb = token(&cursor);
    if (!verb) return fail(error, error_size, "Command is empty");
    if (!strcmp(verb, "help")) prepared.kind = PG_STREAM_CMD_HELP;
    else if (!strcmp(verb, "status")) prepared.kind = PG_STREAM_CMD_STATUS;
    else if (!strcmp(verb, "stop")) prepared.kind = PG_STREAM_CMD_STOP;
    else if (!strcmp(verb, "pause")) prepared.kind = PG_STREAM_CMD_PAUSE;
    else if (!strcmp(verb, "resume")) prepared.kind = PG_STREAM_CMD_RESUME;
    else if (!strcmp(verb, "remove")) prepared.kind = PG_STREAM_CMD_REMOVE;
    else if (!strcmp(verb, "rate")) prepared.kind = PG_STREAM_CMD_RATE;
    else if (!strcmp(verb, "count")) prepared.kind = PG_STREAM_CMD_COUNT;
    else if (!strcmp(verb, "ttl")) prepared.kind = PG_STREAM_CMD_TTL;
    else if (!strcmp(verb, "add")) prepared.kind = PG_STREAM_CMD_ADD;
    else return fail(error, error_size, "Unknown stream command");
    if (prepared.kind == PG_STREAM_CMD_ADD) {
        char *spec = token(&cursor);
        if (!spec || token(&cursor)) return fail(error, error_size, "Use add STREAMSPEC");
        if (pg_stream_parse(spec, &prepared.value.add, error, error_size)) return -1;
        memcpy(prepared.name, prepared.value.add.name, sizeof(prepared.name));
    } else if (prepared.kind != PG_STREAM_CMD_HELP && prepared.kind != PG_STREAM_CMD_STATUS &&
               prepared.kind != PG_STREAM_CMD_STOP) {
        char *name = token(&cursor);
        if (!name || !name_valid(name)) return fail(error, error_size, "Command requires a valid stream name");
        memcpy(prepared.name, name, strlen(name) + 1u);
        uint64_t number = 0;
        if (prepared.kind == PG_STREAM_CMD_RATE || prepared.kind == PG_STREAM_CMD_COUNT) {
            char *value = token(&cursor);
            if (!value) return fail(error, error_size, "Rate/count command requires a value");
            if (prepared.kind == PG_STREAM_CMD_RATE && !strcmp(value, "unlimited"))
                prepared.value.rate.unlimited = true;
            else if (decimal(value, 1, prepared.kind == PG_STREAM_CMD_RATE ? PG_STREAM_MAX_PPS : UINT64_MAX, &number))
                return fail(error, error_size, "Invalid command rate/count value");
            else if (prepared.kind == PG_STREAM_CMD_RATE) prepared.value.rate.pps = number;
            else prepared.value.count = number;
        } else if (prepared.kind == PG_STREAM_CMD_TTL) {
            char *minimum = token(&cursor), *maximum = token(&cursor);
            if (!minimum || !maximum || decimal(minimum, 1, 255, &number))
                return fail(error, error_size, "Use ttl NAME MIN MAX with bounds 1..255");
            prepared.value.ttl.min = (uint8_t)number;
            if (decimal(maximum, 1, 255, &number) || prepared.value.ttl.min > number)
                return fail(error, error_size, "TTL bounds must satisfy 1<=MIN<=MAX<=255");
            prepared.value.ttl.max = (uint8_t)number;
        }
    }
    if (token(&cursor)) return fail(error, error_size, "Unexpected trailing command arguments");
    *out = prepared;
    clear_error(error, error_size);
    return 0;
}

uint64_t pg_stream_rng_next(uint64_t *state)
{
    if (!state) return 0;
    uint64_t value = *state ? *state : UINT64_C(0x9e3779b97f4a7c15);
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    *state = value;
    return value * UINT64_C(2685821657736338717);
}

uint8_t pg_stream_random_ttl(uint64_t *state, uint8_t minimum, uint8_t maximum)
{
    if (!state || !minimum || minimum > maximum) return 0;
    if (minimum == maximum) return minimum;
    uint64_t width = (uint64_t)maximum - minimum + 1u;
    /* xorshift* visits every nonzero uint64_t, so subtract one to obtain
     * exactly UINT64_MAX possible values, then keep a multiple of width. */
    uint64_t limit = UINT64_MAX - (UINT64_MAX % width);
    uint64_t value;
    do { value = pg_stream_rng_next(state) - 1u; } while (value >= limit);
    return (uint8_t)((uint64_t)minimum + value % width);
}
