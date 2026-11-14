/*
 * Native unit tests for the eBPF parsing code (varint.h, protocol.h,
 * bedrock.h and the helpers in common.h).
 *
 * Compiled for the host (not for BPF) and executed by tests/c_unit_tests.rs
 * as part of `cargo test`, with ASan/UBSan enabled when available. Every
 * inspector call runs on an exact-size heap copy of the packet, so any read
 * past data_end trips the address sanitizer instead of going unnoticed.
 */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// provided by bpf/bpf_helpers.h in the BPF build
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/*
 * Stand-in for xdp/config.h, suppressed via its include guard: the real header
 * defines the knobs `volatile const`, but the login tests need to flip
 * ONLINE_NAMES at runtime.
 */
#define CONFIG_H
static volatile __u8 ONLINE_NAMES = 1;
static volatile __u32 RAKNET_PROTO_MIN = 9;
static volatile __u32 RAKNET_PROTO_MAX = 11;
static volatile __u32 RAKNET_OCR1_MIN = 400;
static volatile __u8 GUARD_TLS = 1;
static volatile __u8 GUARD_HTTP = 1;
static volatile __u32 UDPGUARD_FIRST_BYTE = 0xFF;
static volatile __u32 UDPGUARD_MIN_LEN = 17;

#include "../common.h"
#include "../varint.h"
#include "../protocol.h"
#include "../bedrock.h"
#include "../voice.h"

/* ------------------------------------------------------------------------
 * Tiny test framework
 * --------------------------------------------------------------------- */

static unsigned checks_run = 0;
static unsigned checks_failed = 0;

#define CHECK(cond)                                                          \
    do                                                                       \
    {                                                                        \
        checks_run++;                                                        \
        if (!(cond))                                                         \
        {                                                                    \
            checks_failed++;                                                 \
            printf("FAIL %s:%d in %s: %s\n", __FILE__, __LINE__, __func__,   \
                   #cond);                                                   \
        }                                                                    \
    } while (0)

/* ------------------------------------------------------------------------
 * Packet building helpers
 * --------------------------------------------------------------------- */

// reference varint encoder, validated against the wiki.vg test vectors below
static __u32 write_varint(__u8 *out, __s32 value)
{
    __u32 v = (__u32)value;
    __u32 n = 0;
    do
    {
        __u8 byte = v & 0x7F;
        v >>= 7;
        if (v)
        {
            byte |= 0x80;
        }
        out[n++] = byte;
    } while (v);
    return n;
}

struct buf
{
    __u8 b[4096];
    __u32 n;
};

static void put_varint(struct buf *p, __s32 value)
{
    p->n += write_varint(p->b + p->n, value);
}

static void put_u8(struct buf *p, __u8 value)
{
    p->b[p->n++] = value;
}

static void put_fill(struct buf *p, __u8 fill, __u32 count)
{
    memset(p->b + p->n, fill, count);
    p->n += count;
}

// prefixes a packet body with its length varint, like the protocol does
static struct buf packetize(const struct buf *body)
{
    struct buf pkt = {{0}, 0};
    put_varint(&pkt, (__s32)body->n);
    memcpy(pkt.b + pkt.n, body->b, body->n);
    pkt.n += body->n;
    return pkt;
}

/* ------------------------------------------------------------------------
 * Runners: every parse happens on an exact-size heap copy so ASan catches
 * any access past data_end. `slack` adds extra bytes between payload_end
 * and data_end to exercise the dual-bounds checks.
 * --------------------------------------------------------------------- */

static __u8 *heap_copy(const __u8 *bytes, __u32 len, __u32 slack)
{
    const __u32 size = len + slack;
    __u8 *heap = malloc(size ? size : 1); // malloc(0) may return NULL
    if (len)
    {
        memcpy(heap, bytes, len);
    }
    if (slack)
    {
        // 0x01 terminates a varint, so a parser that wrongly runs past
        // payload_end produces a successful-looking parse the assertions
        // can catch (instead of failing by coincidence)
        memset(heap + len, 0x01, slack);
    }
    return heap;
}

static struct varint_value run_varint_slack(const __u8 *bytes, __u32 payload_len, __u32 slack, __u8 max_size)
{
    __u8 *heap = heap_copy(bytes, payload_len, slack);
    const struct varint_value v =
        read_varint_sized(heap, heap + payload_len, max_size, heap + payload_len + slack);
    free(heap);
    return v;
}

static struct varint_value run_varint(const __u8 *bytes, __u32 payload_len, __u8 max_size)
{
    return run_varint_slack(bytes, payload_len, 0, max_size);
}

static __u8 run_status_slack(const __u8 *pkt, __u32 len, __u32 slack)
{
    __u8 *heap = heap_copy(pkt, len, slack);
    const __u8 ok = inspect_status_request(heap, heap + len, heap + len + slack);
    free(heap);
    return ok;
}

static __u8 run_status(const __u8 *pkt, __u32 len)
{
    return run_status_slack(pkt, len, 0);
}

static __u8 run_ping(const __u8 *pkt, __u32 len)
{
    __u8 *heap = heap_copy(pkt, len, 0);
    const __u8 ok = inspect_ping_request(heap, heap + len, heap + len);
    free(heap);
    return ok;
}

static __u8 run_login(const __u8 *pkt, __u32 len, __s32 protocol)
{
    __u8 *heap = heap_copy(pkt, len, 0);
    const __u8 ok = inspect_login_packet(heap, heap + len, heap + len, protocol);
    free(heap);
    return ok;
}

// location of the server address reported by the last run_handshake()
static __u32 last_host_offset = 0;
static __u32 last_host_len = 0;

static __s32 run_handshake(const __u8 *pkt, __u32 len, __s32 *proto_out, __u32 *resume_off)
{
    __u8 *heap = heap_copy(pkt, len, 0);
    const __u8 *resume = NULL;
    const __u8 *host = NULL;
    __s32 proto = 0;
    last_host_len = 0;
    const __s32 state = inspect_handshake(heap, heap + len, heap + len, &proto, &resume, &host, &last_host_len);
    last_host_offset = host ? (__u32)(host - heap) : 0;
    if (proto_out)
    {
        *proto_out = proto;
    }
    if (resume_off)
    {
        *resume_off = resume ? (__u32)(resume - heap) : 0;
    }
    free(heap);
    return state;
}

/* ------------------------------------------------------------------------
 * VARINT_SIZE (compile-time)
 * --------------------------------------------------------------------- */

_Static_assert(VARINT_SIZE(0x00) == 1, "VARINT_SIZE(0)");
_Static_assert(VARINT_SIZE(0x7F) == 1, "VARINT_SIZE(127)");
_Static_assert(VARINT_SIZE(0x80) == 2, "VARINT_SIZE(128)");
_Static_assert(VARINT_SIZE(0x3FFF) == 2, "VARINT_SIZE(16383)");
_Static_assert(VARINT_SIZE(0x4000) == 3, "VARINT_SIZE(16384)");
_Static_assert(VARINT_SIZE(0x1FFFFF) == 3, "VARINT_SIZE(2097151)");
_Static_assert(VARINT_SIZE(0x200000) == 4, "VARINT_SIZE(2097152)");
_Static_assert(VARINT_SIZE(0xFFFFFFF) == 4, "VARINT_SIZE(268435455)");
_Static_assert(VARINT_SIZE(0x10000000) == 5, "VARINT_SIZE(268435456)");

/* ------------------------------------------------------------------------
 * Varint reader
 * --------------------------------------------------------------------- */

// test vectors from the protocol documentation (wiki.vg)
static const struct
{
    __u8 bytes[5];
    __u32 len;
    __s32 value;
} VARINT_VECTORS[] = {
    {{0x00}, 1, 0},
    {{0x01}, 1, 1},
    {{0x02}, 1, 2},
    {{0x7F}, 1, 127},
    {{0x80, 0x01}, 2, 128},
    {{0xFF, 0x01}, 2, 255},
    {{0xDD, 0xC7, 0x01}, 3, 25565},
    {{0xFF, 0xFF, 0x7F}, 3, 2097151},
    {{0xFF, 0xFF, 0xFF, 0xFF, 0x07}, 5, 2147483647},
    {{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}, 5, -1},
    {{0x80, 0x80, 0x80, 0x80, 0x08}, 5, -2147483647 - 1},
};

static void test_varint_decodes_known_vectors(void)
{
    for (__u32 i = 0; i < sizeof(VARINT_VECTORS) / sizeof(VARINT_VECTORS[0]); i++)
    {
        const struct varint_value v =
            run_varint(VARINT_VECTORS[i].bytes, VARINT_VECTORS[i].len, MAX_VARINT_BYTES);
        CHECK(v.value == VARINT_VECTORS[i].value);
        CHECK(v.bytes == VARINT_VECTORS[i].len);

        // the encoder used by the packet builders must produce these
        // exact bytes, otherwise all later tests would test nothing
        __u8 encoded[5] = {0};
        const __u32 n = write_varint(encoded, VARINT_VECTORS[i].value);
        CHECK(n == VARINT_VECTORS[i].len);
        CHECK(memcmp(encoded, VARINT_VECTORS[i].bytes, n) == 0);
    }
}

static void test_varint_roundtrip(void)
{
    static const __s32 VALUES[] = {0,     1,        2,       127,        128,        255,
                                   300,   16383,    16384,   25565,      2097151,    2097152,
                                   -1,    -25565,   268435455, 268435456, 2147483647, -2147483647 - 1};
    for (__u32 i = 0; i < sizeof(VALUES) / sizeof(VALUES[0]); i++)
    {
        __u8 encoded[5];
        const __u32 n = write_varint(encoded, VALUES[i]);
        const struct varint_value v = run_varint(encoded, n, MAX_VARINT_BYTES);
        CHECK(v.value == VALUES[i]);
        CHECK(v.bytes == n);
    }
}

static void test_varint_rejects_truncated_input(void)
{
    const __u8 two_byte[] = {0x80, 0x01};
    CHECK(run_varint(two_byte, 1, MAX_VARINT_BYTES).bytes == 0); // continuation cut off
    CHECK(run_varint(two_byte, 0, MAX_VARINT_BYTES).bytes == 0); // empty payload

    const __u8 three_byte[] = {0xDD, 0xC7, 0x01};
    CHECK(run_varint(three_byte, 2, MAX_VARINT_BYTES).bytes == 0);
}

static void test_varint_respects_max_size(void)
{
    const __u8 two_byte[] = {0x80, 0x01};
    CHECK(run_varint(two_byte, 2, 1).bytes == 0);
    CHECK(run_varint(two_byte, 2, 2).bytes == 2);

    const __u8 three_byte[] = {0xDD, 0xC7, 0x01};
    CHECK(run_varint(three_byte, 3, 2).bytes == 0);
    CHECK(run_varint(three_byte, 3, 3).bytes == 3);
}

static void test_varint_never_reads_past_payload_end(void)
{
    // a continuation byte at the end of the payload, with valid-looking
    // bytes behind payload_end: must fail instead of reading the slack
    const __u8 bytes[] = {0x80};
    CHECK(run_varint_slack(bytes, 1, 4, MAX_VARINT_BYTES).bytes == 0);
}

static void test_varint_stops_at_terminator(void)
{
    // trailing bytes after a complete varint are someone else's business
    const __u8 bytes[] = {0x01, 0xFF, 0xFF};
    const struct varint_value v = run_varint(bytes, 3, MAX_VARINT_BYTES);
    CHECK(v.value == 1);
    CHECK(v.bytes == 1);
}

static void test_varint_rejects_overlong_encoding(void)
{
    // continuation bit still set on the fifth byte: a sixth byte would be
    // required, which no 32-bit varint may have
    const __u8 bytes[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01};
    CHECK(run_varint(bytes, 6, MAX_VARINT_BYTES).bytes == 0);
}

/* ------------------------------------------------------------------------
 * Bounds-check macros
 * --------------------------------------------------------------------- */

static __u8 wrap_check_bounds(const __u8 *cursor, __u32 n, const __u8 *pend, const void *dend)
{
    CHECK_BOUNDS_OR_RETURN(cursor, n, pend, dend);
    return 1;
}

static __u8 wrap_skip_twice(const __u8 *cursor, __u32 a, __u32 b, const __u8 *pend, const void *dend)
{
    SKIP_OR_RETURN(cursor, a, pend, dend);
    SKIP_OR_RETURN(cursor, b, pend, dend);
    return 1;
}

static __u8 wrap_read_u64(const __u8 *cursor, const __u8 *pend, const void *dend, __u64 *out)
{
    READ_VAL_OR_RETURN(*out, cursor, pend, dend);
    return 1;
}

static void test_bounds_macros(void)
{
    __u8 *heap = malloc(16);
    for (__u8 i = 0; i < 16; i++)
    {
        heap[i] = i;
    }
    const __u8 *pend = heap + 16;

    CHECK(wrap_check_bounds(heap, 16, pend, pend) == 1);
    CHECK(wrap_check_bounds(heap, 17, pend, pend) == 0);
    CHECK(wrap_check_bounds(heap + 16, 0, pend, pend) == 1);
    // payload_end binds even when data_end leaves room
    CHECK(wrap_check_bounds(heap, 10, heap + 8, pend) == 0);

    CHECK(wrap_skip_twice(heap, 8, 8, pend, pend) == 1);
    CHECK(wrap_skip_twice(heap, 8, 9, pend, pend) == 0);

    __u64 value = 0;
    CHECK(wrap_read_u64(heap, pend, pend, &value) == 1);
    CHECK(value == 0x0706050403020100ULL); // little endian
    // unaligned read is fine by design (network data)
    CHECK(wrap_read_u64(heap + 1, pend, pend, &value) == 1);
    CHECK(value == 0x0807060504030201ULL);
    CHECK(wrap_read_u64(heap + 9, pend, pend, &value) == 0);

    free(heap);
}

/* ------------------------------------------------------------------------
 * Status request: [len=0x01][id=0x00]
 * --------------------------------------------------------------------- */

static void test_status_request(void)
{
    const __u8 valid[] = {0x01, 0x00};
    CHECK(run_status(valid, 2) == 1);
    // bytes beyond payload_end must not change the verdict
    CHECK(run_status_slack(valid, 2, 8) == 1);

    const __u8 wrong_len[] = {0x02, 0x00};
    CHECK(run_status(wrong_len, 2) == 0);

    const __u8 wrong_id[] = {0x01, 0x01};
    CHECK(run_status(wrong_id, 2) == 0);

    const __u8 trailing[] = {0x01, 0x00, 0x00};
    CHECK(run_status(trailing, 3) == 0);

    const __u8 non_canonical_len[] = {0x81, 0x00, 0x00};
    CHECK(run_status(non_canonical_len, 3) == 0);

    CHECK(run_status(valid, 1) == 0);
    CHECK(run_status(valid, 0) == 0);
}

/* ------------------------------------------------------------------------
 * Ping request: [len=0x09][id=0x01][8 byte timestamp]
 * --------------------------------------------------------------------- */

static void test_ping_request(void)
{
    const __u8 valid[] = {0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(run_ping(valid, 10) == 1);

    CHECK(run_ping(valid, 9) == 0); // truncated timestamp

    const __u8 wrong_id[] = {0x09, 0x00, 1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(run_ping(wrong_id, 10) == 0);

    const __u8 wrong_len[] = {0x08, 0x01, 1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(run_ping(wrong_len, 10) == 0);

    const __u8 trailing[] = {0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    CHECK(run_ping(trailing, 11) == 0);
}

/* ------------------------------------------------------------------------
 * Handshake: [len][id=0x00][protocol][host len][host][port][intention]
 * --------------------------------------------------------------------- */

static struct buf build_handshake(__s32 protocol, __u32 host_len, __s32 intention)
{
    struct buf body = {{0}, 0};
    put_varint(&body, 0x00); // packet id
    put_varint(&body, protocol);
    put_varint(&body, (__s32)host_len);
    put_fill(&body, 'h', host_len);
    put_u8(&body, 0x63); // port 25565
    put_u8(&body, 0xDD);
    put_varint(&body, intention);
    return packetize(&body);
}

static void test_handshake_intentions(void)
{
    __s32 proto = 0;

    struct buf status = build_handshake(763, 14, 1);
    CHECK(run_handshake(status.b, status.n, &proto, NULL) == AWAIT_STATUS_REQUEST);
    CHECK(proto == 763);

    struct buf login = build_handshake(763, 14, 2);
    CHECK(run_handshake(login.b, login.n, &proto, NULL) == AWAIT_LOGIN);

    // intention 3 (transfer) exists since 1.20.5 (766)
    struct buf transfer_new = build_handshake(766, 14, 3);
    CHECK(run_handshake(transfer_new.b, transfer_new.n, &proto, NULL) == AWAIT_LOGIN);
    struct buf transfer_old = build_handshake(765, 14, 3);
    CHECK(run_handshake(transfer_old.b, transfer_old.n, &proto, NULL) == STATE_INVALID);

    struct buf intention_zero = build_handshake(763, 14, 0);
    CHECK(run_handshake(intention_zero.b, intention_zero.n, &proto, NULL) == STATE_INVALID);
    struct buf intention_four = build_handshake(763, 14, 4);
    CHECK(run_handshake(intention_four.b, intention_four.n, &proto, NULL) == STATE_INVALID);
}

static void test_handshake_legacy_ping(void)
{
    const __u8 legacy[] = {0xFE, 0x01};
    CHECK(run_handshake(legacy, 2, NULL, NULL) == RECEIVED_LEGACY_PING);
    CHECK(run_handshake(legacy, 1, NULL, NULL) == RECEIVED_LEGACY_PING);
    CHECK(run_handshake(legacy, 0, NULL, NULL) == STATE_INVALID);
}

static void test_handshake_rejects_malformed(void)
{
    // wrong packet id
    struct buf body = {{0}, 0};
    put_varint(&body, 0x01); // packet id 1 instead of 0
    put_varint(&body, 763);
    put_varint(&body, 0);
    put_u8(&body, 0x63);
    put_u8(&body, 0xDD);
    put_varint(&body, 1);
    struct buf wrong_id = packetize(&body);
    CHECK(run_handshake(wrong_id.b, wrong_id.n, NULL, NULL) == STATE_INVALID);

    // truncated: every prefix of a valid handshake must be rejected
    struct buf valid = build_handshake(763, 14, 1);
    for (__u32 len = 0; len < valid.n; len++)
    {
        CHECK(run_handshake(valid.b, len, NULL, NULL) == STATE_INVALID);
    }

    // length field below the minimum (smallest possible body is 6 bytes)
    const __u8 len_too_small[] = {0x03, 0x00, 0x00};
    CHECK(run_handshake(len_too_small, 3, NULL, NULL) == STATE_INVALID);

    // length field above the maximum (787)
    struct buf len_too_big = {{0}, 0};
    put_varint(&len_too_big, 788);
    put_fill(&len_too_big, 0x00, 8);
    CHECK(run_handshake(len_too_big.b, len_too_big.n, NULL, NULL) == STATE_INVALID);

    // host longer than the protocol allows (255 * 3 = 765)
    struct buf host_too_long = build_handshake(763, 766, 1);
    CHECK(run_handshake(host_too_long.b, host_too_long.n, NULL, NULL) == STATE_INVALID);

    // the longest legal host must still parse
    struct buf host_max = build_handshake(763, 765, 1);
    CHECK(run_handshake(host_max.b, host_max.n, NULL, NULL) == AWAIT_STATUS_REQUEST);

    // empty host is allowed by the protocol bounds
    struct buf host_empty = build_handshake(763, 0, 1);
    CHECK(run_handshake(host_empty.b, host_empty.n, NULL, NULL) == AWAIT_STATUS_REQUEST);
}

static void test_handshake_combined_with_status_request(void)
{
    struct buf pkt = build_handshake(763, 14, 1);
    const __u32 handshake_len = pkt.n;
    put_u8(&pkt, 0x01); // status request appended in the same segment
    put_u8(&pkt, 0x00);

    __s32 proto = 0;
    __u32 resume = 0;
    CHECK(run_handshake(pkt.b, pkt.n, &proto, &resume) == DIRECT_READ_STATUS_REQUEST);
    CHECK(resume == handshake_len);
    CHECK(run_status(pkt.b + resume, pkt.n - resume) == 1);
}

static void test_handshake_combined_with_login(void)
{
    struct buf pkt = build_handshake(765, 14, 2);
    const __u32 handshake_len = pkt.n;

    struct buf login_body = {{0}, 0};
    put_varint(&login_body, 0x00); // packet id
    put_varint(&login_body, 5);    // username length
    put_fill(&login_body, 'a', 5);
    put_fill(&login_body, 0xAB, 16); // uuid (1.20.2+)
    struct buf login = packetize(&login_body);
    memcpy(pkt.b + pkt.n, login.b, login.n);
    pkt.n += login.n;

    __s32 proto = 0;
    __u32 resume = 0;
    CHECK(run_handshake(pkt.b, pkt.n, &proto, &resume) == DIRECT_READ_LOGIN);
    CHECK(resume == handshake_len);
    CHECK(proto == 765);
    CHECK(run_login(pkt.b + resume, pkt.n - resume, proto) == 1);
}

static void test_handshake_rejects_length_mismatch(void)
{
    // valid fields, but the declared length is off by one: the backend's
    // frame decoder would cut the stream at a different offset than the
    // filter's state machine
    struct buf too_big = build_handshake(763, 14, 1);
    too_big.b[0]++;
    CHECK(run_handshake(too_big.b, too_big.n, NULL, NULL) == STATE_INVALID);

    struct buf too_small = build_handshake(763, 14, 1);
    too_small.b[0]--;
    CHECK(run_handshake(too_small.b, too_small.n, NULL, NULL) == STATE_INVALID);

    // the appended status request must not be reachable through a lying
    // handshake length either (the backend would read its bytes as part of
    // the handshake frame)
    struct buf combined = build_handshake(763, 14, 1);
    combined.b[0]++;
    put_u8(&combined, 0x01);
    put_u8(&combined, 0x00);
    CHECK(run_handshake(combined.b, combined.n, NULL, NULL) == STATE_INVALID);
}

/* ------------------------------------------------------------------------
 * Login request, all protocol eras:
 *   < 759            [id][name]
 *   759 (1.19)       [id][name][key block]
 *   760 (1.19.1/2)   [id][name][key block][has uuid + uuid]
 *   761+ (1.19.3)    [id][name][has uuid + uuid]
 *   764+ (1.20.2)    [id][name][uuid]
 * --------------------------------------------------------------------- */

static struct buf build_simple_login(__u32 name_len)
{
    struct buf body = {{0}, 0};
    put_varint(&body, 0x00); // packet id
    put_varint(&body, (__s32)name_len);
    put_fill(&body, 'a', name_len);
    return body; // callers append era-specific fields, then packetize
}

static void test_login_pre_1_19(void)
{
    struct buf body = build_simple_login(5);
    struct buf pkt = packetize(&body);
    CHECK(run_login(pkt.b, pkt.n, 47) == 1);  // 1.8
    CHECK(run_login(pkt.b, pkt.n, 758) == 1); // 1.18.2

    // 1.20.2+ requires a uuid after the name, so the same bytes must fail
    CHECK(run_login(pkt.b, pkt.n, 764) == 0);

    CHECK(run_login(pkt.b, pkt.n - 1, 47) == 0); // truncated
    put_u8(&pkt, 0x00);
    CHECK(run_login(pkt.b, pkt.n, 47) == 0); // trailing byte
    CHECK(run_login(pkt.b, 0, 47) == 0);     // empty payload
}

static void test_login_username_rules(void)
{
    // 16 chars is the online-mode maximum
    struct buf name16 = build_simple_login(16);
    struct buf pkt16 = packetize(&name16);
    CHECK(run_login(pkt16.b, pkt16.n, 758) == 1);

    struct buf name17 = build_simple_login(17);
    struct buf pkt17 = packetize(&name17);
    CHECK(run_login(pkt17.b, pkt17.n, 758) == 0);

    // offline mode allows up to 48 bytes (16 chars * 3 utf-8 bytes)
    ONLINE_NAMES = 0;
    CHECK(run_login(pkt17.b, pkt17.n, 758) == 1);
    struct buf name48 = build_simple_login(48);
    struct buf pkt48 = packetize(&name48);
    CHECK(run_login(pkt48.b, pkt48.n, 758) == 1);
    struct buf name49 = build_simple_login(49);
    struct buf pkt49 = packetize(&name49);
    CHECK(run_login(pkt49.b, pkt49.n, 758) == 0);
    ONLINE_NAMES = 1;

    // empty names are impossible
    struct buf name0 = build_simple_login(0);
    struct buf pkt0 = packetize(&name0);
    CHECK(run_login(pkt0.b, pkt0.n, 758) == 0);

    // a non-canonical two-byte encoding of name length 16 must be rejected
    // (the reader is limited to the canonical varint width)
    struct buf body = {{0}, 0};
    put_varint(&body, 0x00);
    put_u8(&body, 0x90); // 16 with a needless continuation byte
    put_u8(&body, 0x00);
    put_fill(&body, 'a', 16);
    struct buf pkt = packetize(&body);
    CHECK(run_login(pkt.b, pkt.n, 758) == 0);
}

static void test_login_1_19_key_block(void)
{
    // 1.19 - 1.19.2 (759/760): optional chat signing key after the name
    struct buf no_key = build_simple_login(5);
    put_u8(&no_key, 0x00); // has_public_key = false
    struct buf no_key_pkt = packetize(&no_key);
    CHECK(run_login(no_key_pkt.b, no_key_pkt.n, 759) == 1);

    struct buf with_key = build_simple_login(5);
    put_u8(&with_key, 0x01);       // has_public_key = true
    put_fill(&with_key, 0xEE, 8);  // expiry timestamp
    put_varint(&with_key, 16);     // key length
    put_fill(&with_key, 0xBB, 16); // key
    put_varint(&with_key, 32);     // signature length
    put_fill(&with_key, 0xCC, 32); // signature
    struct buf with_key_pkt = packetize(&with_key);
    CHECK(run_login(with_key_pkt.b, with_key_pkt.n, 759) == 1);

    // key larger than the protocol maximum (512)
    struct buf big_key = build_simple_login(5);
    put_u8(&big_key, 0x01);
    put_fill(&big_key, 0xEE, 8);
    put_varint(&big_key, 513);
    put_fill(&big_key, 0xBB, 513);
    put_varint(&big_key, 32);
    put_fill(&big_key, 0xCC, 32);
    struct buf big_key_pkt = packetize(&big_key);
    CHECK(run_login(big_key_pkt.b, big_key_pkt.n, 759) == 0);

    // 1.19.3 (761) dropped the key block again, so a packet carrying one
    // must be rejected there. (The no-key packet is coincidentally also a
    // valid 761 packet: its 0x00 then reads as has_uuid = false.)
    CHECK(run_login(with_key_pkt.b, with_key_pkt.n, 761) == 0);
    CHECK(run_login(no_key_pkt.b, no_key_pkt.n, 761) == 1);
}

static void test_login_uuid_eras(void)
{
    // 760 (1.19.1): key block, then optional uuid
    struct buf v760 = build_simple_login(5);
    put_u8(&v760, 0x00);          // has_public_key = false
    put_u8(&v760, 0x01);          // has_uuid = true
    put_fill(&v760, 0xAB, 16);    // uuid
    struct buf v760_pkt = packetize(&v760);
    CHECK(run_login(v760_pkt.b, v760_pkt.n, 760) == 1);

    struct buf v760_no_uuid = build_simple_login(5);
    put_u8(&v760_no_uuid, 0x00); // has_public_key = false
    put_u8(&v760_no_uuid, 0x00); // has_uuid = false
    struct buf v760_no_uuid_pkt = packetize(&v760_no_uuid);
    CHECK(run_login(v760_no_uuid_pkt.b, v760_no_uuid_pkt.n, 760) == 1);

    // 761/762 (1.19.3/4): no key block, optional uuid
    struct buf v762 = build_simple_login(5);
    put_u8(&v762, 0x01);
    put_fill(&v762, 0xAB, 16);
    struct buf v762_pkt = packetize(&v762);
    CHECK(run_login(v762_pkt.b, v762_pkt.n, 762) == 1);

    // 764+ (1.20.2): uuid always present, no flag
    struct buf v765 = build_simple_login(5);
    put_fill(&v765, 0xAB, 16);
    struct buf v765_pkt = packetize(&v765);
    CHECK(run_login(v765_pkt.b, v765_pkt.n, 765) == 1);

    // truncated uuid
    struct buf v765_short = build_simple_login(5);
    put_fill(&v765_short, 0xAB, 8);
    struct buf v765_short_pkt = packetize(&v765_short);
    CHECK(run_login(v765_short_pkt.b, v765_short_pkt.n, 765) == 0);
}

static void test_login_rejects_length_mismatch(void)
{
    // modern login (1.20.2+): name + uuid, with a length prefix off by one
    struct buf body = build_simple_login(5);
    put_fill(&body, 0xAB, 16); // uuid
    struct buf pkt = packetize(&body);
    CHECK(run_login(pkt.b, pkt.n, 765) == 1); // consistent length is fine

    pkt.b[0]++;
    CHECK(run_login(pkt.b, pkt.n, 765) == 0);

    pkt.b[0] -= 2;
    CHECK(run_login(pkt.b, pkt.n, 765) == 0);
}

/* ------------------------------------------------------------------------
 * Host filter hash
 * --------------------------------------------------------------------- */

// plain FNV-1a, what hash_host() has to produce for an already normalized name
static __u64 fnv1a64(const char *s)
{
    __u64 hash = 0xCBF29CE484222325ULL;
    for (; *s; s++)
    {
        hash = (hash ^ (__u8)*s) * 0x100000001B3ULL;
    }
    return hash;
}

// hashes `len` bytes of `host` on an exact-size heap copy; 0 = rejected
static __u64 run_hash_host(const char *host, __u32 len)
{
    __u8 *heap = heap_copy((const __u8 *)host, len, 0);
    __u64 hash = 0;
    const __u8 ok = hash_host(heap, len, heap + len, heap + len, &hash);
    free(heap);
    return ok ? hash : 0;
}

static void test_host_hash(void)
{
    // published FNV-1a 64 test vectors; loader/hosts.rs checks the same ones
    CHECK(fnv1a64("") == 0xCBF29CE484222325ULL);
    CHECK(fnv1a64("a") == 0xAF63DC4C8601EC8CULL);
    CHECK(fnv1a64("foobar") == 0x85944171F73967E8ULL);

    const __u64 expected = fnv1a64("mc.example.com");
    CHECK(run_hash_host("mc.example.com", 14) == expected);
    CHECK(run_hash_host("MC.Example.COM", 14) == expected);
    CHECK(run_hash_host("mc.example.com.", 15) == expected);           // SRV target with root dot
    CHECK(run_hash_host("mc.example.com\0FML\0", 19) == expected);     // Forge marker
    CHECK(run_hash_host("mc.example.com.\0FML2\0", 21) == expected);
    CHECK(run_hash_host("mc.example.com\0" "198.51.100.1\0uuid", 32) == expected); // forwarding data

    CHECK(run_hash_host("mc.example.co", 13) != expected);
    CHECK(run_hash_host("mc.example.com..", 16) == fnv1a64("mc.example.com."));
    CHECK(run_hash_host("mc..example.com", 15) == fnv1a64("mc..example.com"));
    CHECK(run_hash_host("mcexamplecom", 12) == fnv1a64("mcexamplecom"));
    CHECK(run_hash_host("", 0) == fnv1a64(""));
    CHECK(run_hash_host(".", 1) == fnv1a64(""));
    // only ASCII letters are folded
    CHECK(run_hash_host("@[`{", 4) == fnv1a64("@[`{"));

    // length limit: HOST_HASH_MAX characters are fine, one more is not ...
    char longest[HOST_HASH_MAX + 2];
    memset(longest, 'a', sizeof(longest));
    longest[HOST_HASH_MAX] = 0;
    CHECK(run_hash_host(longest, HOST_HASH_MAX) == fnv1a64(longest));
    CHECK(run_hash_host(longest, HOST_HASH_MAX + 1) == fnv1a64(longest)); // NUL right at the limit
    longest[HOST_HASH_MAX] = 'a';
    CHECK(run_hash_host(longest, HOST_HASH_MAX + 1) == 0);
    // ... unless everything past the limit is behind a NUL
    char marked[200];
    memset(marked, 'x', sizeof(marked));
    memcpy(marked, "mc.example.com", 15);
    CHECK(run_hash_host(marked, sizeof(marked)) == expected);
}

static void test_handshake_reports_host(void)
{
    struct buf handshake = build_handshake(763, 14, 2);
    CHECK(run_handshake(handshake.b, handshake.n, NULL, NULL) == AWAIT_LOGIN);
    CHECK(last_host_len == 14);
    // [len=1][id=1][protocol 763=2][host len=1] -> host starts at byte 5
    CHECK(last_host_offset == 5);
    CHECK(handshake.b[last_host_offset] == 'h' && handshake.b[last_host_offset + 13] == 'h');

    struct buf empty_host = build_handshake(763, 0, 1);
    CHECK(run_handshake(empty_host.b, empty_host.n, NULL, NULL) == AWAIT_STATUS_REQUEST);
    CHECK(last_host_len == 0);
}

/* ------------------------------------------------------------------------
 * Bedrock RakNet
 * --------------------------------------------------------------------- */

static const __u8 MAGIC[16] = {0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
                               0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78};

static void put_bytes(struct buf *p, const __u8 *bytes, __u32 count)
{
    memcpy(p->b + p->n, bytes, count);
    p->n += count;
}

typedef __u8 (*inspector)(const __u8 *, const __u8 *, const void *);

// runs an inspector on an exact-size heap copy, optionally with slack bytes
// after the payload (padding of a short ethernet frame)
static __u8 run_inspector(inspector inspect, const struct buf *pkt, __u32 len, __u32 slack)
{
    __u8 *heap = heap_copy(pkt->b, len, slack);
    const __u8 ok = inspect(heap, heap + len, heap + len + slack);
    free(heap);
    return ok;
}

static __u8 call_ping(const __u8 *p, const __u8 *e, const void *d) { return inspect_raknet_ping(p, e, d); }
static __u8 call_ocr1(const __u8 *p, const __u8 *e, const void *d) { return inspect_raknet_ocr1(p, e, d); }
static __u8 call_ocr2(const __u8 *p, const __u8 *e, const void *d) { return inspect_raknet_ocr2(p, e, d); }
static __u8 call_stun(const __u8 *p, const __u8 *e, const void *d) { return inspect_stun_binding(p, e, d); }
static __u8 call_guard(const __u8 *p, const __u8 *e, const void *d) { return inspect_guard_data(p, e, d); }

static struct buf build_raknet_ping(void)
{
    struct buf pkt = {{0}, 0};
    put_u8(&pkt, 0x01);
    put_fill(&pkt, 0x11, 8); // time
    put_bytes(&pkt, MAGIC, sizeof(MAGIC));
    put_fill(&pkt, 0x22, 8); // client guid
    return pkt;
}

static struct buf build_raknet_ocr1(__u8 protocol, __u32 total_len)
{
    struct buf pkt = {{0}, 0};
    put_u8(&pkt, 0x05);
    put_bytes(&pkt, MAGIC, sizeof(MAGIC));
    put_u8(&pkt, protocol);
    if (total_len > pkt.n)
    {
        put_fill(&pkt, 0x00, total_len - pkt.n);
    }
    return pkt;
}

static struct buf build_raknet_ocr2(__u32 address_len)
{
    struct buf pkt = {{0}, 0};
    put_u8(&pkt, 0x07);
    put_bytes(&pkt, MAGIC, sizeof(MAGIC));
    put_fill(&pkt, 0x04, address_len);
    put_fill(&pkt, 0x05, 2); // mtu
    put_fill(&pkt, 0x22, 8); // client guid
    return pkt;
}

static void test_raknet_ping(void)
{
    struct buf ping = build_raknet_ping();
    CHECK(ping.n == RAKNET_PING_LEN);
    CHECK(run_inspector(call_ping, &ping, ping.n, 0) == 1);
    CHECK(run_inspector(call_ping, &ping, ping.n, 13) == 1);
    // every truncation is rejected without reading past the payload
    for (__u32 len = 0; len < ping.n; len++)
    {
        CHECK(run_inspector(call_ping, &ping, len, 0) == 0);
        CHECK(run_inspector(call_ping, &ping, len, 40) == 0);
    }
    // some pingers append data, but not a whole datagram of it
    put_fill(&ping, 0x00, RAKNET_PING_MAX_LEN - ping.n);
    CHECK(run_inspector(call_ping, &ping, ping.n, 0) == 1);
    put_u8(&ping, 0x00);
    CHECK(run_inspector(call_ping, &ping, ping.n, 0) == 0);

    // every single bit of the magic matters
    for (__u32 i = 0; i < sizeof(MAGIC); i++)
    {
        struct buf bad = build_raknet_ping();
        bad.b[9 + i] ^= 0x01;
        CHECK(run_inspector(call_ping, &bad, bad.n, 0) == 0);
    }
}

static void test_raknet_open_connection(void)
{
    struct buf ocr1 = build_raknet_ocr1(11, 1464);
    CHECK(run_inspector(call_ocr1, &ocr1, ocr1.n, 0) == 1);
    ocr1 = build_raknet_ocr1(11, 400);
    CHECK(run_inspector(call_ocr1, &ocr1, ocr1.n, 0) == 1);
    CHECK(run_inspector(call_ocr1, &ocr1, 399, 0) == 0);  // below RAKNET_OCR1_MIN
    CHECK(run_inspector(call_ocr1, &ocr1, 399, 50) == 0); // frame padding does not count
    CHECK(run_inspector(call_ocr1, &ocr1, 17, 0) == 0);
    CHECK(run_inspector(call_ocr1, &ocr1, 0, 0) == 0);

    for (__u32 protocol = 0; protocol < 256; protocol++)
    {
        ocr1 = build_raknet_ocr1((__u8)protocol, 548);
        CHECK(run_inspector(call_ocr1, &ocr1, ocr1.n, 0) == (protocol >= 9 && protocol <= 11));
    }
    ocr1 = build_raknet_ocr1(11, 548);
    ocr1.b[16] ^= 0x80; // last byte of the magic
    CHECK(run_inspector(call_ocr1, &ocr1, ocr1.n, 0) == 0);

    // without a minimum size only the header is required
    RAKNET_OCR1_MIN = 0;
    ocr1 = build_raknet_ocr1(11, 0);
    CHECK(ocr1.n == RAKNET_OCR1_HEADER_LEN);
    CHECK(run_inspector(call_ocr1, &ocr1, ocr1.n, 0) == 1);
    CHECK(run_inspector(call_ocr1, &ocr1, ocr1.n - 1, 0) == 0);
    CHECK(run_inspector(call_ocr1, &ocr1, ocr1.n - 1, 8) == 0);
    RAKNET_OCR1_MIN = 400;

    // OpenConnectionRequest2 with an IPv4 (7 bytes) or IPv6 (29 bytes)
    // server address, with or without the 5 cookie bytes
    const __u32 address_lens[] = {7, 12, 29, 34};
    for (__u32 i = 0; i < 4; i++)
    {
        struct buf ocr2 = build_raknet_ocr2(address_lens[i]);
        CHECK(run_inspector(call_ocr2, &ocr2, ocr2.n, 0) == 1);
    }
    struct buf ocr2 = build_raknet_ocr2(7);
    CHECK(ocr2.n == RAKNET_OCR2_MIN_LEN);
    CHECK(run_inspector(call_ocr2, &ocr2, ocr2.n - 1, 0) == 0);
    CHECK(run_inspector(call_ocr2, &ocr2, ocr2.n - 1, 20) == 0);
    ocr2.b[1] ^= 0xFF;
    CHECK(run_inspector(call_ocr2, &ocr2, ocr2.n, 0) == 0);
    ocr2 = build_raknet_ocr2(35);
    CHECK(run_inspector(call_ocr2, &ocr2, ocr2.n, 0) == 0); // longer than any real one
}

/* ------------------------------------------------------------------------
 * NetherNet: STUN and the first byte demultiplexing
 * --------------------------------------------------------------------- */

static struct buf build_stun(__u16 type, __u16 attributes_len, __u32 actual_attributes)
{
    struct buf pkt = {{0}, 0};
    put_u8(&pkt, (__u8)(type >> 8));
    put_u8(&pkt, (__u8)type);
    put_u8(&pkt, (__u8)(attributes_len >> 8));
    put_u8(&pkt, (__u8)attributes_len);
    const __u8 cookie[4] = {0x21, 0x12, 0xA4, 0x42};
    put_bytes(&pkt, cookie, 4);
    put_fill(&pkt, 0x33, 12); // transaction id
    put_fill(&pkt, 0x44, actual_attributes);
    return pkt;
}

static void test_stun_binding(void)
{
    struct buf stun = build_stun(0x0001, 0, 0);
    CHECK(run_inspector(call_stun, &stun, stun.n, 0) == 1);
    CHECK(run_inspector(call_stun, &stun, stun.n, 30) == 1);
    stun = build_stun(0x0001, 72, 72);
    CHECK(run_inspector(call_stun, &stun, stun.n, 0) == 1);
    for (__u32 len = 0; len < stun.n; len++)
    {
        CHECK(run_inspector(call_stun, &stun, len, 0) == 0);
        CHECK(run_inspector(call_stun, &stun, len, 100) == 0);
    }

    stun = build_stun(0x0101, 72, 72); // binding success response
    CHECK(run_inspector(call_stun, &stun, stun.n, 0) == 0);
    stun = build_stun(0x0003, 72, 72); // TURN allocate
    CHECK(run_inspector(call_stun, &stun, stun.n, 0) == 0);
    stun = build_stun(0x0001, 70, 70); // attributes are padded to 4 bytes
    CHECK(run_inspector(call_stun, &stun, stun.n, 0) == 0);
    stun = build_stun(0x0001, 72, 76); // trailing data
    CHECK(run_inspector(call_stun, &stun, stun.n, 0) == 0);
    stun = build_stun(0x0001, 72, 72);
    stun.b[7] ^= 0x01; // magic cookie
    CHECK(run_inspector(call_stun, &stun, stun.n, 0) == 0);
    stun = build_stun(0x0001, 1008, 1008); // larger than any connectivity check
    CHECK(run_inspector(call_stun, &stun, stun.n, 0) == 0);

    // RFC 7983: 0-3 STUN, 20-63 DTLS; everything else has no business on the port
    for (__u32 first = 0; first < 256; first++)
    {
        CHECK(ice_first_byte_valid((__u8)first) == (first <= 3 || (first >= 20 && first <= 63)));
    }
}

/* ------------------------------------------------------------------------
 * Generic TCP guard
 * --------------------------------------------------------------------- */

static struct buf build_text(const char *text)
{
    struct buf pkt = {{0}, 0};
    put_bytes(&pkt, (const __u8 *)text, (__u32)strlen(text));
    return pkt;
}

static void test_guard_data(void)
{
    const __u8 hello_bytes[] = {0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03};
    struct buf hello = {{0}, 0};
    put_bytes(&hello, hello_bytes, sizeof(hello_bytes));
    struct buf get = build_text("GET /v1/join HTTP/1.1\r\n");

    CHECK(run_inspector(call_guard, &hello, hello.n, 0) == 1);
    CHECK(run_inspector(call_guard, &hello, 6, 0) == 1);
    CHECK(run_inspector(call_guard, &hello, 5, 0) == 0);
    CHECK(run_inspector(call_guard, &hello, 5, 10) == 0);
    CHECK(run_inspector(call_guard, &get, get.n, 0) == 1);

    const char *methods[] = {"POST /x HTTP/1.1", "HEAD / HTTP/1.1", "PUT /x HTTP/1.1", "OPTIONS * HTTP/1.1",
                             "DELETE /x HTTP/1.1", "PATCH /x HTTP/1.1", "PRI * HTTP/2.0"};
    for (__u32 i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
    {
        struct buf request = build_text(methods[i]);
        CHECK(run_inspector(call_guard, &request, request.n, 0) == 1);
    }
    const char *garbage[] = {"SSH-2.0-OpenSSH_9.9", "get / http/1.1", "GETX / HTTP/1.1", "\x16\x03\x01\x02\x00\x02 server hello",
                             "\x17\x03\x03\x00\x10\x01 app data", "\x16\x02\x00\x02\x00\x01 sslv2", "\x16\x03\x05\x02\x00\x01 tls 1.4",
                             "\x10\x00\x00\x00\x00\x00 mc"};
    for (__u32 i = 0; i < sizeof(garbage) / sizeof(garbage[0]); i++)
    {
        struct buf payload = build_text(garbage[i]);
        CHECK(run_inspector(call_guard, &payload, payload.n, 0) == 0);
    }

    GUARD_HTTP = 0;
    CHECK(run_inspector(call_guard, &hello, hello.n, 0) == 1);
    CHECK(run_inspector(call_guard, &get, get.n, 0) == 0);
    GUARD_HTTP = 1;
    GUARD_TLS = 0;
    CHECK(run_inspector(call_guard, &hello, hello.n, 0) == 0);
    CHECK(run_inspector(call_guard, &get, get.n, 0) == 1);
    GUARD_TLS = 1;
}

static void test_udp_guard(void)
{
    CHECK(udp_guard_valid(0xFF, 17) == 1);
    CHECK(udp_guard_valid(0xFF, 1400) == 1);
    CHECK(udp_guard_valid(0xFF, 16) == 0);
    CHECK(udp_guard_valid(0xFE, 17) == 0);
    CHECK(udp_guard_valid(0x00, 17) == 0);

    UDPGUARD_FIRST_BYTE = UDPGUARD_ANY_BYTE;
    CHECK(udp_guard_valid(0x00, 17) == 1);
    CHECK(udp_guard_valid(0x00, 16) == 0);
    UDPGUARD_MIN_LEN = 0;
    CHECK(udp_guard_valid(0x42, 1) == 1);
    UDPGUARD_FIRST_BYTE = 0xFF;
    UDPGUARD_MIN_LEN = 17;
}

/* ------------------------------------------------------------------------
 * Simple Voice Chat
 * --------------------------------------------------------------------- */

static struct buf build_voice(__u8 uuid_fill, __u32 payload_len)
{
    struct buf pkt = {{0}, 0};
    put_u8(&pkt, 0xFF);
    put_fill(&pkt, uuid_fill, 16);
    put_varint(&pkt, (__s32)payload_len);
    put_fill(&pkt, 0x5A, payload_len);
    return pkt;
}

static __u16 last_voice_connection = 0;

static __u32 run_voice(const struct buf *pkt, __u32 len, __u32 slack)
{
    __u8 *heap = heap_copy(pkt->b, len, slack);
    last_voice_connection = 0;
    const __u32 kind = inspect_voice(heap, heap + len, heap + len + slack, &last_voice_connection);
    free(heap);
    return kind;
}

static void test_voice_packets(void)
{
    // authenticate / keep-alive: nothing but IV, packet type and tag
    struct buf auth = build_voice(0xA1, VOICE_PAYLOAD_MIN);
    CHECK(auth.n == 47);
    CHECK(run_voice(&auth, auth.n, 0) == VOICE_DATA);
    CHECK(run_voice(&auth, auth.n, 25) == VOICE_DATA);
    const __u16 connection = last_voice_connection;

    // every truncation and every extra byte breaks the frame
    for (__u32 len = 0; len < auth.n; len++)
    {
        CHECK(run_voice(&auth, len, 0) == VOICE_INVALID);
        CHECK(run_voice(&auth, len, 60) == VOICE_INVALID);
    }
    struct buf padded = auth;
    put_u8(&padded, 0);
    CHECK(run_voice(&padded, padded.n, 0) == VOICE_INVALID);

    // audio: one and two length bytes, up to the maximum
    const __u32 sizes[] = {30, 127, 128, 200, 1315, VOICE_PAYLOAD_MAX};
    for (__u32 i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
    {
        struct buf mic = build_voice(0xA1, sizes[i]);
        CHECK(run_voice(&mic, mic.n, 0) == VOICE_DATA);
        // the digest belongs to the connection id, not to the packet
        CHECK(last_voice_connection == connection);
        CHECK(run_voice(&mic, mic.n - 1, 0) == VOICE_INVALID);
    }
    struct buf other = build_voice(0xB2, VOICE_PAYLOAD_MIN);
    CHECK(run_voice(&other, other.n, 0) == VOICE_DATA);
    CHECK(last_voice_connection != connection);

    // payload sizes no client produces
    struct buf small = build_voice(0xA1, VOICE_PAYLOAD_MIN - 1);
    CHECK(run_voice(&small, small.n, 0) == VOICE_INVALID);
    struct buf empty = build_voice(0xA1, 0);
    CHECK(run_voice(&empty, empty.n, 0) == VOICE_INVALID);
    struct buf huge = {{0}, 0};
    put_u8(&huge, 0xFF);
    put_fill(&huge, 0xA1, 16);
    put_varint(&huge, VOICE_PAYLOAD_MAX + 1);
    CHECK(run_voice(&huge, huge.n, 0) == VOICE_INVALID);

    // wrong magic
    struct buf magic = build_voice(0xA1, VOICE_PAYLOAD_MIN);
    magic.b[0] = 0xFE;
    CHECK(run_voice(&magic, magic.n, 0) == VOICE_INVALID);

    // a length written with more bytes than needed, or with three bytes
    struct buf overlong = {{0}, 0};
    put_u8(&overlong, 0xFF);
    put_fill(&overlong, 0xA1, 16);
    put_u8(&overlong, 0x80 | VOICE_PAYLOAD_MIN);
    put_u8(&overlong, 0x00);
    put_fill(&overlong, 0x5A, VOICE_PAYLOAD_MIN);
    CHECK(run_voice(&overlong, overlong.n, 0) == VOICE_INVALID);
    struct buf three = {{0}, 0};
    put_u8(&three, 0xFF);
    put_fill(&three, 0xA1, 16);
    put_u8(&three, 0x80);
    put_u8(&three, 0x80);
    put_u8(&three, 0x01);
    put_fill(&three, 0x5A, 100);
    CHECK(run_voice(&three, three.n, 0) == VOICE_INVALID);

    // the unauthenticated ping: its uuid and exactly 24 bytes
    const __u8 ping_uuid[16] = {0x58, 0xbc, 0x9a, 0xe9, 0xc7, 0xa8, 0x45, 0xe4,
                                0xa1, 0x1c, 0xef, 0xbb, 0x67, 0x19, 0x94, 0x25};
    struct buf ping = {{0}, 0};
    put_u8(&ping, 0xFF);
    put_bytes(&ping, ping_uuid, 16);
    put_varint(&ping, VOICE_PING_PAYLOAD);
    put_fill(&ping, 0x33, VOICE_PING_PAYLOAD);
    CHECK(ping.n == 42);
    CHECK(run_voice(&ping, ping.n, 0) == VOICE_PING);
    CHECK(run_voice(&ping, ping.n - 1, 0) == VOICE_INVALID);
    struct buf long_ping = {{0}, 0};
    put_u8(&long_ping, 0xFF);
    put_bytes(&long_ping, ping_uuid, 16);
    put_varint(&long_ping, VOICE_PAYLOAD_MIN);
    put_fill(&long_ping, 0x33, VOICE_PAYLOAD_MIN);
    CHECK(run_voice(&long_ping, long_ping.n, 0) == VOICE_INVALID);
    // 24 bytes are too few for anything encrypted
    struct buf short_data = build_voice(0xA1, VOICE_PING_PAYLOAD);
    CHECK(run_voice(&short_data, short_data.n, 0) == VOICE_INVALID);
}

/* ------------------------------------------------------------------------
 * Retransmit challenge table
 * --------------------------------------------------------------------- */

#define TICK (1ULL << RETRY_TICK_SHIFT)
#define MIN_TICKS 3
#define MAX_TICKS 150

static __u8 retry(__u64 *slot, __u64 hash, __u64 tick)
{
    return retry_table_check(slot, hash, tick * TICK, MIN_TICKS, MAX_TICKS);
}

static void test_retry_table(void)
{
    const __u64 a = 0x1111000000000000ULL;
    const __u64 b = 0x2222000000000000ULL;
    const __u64 c = 0x3333000000000000ULL;
    __u64 slot = 0;

    // first sighting, duplicates right after it, then the real retransmit
    CHECK(retry(&slot, a, 1000) == 0);
    CHECK(retry(&slot, a, 1000) == 0);
    CHECK(retry(&slot, a, 1000 + MIN_TICKS - 1) == 0);
    CHECK(retry(&slot, a, 1000 + MIN_TICKS) == 1);
    // passing consumes the entry: the next one starts over
    CHECK(slot == 0);
    CHECK(retry(&slot, a, 1010) == 0);
    CHECK(retry(&slot, a, 1010 + MAX_TICKS) == 1);

    // too late: counts as a new first sighting
    CHECK(retry(&slot, a, 2000) == 0);
    CHECK(retry(&slot, a, 2000 + MAX_TICKS + 1) == 0);
    CHECK(retry(&slot, a, 2000 + MAX_TICKS + 1 + MIN_TICKS) == 1);

    // two flows share a slot without disturbing each other
    slot = 0;
    CHECK(retry(&slot, a, 3000) == 0);
    CHECK(retry(&slot, b, 3001) == 0);
    CHECK(retry(&slot, b, 3010) == 1);
    CHECK(retry(&slot, a, 3010) == 1);
    CHECK(slot == 0);

    // a third one replaces the older entry and keeps the younger
    CHECK(retry(&slot, a, 4000) == 0);
    CHECK(retry(&slot, b, 4005) == 0);
    CHECK(retry(&slot, c, 4006) == 0);
    CHECK(retry(&slot, b, 4010) == 1);
    CHECK(retry(&slot, c, 4010) == 1);
    CHECK(retry(&slot, a, 4010) == 0); // was evicted, this is a first sighting again

    // the 16 bit tick counter wraps around
    slot = 0;
    CHECK(retry(&slot, a, 0xFFFE) == 0);
    CHECK(retry(&slot, a, 0x10000 + 10) == 1);

    // a hash whose fingerprint bits are zero still gets a usable entry
    slot = 0;
    CHECK(retry(&slot, 0, 5000) == 0);
    CHECK(slot != 0);
    CHECK(retry(&slot, 0, 5010) == 1);

    // the mixer spreads neighbouring inputs over the table
    CHECK(mix64(1) != mix64(2));
    CHECK((mix64(1) & 0xFFFFF) != (mix64(2) & 0xFFFFF));
    CHECK(mix64(0) == 0); // fixed point of the finalizer, harmless with a seed
}

/* --------------------------------------------------------------------- */

int main(void)
{
    test_varint_decodes_known_vectors();
    test_varint_roundtrip();
    test_varint_rejects_truncated_input();
    test_varint_respects_max_size();
    test_varint_never_reads_past_payload_end();
    test_varint_stops_at_terminator();
    test_varint_rejects_overlong_encoding();
    test_bounds_macros();
    test_status_request();
    test_ping_request();
    test_handshake_intentions();
    test_handshake_legacy_ping();
    test_handshake_rejects_malformed();
    test_handshake_combined_with_status_request();
    test_handshake_combined_with_login();
    test_handshake_rejects_length_mismatch();
    test_login_pre_1_19();
    test_login_username_rules();
    test_login_1_19_key_block();
    test_login_uuid_eras();
    test_login_rejects_length_mismatch();
    test_host_hash();
    test_handshake_reports_host();
    test_raknet_ping();
    test_raknet_open_connection();
    test_stun_binding();
    test_guard_data();
    test_udp_guard();
    test_voice_packets();
    test_retry_table();

    printf("%u checks, %u failures\n", checks_run, checks_failed);
    return checks_failed ? 1 : 0;
}
