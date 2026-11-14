#ifndef BEDROCK_H
#define BEDROCK_H

#include <linux/types.h>

#include "common.h"
#include "config.h"

/*
 * Inspection of everything that is not Minecraft Java: Bedrock RakNet
 * (UDP), NetherNet WebRTC (UDP: STUN + DTLS) and the first payload of
 * generic TCP guard connections (TLS / HTTP, e.g. NetherNet signaling).
 *
 * Like in protocol.h every inspector returns 0 as soon as the datagram does
 * not look like what it claims to be.
 */

/* ------------------------------------------------------------------------
 * RakNet offline messages
 *
 * Until a session exists a client may only send "offline" messages, all of
 * which carry the same 16 byte magic:
 *
 *   0x01 / 0x02  UnconnectedPing        id, time(8), magic, client guid(8)
 *   0x05         OpenConnectionRequest1 id, magic, protocol(1), zero padding up to the MTU
 *   0x07         OpenConnectionRequest2 id, magic, [cookie(4), flag(1)], server address, mtu(2), client guid(8)
 *
 * Everything a connected client sends afterwards has the 0x80 bit set in
 * its first byte (frame sets 0x80-0x8f, ACK 0xc0, NACK 0xa0).
 * --------------------------------------------------------------------- */

#define RAKNET_UNCONNECTED_PING 0x01
#define RAKNET_UNCONNECTED_PING_OPEN 0x02
#define RAKNET_OPEN_CONNECTION_REQUEST_1 0x05
#define RAKNET_OPEN_CONNECTION_REQUEST_2 0x07
#define RAKNET_CONNECTED_FLAG 0x80

// 00 ff ff 00 fe fe fe fe fd fd fd fd 12 34 56 78
#define RAKNET_MAGIC_HIGH CONST_BE64(0x00FFFF00FEFEFEFEULL)
#define RAKNET_MAGIC_LOW CONST_BE64(0xFDFDFDFD12345678ULL)
#define RAKNET_MAGIC_LEN 16

#define RAKNET_PING_LEN (1 + 8 + RAKNET_MAGIC_LEN + 8)
#define RAKNET_PING_MAX_LEN 64
#define RAKNET_OCR1_HEADER_LEN (1 + RAKNET_MAGIC_LEN + 1)
// shortest: IPv4 server address (1 + 4 + 2); longest: cookie + IPv6 address (1 + 2 + 2 + 4 + 16 + 4)
#define RAKNET_OCR2_MIN_LEN (1 + RAKNET_MAGIC_LEN + 7 + 2 + 8)
#define RAKNET_OCR2_MAX_LEN (1 + RAKNET_MAGIC_LEN + 5 + 29 + 2 + 8)

// returns 1 if the 16 bytes at ptr are the RakNet offline message magic
static __always_inline __u8 raknet_magic_at(const __u8 *ptr, const __u8 *payload_end, const void *data_end)
{
    CHECK_BOUNDS_OR_RETURN(ptr, RAKNET_MAGIC_LEN, payload_end, data_end);
    return *(const __u64 *)ptr == RAKNET_MAGIC_HIGH && *(const __u64 *)(ptr + 8) == RAKNET_MAGIC_LOW;
}

// returns 1 if the datagram is a valid unconnected ping (id already checked)
static __always_inline __u8 inspect_raknet_ping(const __u8 *payload, const __u8 *payload_end, const void *data_end)
{
    const __u64 len = (__u64)(payload_end - payload);
    ASSERT_IN_RANGE_OR_RETURN(len, RAKNET_PING_LEN, RAKNET_PING_MAX_LEN);
    return raknet_magic_at(payload + 1 + 8, payload_end, data_end);
}

// returns 1 if the datagram is a valid OpenConnectionRequest1 (id already checked)
static __always_inline __u8 inspect_raknet_ocr1(const __u8 *payload, const __u8 *payload_end, const void *data_end)
{
    const __u64 len = (__u64)(payload_end - payload);
    ASSERT_OR_RETURN(len >= RAKNET_OCR1_HEADER_LEN && len >= RAKNET_OCR1_MIN);
    ASSERT_OR_RETURN(raknet_magic_at(payload + 1, payload_end, data_end));

    const __u8 *version_ptr = payload + 1 + RAKNET_MAGIC_LEN;
    CHECK_BOUNDS_OR_RETURN(version_ptr, 1, payload_end, data_end);
    const __u32 version = *version_ptr;
    return version >= RAKNET_PROTO_MIN && version <= RAKNET_PROTO_MAX;
}

// returns 1 if the datagram is a valid OpenConnectionRequest2 (id already checked)
static __always_inline __u8 inspect_raknet_ocr2(const __u8 *payload, const __u8 *payload_end, const void *data_end)
{
    const __u64 len = (__u64)(payload_end - payload);
    ASSERT_IN_RANGE_OR_RETURN(len, RAKNET_OCR2_MIN_LEN, RAKNET_OCR2_MAX_LEN);
    return raknet_magic_at(payload + 1, payload_end, data_end);
}

/* ------------------------------------------------------------------------
 * NetherNet WebRTC: one UDP port carries STUN and DTLS, told apart by the
 * first byte as in RFC 7983 (0-3 STUN, 20-63 DTLS). A session has to start
 * with a STUN binding request, the connectivity check of ICE.
 * --------------------------------------------------------------------- */

#define STUN_HEADER_LEN 20
#define STUN_BINDING_REQUEST CONST_BE16(0x0001)
#define STUN_MAGIC_COOKIE CONST_BE32(0x2112A442)
#define STUN_MAX_LEN 1024

// returns 1 if the first byte belongs to a protocol a WebRTC data channel uses
static __always_inline __u8 ice_first_byte_valid(const __u8 first)
{
    return first <= 3 || (first >= 20 && first <= 63);
}

// returns 1 if the datagram is a well-formed STUN binding request
static __always_inline __u8 inspect_stun_binding(const __u8 *payload, const __u8 *payload_end, const void *data_end)
{
    const __u64 len = (__u64)(payload_end - payload);
    ASSERT_IN_RANGE_OR_RETURN(len, STUN_HEADER_LEN, STUN_MAX_LEN);
    CHECK_BOUNDS_OR_RETURN(payload, STUN_HEADER_LEN, payload_end, data_end);

    const __u16 type = *(const __u16 *)payload;
    const __u16 attributes_len = __builtin_bswap16(*(const __u16 *)(payload + 2));
    const __u32 cookie = *(const __u32 *)(payload + 4);

    // attributes are padded to 4 bytes and have to fill the datagram exactly
    return type == STUN_BINDING_REQUEST && cookie == STUN_MAGIC_COOKIE &&
           (attributes_len & 3) == 0 && (__u64)attributes_len + STUN_HEADER_LEN == len;
}

/* ------------------------------------------------------------------------
 * Generic TCP guard: the first payload of the connection has to open a
 * protocol the service behind the port speaks.
 * --------------------------------------------------------------------- */

#define TLS_RECORD_HANDSHAKE 0x16
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01

#define HTTP_METHOD(a, b, c, d) CONST_BE32(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

// returns 1 if the payload starts a TLS handshake or (if allowed) an HTTP request
static __always_inline __u8 inspect_guard_data(const __u8 *payload, const __u8 *payload_end, const void *data_end)
{
    CHECK_BOUNDS_OR_RETURN(payload, 6, payload_end, data_end);

    if (GUARD_TLS)
    {
        // record header: type, version 3.x, length(2); then the handshake type
        if (payload[0] == TLS_RECORD_HANDSHAKE && payload[1] == 0x03 && payload[2] <= 0x04 &&
            payload[5] == TLS_HANDSHAKE_CLIENT_HELLO)
        {
            return 1;
        }
    }

    if (GUARD_HTTP)
    {
        const __u32 method = *(const __u32 *)payload;
        if (method == HTTP_METHOD('G', 'E', 'T', ' ') || method == HTTP_METHOD('P', 'O', 'S', 'T') ||
            method == HTTP_METHOD('H', 'E', 'A', 'D') || method == HTTP_METHOD('P', 'U', 'T', ' ') ||
            method == HTTP_METHOD('O', 'P', 'T', 'I') || method == HTTP_METHOD('D', 'E', 'L', 'E') ||
            method == HTTP_METHOD('P', 'A', 'T', 'C') || method == HTTP_METHOD('P', 'R', 'I', ' '))
        {
            return 1;
        }
    }

    return 0;
}

#endif
