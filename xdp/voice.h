#ifndef VOICE_H
#define VOICE_H

#include <linux/types.h>

#include "common.h"
#include "varint.h"

/*
 * Simple Voice Chat (https://github.com/henkelmax/simple-voice-chat), UDP.
 *
 * Everything a client sends has the same frame (NetworkMessage.java,
 * ClientNetworkMessage.writeClient() in the mod):
 *
 *   0xFF            magic
 *   uuid(16)        connection id (the player uuid before mod 2.6)
 *   varint length   of the payload
 *   payload         fills the rest of the datagram
 *
 * The payload is encrypted with a secret the client got over the Minecraft
 * connection, so the filter can not look inside. Its size is known though:
 * AES-GCM with a 12 byte IV and a 16 byte tag around at least the packet
 * type (mod 2.5 used AES-CBC: a 16 byte IV and at least one 16 byte block),
 * and at most MAX_VOICE_CHAT_PACKET_SIZE.
 *
 * The one exception is the unauthenticated ping of external tools
 * (PingHandler.java): a fixed uuid and 24 unencrypted bytes.
 */

#define VOICE_MAGIC 0xFF
#define VOICE_UUID_LEN 16
#define VOICE_HEADER_LEN (1 + VOICE_UUID_LEN)

#define VOICE_PAYLOAD_MIN (12 + 1 + 16) // IV, packet type, GCM tag
#define VOICE_PAYLOAD_MAX 2048          // Utils.MAX_VOICE_CHAT_PACKET_SIZE
#define VOICE_LENGTH_MAX_BYTES 2        // a varint up to 2048 takes two bytes

// PingHandler.PING_V1: 58bc9ae9-c7a8-45e4-a11c-efbb67199425
#define VOICE_PING_UUID_HIGH CONST_BE64(0x58BC9AE9C7A845E4ULL)
#define VOICE_PING_UUID_LOW CONST_BE64(0xA11CEFBB67199425ULL)
#define VOICE_PING_PAYLOAD 24 // ping id (uuid) and timestamp

enum voice_packet
{
    VOICE_INVALID = 0,
    VOICE_DATA = 1, // packet of a voice connection
    VOICE_PING = 2, // unauthenticated ping
};

/*
 * Returns what kind of voice chat datagram this is, or VOICE_INVALID.
 *
 * For VOICE_DATA *connection receives a 16 bit digest of the connection
 * id: a verified session is bound to the id that opened it.
 */
static __always_inline __u32 inspect_voice(const __u8 *payload, const __u8 *payload_end, const void *data_end, __u16 *connection)
{
    const __u64 len = (__u64)(payload_end - payload);
    const __u8 *cursor = payload;

    __u8 magic;
    READ_VAL_OR_RETURN(magic, cursor, payload_end, data_end);
    ASSERT_OR_RETURN(magic == VOICE_MAGIC);

    __u64 uuid_high;
    __u64 uuid_low;
    READ_VAL_OR_RETURN(uuid_high, cursor, payload_end, data_end);
    READ_VAL_OR_RETURN(uuid_low, cursor, payload_end, data_end);

    // the payload length, written the short way and matching the datagram
    struct varint_value length;
    READ_VARINT_OR_RETURN(length, cursor, payload_end, data_end, VOICE_LENGTH_MAX_BYTES);
    ASSERT_OR_RETURN(length.bytes == 1 || length.value >= 0x80);
    ASSERT_OR_RETURN((__u64)VOICE_HEADER_LEN + length.bytes + (__u64)(__u32)length.value == len);

    if (uuid_high == VOICE_PING_UUID_HIGH && uuid_low == VOICE_PING_UUID_LOW)
    {
        return length.value == VOICE_PING_PAYLOAD ? VOICE_PING : VOICE_INVALID;
    }

    ASSERT_IN_RANGE_OR_RETURN(length.value, VOICE_PAYLOAD_MIN, VOICE_PAYLOAD_MAX);
    *connection = (__u16)mix64(uuid_high ^ mix64(uuid_low));
    return VOICE_DATA;
}

#endif
