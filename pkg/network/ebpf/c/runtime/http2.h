#include "kconfig.h"
#include "tracer.h"
#include "bpf_telemetry.h"
#include "bpf_builtins.h"
#include "ip.h"
#include "ipv6.h"
#include "http.h"
#include "https.h"
#include "http-buffer.h"
#include "sockfd.h"
#include "tags-types.h"
#include "port_range.h"
#include "go-tls-types.h"
#include "go-tls-goid.h"
#include "go-tls-location.h"
#include "go-tls-conn.h"
#include "protocol-dispatcher-helpers.h"
#include "skb.h"

#include "sock.h"

// Checkout https://datatracker.ietf.org/doc/html/rfc7540 under "Frame Format" section
#define HTTP2_FRAME_HEADER_SIZE 9
// A limit of max frames we will upload from a single connection to the user mode.
// NOTE: we may need to revisit this const if we need to capture more connections.
#define HTTP2_MAX_FRAMES 40

// All types of http2 frames exist in the protocol.
// Checkout https://datatracker.ietf.org/doc/html/rfc7540 under "Frame Type Registry" section.
typedef enum {
    kDataFrame          = 0,
    kHeadersFrame       = 1,
    kPriorityFrame      = 2,
    kRSTStreamFrame     = 3,
    kSettingsFrame      = 4,
    kPushPromiseFrame   = 5,
    kPingFrame          = 6,
    kGoAwayFrame        = 7,
    kWindowUpdateFrame  = 8,
    kContinuationFrame  = 9,
} __attribute__ ((packed)) frame_type_t;

struct http2_frame {
    uint32_t length;
    frame_type_t type;
    uint8_t flags;
    uint32_t stream_id;
};

static __always_inline uint32_t as_uint32_t(unsigned char input) {
    return (uint32_t)input;
}

static __always_inline bool is_empty_frame_header(const char *frame) {
#pragma unroll
    for (uint32_t i = 0; i < HTTP2_FRAME_HEADER_SIZE; i++) {
        if (frame[i] != 0) {
            return false;
        }
    }
    return true;
}

static __always_inline bool read_http2_frame_header(const char *buf, size_t buf_size, struct http2_frame *out) {
    if (buf == NULL) {
        return false;
    }

    if (buf_size < HTTP2_FRAME_HEADER_SIZE) {
        return false;
    }

    if (is_empty_frame_header(buf)) {
        return false;
    }

// We extract the frame by its shape to fields.
// See: https://datatracker.ietf.org/doc/html/rfc7540#section-4.1
    out->length = as_uint32_t(buf[0])<<16 | as_uint32_t(buf[1])<<8 | as_uint32_t(buf[2]);
    out->type = (frame_type_t)buf[3];
    out->flags = (uint8_t)buf[4];
    out->stream_id = (as_uint32_t(buf[5]) << 24 |
                      as_uint32_t(buf[6]) << 16 |
                      as_uint32_t(buf[7]) << 8 |
                      as_uint32_t(buf[8])) & 2147483647;

    return true;
}
