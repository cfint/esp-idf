/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/bt_trace.h"
#include "stack/a2dp_vendor_aptx_decoder.h"


#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)

/* libfreeaptx API */
extern struct aptx_context *aptx_init(int hd);
extern void aptx_reset(struct aptx_context *ctx);
extern void aptx_finish(struct aptx_context *ctx);
extern int aptx_encode_finish(struct aptx_context *ctx,
                              unsigned char *output,
                              size_t output_size,
                              size_t *written);
extern size_t aptx_decode(struct aptx_context *ctx,
                          const unsigned char *input,
                          size_t input_size,
                          unsigned char *output,
                          size_t output_size,
                          size_t *written);
extern size_t aptx_decode16(struct aptx_context *ctx,
                            const unsigned char *input,
                            size_t input_size,
                            unsigned char *output,
                            size_t output_size,
                            size_t *written);
extern size_t aptx_decode32(struct aptx_context *ctx,
                            const unsigned char *input,
                            size_t input_size,
                            unsigned char *output,
                            size_t output_size,
                            size_t *written);

typedef enum
{
    APTX_STANDARD,
    APTX_HD,
    APTX_LL,
} tA2DP_APTX_TYPE;

typedef struct {
  struct aptx_context* decoder_context;
  tA2DP_APTX_TYPE aptx_type;
  decoded_data_callback_t decode_callback;
} tA2DP_APTX_DECODER_CB;

static tA2DP_APTX_DECODER_CB a2dp_aptx_decoder_cb;


bool a2dp_aptx_decoder_init(decoded_data_callback_t decode_callback) {
    struct aptx_context* decoder_context = aptx_init(0);
    if (!decoder_context) {
        APPL_TRACE_ERROR("%s decoder init failed", __func__);
        return false;
    }
    a2dp_aptx_decoder_cb.decoder_context = decoder_context;
    a2dp_aptx_decoder_cb.decode_callback = decode_callback;
    a2dp_aptx_decoder_cb.aptx_type = APTX_STANDARD;
    return true;
}

void a2dp_aptx_decoder_cleanup(void) {
    struct aptx_context* decoder_context = a2dp_aptx_decoder_cb.decoder_context;
    if (!decoder_context) {
        APPL_TRACE_ERROR("%s decoder context not initialized", __func__);
        return;
    }

    aptx_finish(decoder_context);
    decoder_context = NULL;
}

bool a2dp_aptx_decoder_reset(void) {
    struct aptx_context* decoder_context = a2dp_aptx_decoder_cb.decoder_context;
    if (!decoder_context) {
        APPL_TRACE_ERROR("%s decoder context not initialized", __func__);
        return false;
    }

    aptx_reset(decoder_context);
    return true;
}

size_t a2dp_aptx_decoder_decode_packet_header(BT_HDR* p_buf) {
    if (a2dp_aptx_decoder_cb.aptx_type != APTX_HD) {
        return 0;
    }
    size_t header_len = sizeof(struct media_packet_header);
    p_buf->offset += header_len;
    p_buf->len -= header_len;
    return 0;
}

bool a2dp_aptx_decoder_decode_packet(BT_HDR* p_buf, unsigned char* buf, size_t buf_len) {
    struct aptx_context* decoder_context = a2dp_aptx_decoder_cb.decoder_context;

    unsigned char* dst = buf;
    unsigned char* src = ((unsigned char *)(p_buf + 1) + p_buf->offset);
    int32_t src_size = p_buf->len;
    int32_t avail = buf_len;

    size_t processed = -1;
    while (src_size > 0 && avail > 0 && processed) {
        size_t written;
        if (a2dp_aptx_decoder_cb.aptx_type == APTX_LL) {
            processed = aptx_decode32(decoder_context, src, (size_t)src_size, dst, (size_t)avail, &written);
        } else {
            processed = aptx_decode16(decoder_context, src, (size_t)src_size, dst, (size_t)avail, &written);
        }

        src += processed;
        src_size -= processed;
        avail -= written;
        dst += written;

        p_buf->offset += processed;
        p_buf->len -= processed;
    }

    if (src_size > 0 && avail <= 0) {
        LOG_ERROR("%s: Insufficient output buffer size. %d bytes remain.", __func__, src_size);
    }

    size_t len = buf_len - avail;
    len = len <= buf_len ? len : buf_len;
    a2dp_aptx_decoder_cb.decode_callback((uint8_t*)buf, len);
    return true;
}

void a2dp_aptx_decoder_configure(const uint8_t* p_codec_info) {
    struct aptx_context* decoder_context = a2dp_aptx_decoder_cb.decoder_context;
    btav_a2dp_codec_index_t index = A2DP_SinkCodecIndex(p_codec_info);

    if (!decoder_context) {
        LOG_ERROR("%s: decoder not initialized", __func__);
        return;
    }

    if (index == BTAV_A2DP_CODEC_INDEX_SINK_APTX_HD) {
        a2dp_aptx_decoder_cb.aptx_type = APTX_HD;
    } else if (index == BTAV_A2DP_CODEC_INDEX_SINK_APTX_LL) {
        a2dp_aptx_decoder_cb.aptx_type = APTX_LL;
    } else {
        a2dp_aptx_decoder_cb.aptx_type = APTX_STANDARD;
    }

    aptx_finish(decoder_context);
    a2dp_aptx_decoder_cb.decoder_context = aptx_init(a2dp_aptx_decoder_cb.aptx_type == APTX_HD);
}

#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */
