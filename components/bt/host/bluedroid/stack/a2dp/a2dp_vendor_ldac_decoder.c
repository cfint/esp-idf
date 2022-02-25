/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/bt_trace.h"
#include "stack/a2dp_vendor_ldac_constants.h"
#include "stack/a2dp_vendor_ldac_decoder.h"
#include "ldacdec.h"


#if (defined(LDAC_DEC_INCLUDED) && LDAC_DEC_INCLUDED == TRUE)

typedef struct {
  ldacdec_t decoder;
  decoded_data_callback_t decode_callback;
} tA2DP_LDAC_DECODER_CB;

static tA2DP_LDAC_DECODER_CB a2dp_ldac_decoder_cb;


bool a2dp_ldac_decoder_init(decoded_data_callback_t decode_callback) {
    int res;

    res = ldacdecInit(&a2dp_ldac_decoder_cb.decoder);
    if (res) {
        APPL_TRACE_ERROR("%s: decoder init failed %d", __func__, res);
        return false;
    }
    a2dp_ldac_decoder_cb.decode_callback = decode_callback;
    return true;
}

ssize_t a2dp_ldac_decoder_decode_packet_header(BT_HDR* p_buf) {
    size_t header_len = sizeof(struct media_packet_header) +
                        A2DP_LDAC_MPL_HDR_LEN;
    p_buf->offset += header_len;
    p_buf->len -= header_len;
    return 0;
}

static bool find_sync_word(unsigned char** buf, int *size) {
    while((*size) > 0 && **buf != 0xAA) {
        (*buf)++;
        (*size)--;
    }

    return (*size) > 0;
}


bool a2dp_ldac_decoder_decode_packet(BT_HDR* p_buf, unsigned char* buf, size_t buf_len) {
    ldacdec_t* decoder = &a2dp_ldac_decoder_cb.decoder;
    int ret;

    unsigned char* src = ((unsigned char *)(p_buf + 1) + p_buf->offset);
    int src_size = p_buf->len;
    unsigned char* dst = buf;
    uint32_t dst_size = 0;
    int bytes_used;

    while (src_size > 0 && dst_size < buf_len) {
        int out_size;

        if (!find_sync_word(&src, &src_size)) {
            break;
        }

        ret = ldacDecode(decoder, src, (void*)dst, &bytes_used);
        if (ret != 0) {
            APPL_TRACE_ERROR("%s: decoder error %d", __func__, ret);
            return false;
        }
        src += bytes_used;
        src_size -= bytes_used;

        frame_t *frame = &decoder->frame;
        out_size = frame->frameSamples * frame->channelCount * sizeof(int16_t);
        dst += out_size;
        dst_size += out_size;
    }

    a2dp_ldac_decoder_cb.decode_callback((uint8_t*)buf, dst_size);
    return true;    
}

#endif /* defined(LDAC_DEC_INCLUDED) && LDAC_DEC_INCLUDED == TRUE) */
