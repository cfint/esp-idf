#ifndef A2DP_VENDOR_LHDCV5_DECODER_H
#define A2DP_VENDOR_LHDCV5_DECODER_H

#include "a2dp_codec_api.h"
#include "a2dp_decoder.h"
#include "stack/bt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

bool a2dp_lhdcv5_decoder_init(decoded_data_callback_t decode_callback);
void a2dp_lhdcv5_decoder_cleanup(void);
void a2dp_lhdcv5_decoder_configure(const uint8_t* p_codec_info);
ssize_t a2dp_lhdcv5_decoder_decode_packet_header(BT_HDR* p_data);
bool a2dp_lhdcv5_decoder_decode_packet(BT_HDR* p_buf, unsigned char* buf,
                                       size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif  // A2DP_VENDOR_LHDCV5_DECODER_H
