#ifndef A2DP_VENDOR_LHDCV5_H
#define A2DP_VENDOR_LHDCV5_H

#include <stdbool.h>
#include <stdint.h>

#include "a2dp_codec_api.h"
#include "a2dp_vendor_lhdcv5_constants.h"
#include "bt_av.h"
#include "stack/a2d_api.h"

typedef struct {
  uint32_t vendorId;
  uint16_t codecId;
  uint8_t sampleRate;
  uint8_t bitsPerSample;
  uint8_t channelMode;
  uint8_t version;
  uint8_t frameLenType;
  uint8_t maxTargetBitrate;
  uint8_t minTargetBitrate;
  bool hasFeatureAR;
  bool hasFeatureJAS;
  bool hasFeatureMETA;
  bool hasFeatureLL;
  bool hasFeatureLLESS48K;
  bool hasFeatureLLESS24Bit;
  bool hasFeatureLLESS96K;
  bool hasFeatureLLESSRaw;
} tA2DP_LHDCV5_CIE;

#ifdef __cplusplus
extern "C" {
#endif

tA2D_STATUS A2DP_BuildInfoLhdcV5(uint8_t media_type,
                                 const tA2DP_LHDCV5_CIE* p_ie,
                                 uint8_t* p_result);
tA2D_STATUS A2DP_ParseInfoLhdcV5(tA2DP_LHDCV5_CIE* p_ie,
                                 const uint8_t* p_codec_info,
                                 bool is_capability);
tA2D_STATUS A2DP_IsVendorPeerSourceCodecValidLhdcV5(const uint8_t* p_codec_info);
bool A2DP_IsVendorPeerSinkCodecValidLhdcV5(const uint8_t* p_codec_info);
btav_a2dp_codec_index_t A2DP_VendorSinkCodecIndexLhdcV5(const uint8_t* p_codec_info);
btav_a2dp_codec_index_t A2DP_VendorSourceCodecIndexLhdcV5(const uint8_t* p_codec_info);
const char* A2DP_VendorCodecNameLhdcV5(const uint8_t* p_codec_info);
bool A2DP_VendorCodecTypeEqualsLhdcV5(const uint8_t* p_codec_info_a,
                                      const uint8_t* p_codec_info_b);
bool A2DP_VendorInitCodecConfigLhdcV5(btav_a2dp_codec_index_t codec_index,
                                      uint8_t* p_result);
bool A2DP_VendorInitCodecConfigLhdcV5Sink(uint8_t* p_codec_info);
bool A2DP_VendorBuildCodecConfigLhdcV5(uint8_t* p_src_cap, uint8_t* p_result);
const tA2DP_DECODER_INTERFACE* A2DP_GetVendorDecoderInterfaceLhdcV5(
    const uint8_t* p_codec_info);

#ifdef __cplusplus
}
#endif

#endif  // A2DP_VENDOR_LHDCV5_H
