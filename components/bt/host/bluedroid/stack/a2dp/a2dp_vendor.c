/*
 * Copyright 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Vendor Specific A2DP Codecs Support
 */

#if (A2D_INCLUDED == TRUE)

#include "bt_av.h"
#include "stack/a2d_api.h"
#include "stack/a2dp_codec_api.h"
#include "stack/a2dp_vendor.h"
#include "stack/a2dp_vendor_aptx.h"

tA2D_STATUS A2DP_VendorParseInfo(uint8_t* p_ie, const uint8_t* p_codec_info,
                                 bool is_capability) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_ParseInfoAptx((tA2DP_APTX_CIE*)p_ie, p_codec_info, is_capability);
  }
#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */

  // Add checks based on <vendor_id, codec_id>
  (void)vendor_id;
  (void)codec_id;

  return A2D_FAIL;
}

bool A2DP_IsVendorPeerSinkCodecValid(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_IsVendorPeerSinkCodecValidAptx(p_codec_info);
  }
#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */

  // Add checks based on <vendor_id, codec_id>
  (void)vendor_id;
  (void)codec_id;

  return false;
}

tA2D_STATUS A2DP_IsVendorSinkCodecSupported(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  UNUSED(vendor_id);
  UNUSED(codec_id);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return A2D_FAIL;
}

tA2D_STATUS A2DP_IsVendorPeerSourceCodecSupported(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_IsVendorPeerSourceCodecValidAptx(p_codec_info);
  }
#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */

  // Add checks based on <vendor_id, codec_id> and peer codec capabilities
  // NOTE: Should be done only for local Sink codecs.
  (void)vendor_id;
  (void)codec_id;

  return A2D_FAIL;
}


uint32_t A2DP_VendorCodecGetVendorId(const uint8_t* p_codec_info) {
  const uint8_t* p = &p_codec_info[A2DP_VENDOR_CODEC_VENDOR_ID_START_IDX];

  uint32_t vendor_id = (p[0] & 0x000000ff) | ((p[1] << 8) & 0x0000ff00) |
                       ((p[2] << 16) & 0x00ff0000) |
                       ((p[3] << 24) & 0xff000000);

  return vendor_id;
}

uint16_t A2DP_VendorCodecGetCodecId(const uint8_t* p_codec_info) {
  const uint8_t* p = &p_codec_info[A2DP_VENDOR_CODEC_CODEC_ID_START_IDX];

  uint16_t codec_id = (p[0] & 0x00ff) | ((p[1] << 8) & 0xff00);

  return codec_id;
}

btav_a2dp_codec_index_t A2DP_VendorSinkCodecIndex(
    const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorSinkCodecIndexAptx(p_codec_info);
  }
#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */

  // Check for aptX-HD
  if (vendor_id == A2DP_APTX_HD_VENDOR_ID &&
      codec_id == A2DP_APTX_HD_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorSinkCodecIndexAptxHd(p_codec_info);
  }

  // Add checks based on <vendor_id, codec_id>
  (void)vendor_id;
  (void)codec_id;

  return BTAV_A2DP_CODEC_INDEX_MAX;
}

btav_a2dp_codec_index_t A2DP_VendorSourceCodecIndex(
    const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorSourceCodecIndexAptx(p_codec_info);
  }
#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */

  // Add checks based on <vendor_id, codec_id>
  (void)vendor_id;
  (void)codec_id;

  return BTAV_A2DP_CODEC_INDEX_MAX;
}

bool A2DP_VendorInitCodecConfig(btav_a2dp_codec_index_t codec_index, UINT8 *p_result) {

#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  // Check for aptX
  if (A2DP_VendorInitCodecConfigAptx(codec_index, p_result)) {
    return true;
  }
#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */

  (void)codec_index;
  (void)p_result;

  return false;
}

// Build codec info from a source config
bool A2DP_VendorBuildCodecConfig(UINT8 *p_src_cap, UINT8 *p_result) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_src_cap);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_src_cap);

#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorBuildCodecConfigAptx(p_src_cap, p_result);
  }
#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */

  // Add checks based on <vendor_id, codec_id>
  (void)vendor_id;
  (void)codec_id;

  return false;
}

const char* A2DP_VendorCodecName(const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  // Check for aptX
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecNameAptx(p_codec_info);
  }
#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */

  // Add checks based on <vendor_id, codec_id>
  (void)vendor_id;
  (void)codec_id;

  return "UNKNOWN VENDOR CODEC";
}

bool A2DP_VendorCodecTypeEquals(const uint8_t* p_codec_info_a,
                                const uint8_t* p_codec_info_b) {
  tA2D_CODEC_TYPE codec_type_a = A2DP_GetCodecType(p_codec_info_a);
  tA2D_CODEC_TYPE codec_type_b = A2DP_GetCodecType(p_codec_info_b);

  if ((codec_type_a != codec_type_b) ||
      (codec_type_a != A2D_MEDIA_CT_NON_A2DP)) {
    return false;
  }

  uint32_t vendor_id_a = A2DP_VendorCodecGetVendorId(p_codec_info_a);
  uint16_t codec_id_a = A2DP_VendorCodecGetCodecId(p_codec_info_a);
  uint32_t vendor_id_b = A2DP_VendorCodecGetVendorId(p_codec_info_b);
  uint16_t codec_id_b = A2DP_VendorCodecGetCodecId(p_codec_info_b);

  if (vendor_id_a != vendor_id_b || codec_id_a != codec_id_b) return false;

#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  // Check for aptX
  if (vendor_id_a == A2DP_APTX_VENDOR_ID &&
      codec_id_a == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_VendorCodecTypeEqualsAptx(p_codec_info_a, p_codec_info_b);
  }
#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */

  // OPTIONAL: Add extra vendor-specific checks based on the
  // vendor-specific data stored in "p_codec_info_a" and "p_codec_info_b".
  (void)vendor_id_a;
  (void)codec_id_a;
  (void)vendor_id_b;
  (void)codec_id_b;

  return true;
}

const tA2DP_DECODER_INTERFACE* A2DP_GetVendorDecoderInterface(
    const uint8_t* p_codec_info) {
  uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  if (vendor_id == A2DP_APTX_VENDOR_ID &&
      codec_id == A2DP_APTX_CODEC_ID_BLUETOOTH) {
    return A2DP_GetVendorDecoderInterfaceAptx(p_codec_info);
  }
#endif /* defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE) */

  (void)vendor_id;
  (void)codec_id;

  return NULL;
}

#endif  ///A2D_INCLUDED
