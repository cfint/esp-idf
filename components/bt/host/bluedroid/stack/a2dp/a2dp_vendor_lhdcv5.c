#include <string.h>

#include "a2d_int.h"
#include "common/bt_defs.h"
#include "common/bt_target.h"
#include "stack/a2d_api.h"
#include "stack/a2d_sbc.h"
#include "stack/a2dp_vendor_lhdcv5.h"
#include "stack/a2dp_vendor_lhdcv5_decoder.h"

#if (defined(LHDCV5_DEC_INCLUDED) && LHDCV5_DEC_INCLUDED == TRUE)

static const tA2DP_LHDCV5_CIE a2dp_lhdcv5_sink_caps = {
    A2DP_LHDCV5_VENDOR_ID,
    A2DP_LHDCV5_CODEC_ID,
    /* Advertise all four rates. NOTE: this is a bitmask (bitwise OR), so the order
     * below does not change the advertised value or any priority — 192k listed
     * first here is purely cosmetic. The source (phone) picks the rate. */
    A2DP_LHDCV5_SAMPLING_FREQ_192000 |  /* 192k: fast IMDCT-1920 */
        A2DP_LHDCV5_SAMPLING_FREQ_96000 |   /* 96k: fast IMDCT-960 */
        A2DP_LHDCV5_SAMPLING_FREQ_48000 |
        A2DP_LHDCV5_SAMPLING_FREQ_44100,
    A2DP_LHDCV5_BITS_PER_SAMPLE_24 |
        A2DP_LHDCV5_BITS_PER_SAMPLE_16,
    A2DP_LHDCV5_CHANNEL_MODE_STEREO,
    A2DP_LHDCV5_VER_1,
    A2DP_LHDCV5_FRAME_LEN_5MS,
    A2DP_LHDCV5_MAX_BIT_RATE_1000K,
    A2DP_LHDCV5_MIN_BIT_RATE_64K,
    false,
    false,
    false,
    true,
    false,
    false,
    false,
    false,
};

static const tA2DP_LHDCV5_CIE a2dp_lhdcv5_default_config = {
    A2DP_LHDCV5_VENDOR_ID,
    A2DP_LHDCV5_CODEC_ID,
    A2DP_LHDCV5_SAMPLING_FREQ_192000,
    A2DP_LHDCV5_BITS_PER_SAMPLE_24,
    A2DP_LHDCV5_CHANNEL_MODE_STEREO,
    A2DP_LHDCV5_VER_1,
    A2DP_LHDCV5_FRAME_LEN_5MS,
    A2DP_LHDCV5_MAX_BIT_RATE_1000K,
    A2DP_LHDCV5_MIN_BIT_RATE_64K,
    false,
    false,
    false,
    true,
    false,
    false,
    false,
    false,
};

static const tA2DP_DECODER_INTERFACE a2dp_decoder_interface_lhdcv5 = {
    a2dp_lhdcv5_decoder_init,
    a2dp_lhdcv5_decoder_cleanup,
    NULL,
    a2dp_lhdcv5_decoder_decode_packet_header,
    a2dp_lhdcv5_decoder_decode_packet,
    NULL,
    NULL,
    a2dp_lhdcv5_decoder_configure,
};

tA2D_STATUS A2DP_BuildInfoLhdcV5(uint8_t media_type,
                                 const tA2DP_LHDCV5_CIE* p_ie,
                                 uint8_t* p_result) {
  if (p_ie == NULL || p_result == NULL) return A2D_INVALID_PARAMS;

  *p_result++ = A2DP_LHDCV5_CODEC_LEN;
  *p_result++ = (media_type << 4);
  *p_result++ = A2D_MEDIA_CT_NON_A2DP;
  *p_result++ = (uint8_t)(p_ie->vendorId & 0xff);
  *p_result++ = (uint8_t)((p_ie->vendorId >> 8) & 0xff);
  *p_result++ = (uint8_t)((p_ie->vendorId >> 16) & 0xff);
  *p_result++ = (uint8_t)((p_ie->vendorId >> 24) & 0xff);
  *p_result++ = (uint8_t)(p_ie->codecId & 0xff);
  *p_result++ = (uint8_t)((p_ie->codecId >> 8) & 0xff);
  *p_result++ = p_ie->sampleRate & A2DP_LHDCV5_SAMPLING_FREQ_MASK;
  *p_result++ = (p_ie->bitsPerSample & A2DP_LHDCV5_BIT_FMT_MASK) |
                (p_ie->maxTargetBitrate & A2DP_LHDCV5_MAX_BIT_RATE_MASK) |
                (p_ie->minTargetBitrate & A2DP_LHDCV5_MIN_BIT_RATE_MASK);
  *p_result++ = (p_ie->version & A2DP_LHDCV5_VERSION_MASK) |
                (p_ie->frameLenType & A2DP_LHDCV5_FRAME_LEN_MASK);
  *p_result++ = (p_ie->hasFeatureAR ? A2DP_LHDCV5_FEATURE_AR : 0) |
                (p_ie->hasFeatureJAS ? A2DP_LHDCV5_FEATURE_JAS : 0) |
                (p_ie->hasFeatureMETA ? A2DP_LHDCV5_FEATURE_META : 0) |
                (p_ie->hasFeatureLL ? A2DP_LHDCV5_FEATURE_LL : 0) |
                (p_ie->hasFeatureLLESS48K ? A2DP_LHDCV5_FEATURE_LLESS48K : 0) |
                (p_ie->hasFeatureLLESS24Bit ? A2DP_LHDCV5_FEATURE_LLESS24BIT : 0) |
                (p_ie->hasFeatureLLESS96K ? A2DP_LHDCV5_FEATURE_LLESS96K : 0);
  *p_result++ = p_ie->hasFeatureLLESSRaw ? A2DP_LHDCV5_FEATURE_LLESS_RAW : 0;

  return A2D_SUCCESS;
}

tA2D_STATUS A2DP_ParseInfoLhdcV5(tA2DP_LHDCV5_CIE* p_ie,
                                 const uint8_t* p_codec_info,
                                 bool is_capability) {
  if (p_ie == NULL || p_codec_info == NULL) return A2D_INVALID_PARAMS;
  memset(p_ie, 0, sizeof(*p_ie));

  uint8_t losc = *p_codec_info++;
  if (losc != A2DP_LHDCV5_CODEC_LEN) return A2D_WRONG_CODEC;

  uint8_t media_type = (*p_codec_info++) >> 4;
  tA2D_CODEC_TYPE codec_type = *p_codec_info++;
  if (media_type != A2D_MEDIA_TYPE_AUDIO ||
      codec_type != A2D_MEDIA_CT_NON_A2DP) {
    return A2D_WRONG_CODEC;
  }

  p_ie->vendorId = (uint32_t)p_codec_info[0] |
                   ((uint32_t)p_codec_info[1] << 8) |
                   ((uint32_t)p_codec_info[2] << 16) |
                   ((uint32_t)p_codec_info[3] << 24);
  p_codec_info += 4;
  p_ie->codecId = (uint16_t)p_codec_info[0] |
                  ((uint16_t)p_codec_info[1] << 8);
  p_codec_info += 2;

  if (p_ie->vendorId != A2DP_LHDCV5_VENDOR_ID ||
      p_ie->codecId != A2DP_LHDCV5_CODEC_ID) {
    return A2D_WRONG_CODEC;
  }

  p_ie->sampleRate = *p_codec_info++ & A2DP_LHDCV5_SAMPLING_FREQ_MASK;
  uint8_t bitrate_depth = *p_codec_info++;
  p_ie->bitsPerSample = bitrate_depth & A2DP_LHDCV5_BIT_FMT_MASK;
  p_ie->maxTargetBitrate = bitrate_depth & A2DP_LHDCV5_MAX_BIT_RATE_MASK;
  p_ie->minTargetBitrate = bitrate_depth & A2DP_LHDCV5_MIN_BIT_RATE_MASK;

  uint8_t version_frame = *p_codec_info++;
  p_ie->version = version_frame & A2DP_LHDCV5_VERSION_MASK;
  p_ie->frameLenType = version_frame & A2DP_LHDCV5_FRAME_LEN_MASK;
  p_ie->channelMode = A2DP_LHDCV5_CHANNEL_MODE_STEREO;

  uint8_t features = *p_codec_info++ & A2DP_LHDCV5_FEATURE_MASK;
  p_ie->hasFeatureAR = (features & A2DP_LHDCV5_FEATURE_AR) != 0;
  p_ie->hasFeatureJAS = (features & A2DP_LHDCV5_FEATURE_JAS) != 0;
  p_ie->hasFeatureMETA = (features & A2DP_LHDCV5_FEATURE_META) != 0;
  p_ie->hasFeatureLL = (features & A2DP_LHDCV5_FEATURE_LL) != 0;
  p_ie->hasFeatureLLESS48K = (features & A2DP_LHDCV5_FEATURE_LLESS48K) != 0;
  p_ie->hasFeatureLLESS24Bit =
      (features & A2DP_LHDCV5_FEATURE_LLESS24BIT) != 0;
  p_ie->hasFeatureLLESS96K = (features & A2DP_LHDCV5_FEATURE_LLESS96K) != 0;
  p_ie->hasFeatureLLESSRaw =
      ((*p_codec_info++ & A2DP_LHDCV5_FEATURE_LLESS_RAW) != 0);

  if (is_capability) {
    if (A2D_BitsSet(p_ie->sampleRate) == A2D_SET_ZERO_BIT)
      return A2D_BAD_SAMP_FREQ;
    if (A2D_BitsSet(p_ie->bitsPerSample) == A2D_SET_ZERO_BIT)
      return A2D_FAIL;
    if ((p_ie->version & A2DP_LHDCV5_VER_1) == 0)
      return A2D_WRONG_CODEC;
    if (A2D_BitsSet(p_ie->frameLenType) == A2D_SET_ZERO_BIT)
      return A2D_FAIL;
    return A2D_SUCCESS;
  }

  return A2D_SUCCESS;
}

tA2D_STATUS A2DP_IsVendorPeerSourceCodecValidLhdcV5(
    const uint8_t* p_codec_info) {
  tA2DP_LHDCV5_CIE cfg_cie;
  tA2D_STATUS status = A2DP_ParseInfoLhdcV5(&cfg_cie, p_codec_info, true);
  if (status == A2D_SUCCESS) return status;
  return A2DP_ParseInfoLhdcV5(&cfg_cie, p_codec_info, false);
}

bool A2DP_IsVendorPeerSinkCodecValidLhdcV5(const uint8_t* p_codec_info) {
  tA2DP_LHDCV5_CIE cfg_cie;
  return (A2DP_ParseInfoLhdcV5(&cfg_cie, p_codec_info, false) == A2D_SUCCESS) ||
         (A2DP_ParseInfoLhdcV5(&cfg_cie, p_codec_info, true) == A2D_SUCCESS);
}

btav_a2dp_codec_index_t A2DP_VendorSinkCodecIndexLhdcV5(
    const uint8_t* p_codec_info) {
  UNUSED(p_codec_info);
  return BTAV_A2DP_CODEC_INDEX_SINK_LHDCV5;
}

btav_a2dp_codec_index_t A2DP_VendorSourceCodecIndexLhdcV5(
    const uint8_t* p_codec_info) {
  UNUSED(p_codec_info);
  return BTAV_A2DP_CODEC_INDEX_SOURCE_LHDCV5;
}

const char* A2DP_VendorCodecNameLhdcV5(const uint8_t* p_codec_info) {
  UNUSED(p_codec_info);
  return "LHDC V5";
}

bool A2DP_VendorCodecTypeEqualsLhdcV5(const uint8_t* p_codec_info_a,
                                      const uint8_t* p_codec_info_b) {
  tA2DP_LHDCV5_CIE cie_a;
  tA2DP_LHDCV5_CIE cie_b;

  if (A2DP_ParseInfoLhdcV5(&cie_a, p_codec_info_a, true) != A2D_SUCCESS)
    return false;
  if (A2DP_ParseInfoLhdcV5(&cie_b, p_codec_info_b, true) != A2D_SUCCESS)
    return false;

  return true;
}

bool A2DP_VendorInitCodecConfigLhdcV5(btav_a2dp_codec_index_t codec_index,
                                      uint8_t* p_result) {
  switch (codec_index) {
    case BTAV_A2DP_CODEC_INDEX_SINK_LHDCV5:
      return A2DP_VendorInitCodecConfigLhdcV5Sink(p_result);
    default:
      break;
  }
  return false;
}

bool A2DP_VendorInitCodecConfigLhdcV5Sink(uint8_t* p_codec_info) {
  return A2DP_BuildInfoLhdcV5(A2D_MEDIA_TYPE_AUDIO, &a2dp_lhdcv5_sink_caps,
                              p_codec_info) == A2D_SUCCESS;
}

bool A2DP_VendorBuildCodecConfigLhdcV5(uint8_t* p_src_cap, uint8_t* p_result) {
  tA2DP_LHDCV5_CIE src_cap;
  tA2DP_LHDCV5_CIE pref_cap = a2dp_lhdcv5_default_config;

  if (A2DP_ParseInfoLhdcV5(&src_cap, p_src_cap, true) != A2D_SUCCESS) {
    return false;
  }

  /* Prefer the highest hi-res rate the phone offers (192k default), falling back
   * down the chain. The decoder handles every rate via the validated fast IMDCT
   * (480/960/1920), the scale-factor/gain reconstruction is exact at all rates,
   * and the output ring uses rate-proportional prefetch so 192k stays fed. */
  if (src_cap.sampleRate & A2DP_LHDCV5_SAMPLING_FREQ_192000) {
    pref_cap.sampleRate = A2DP_LHDCV5_SAMPLING_FREQ_192000;
  } else if (src_cap.sampleRate & A2DP_LHDCV5_SAMPLING_FREQ_96000) {
    pref_cap.sampleRate = A2DP_LHDCV5_SAMPLING_FREQ_96000;
  } else if (src_cap.sampleRate & A2DP_LHDCV5_SAMPLING_FREQ_48000) {
    pref_cap.sampleRate = A2DP_LHDCV5_SAMPLING_FREQ_48000;
  } else if (src_cap.sampleRate & A2DP_LHDCV5_SAMPLING_FREQ_44100) {
    pref_cap.sampleRate = A2DP_LHDCV5_SAMPLING_FREQ_44100;
  } else {
    /* Phone offers only rates we don't support -> fail config; phone picks
     * another codec (LDAC/AAC/SBC) rather than a broken LHDC link. */
    return false;
  }

  if (src_cap.bitsPerSample & A2DP_LHDCV5_BITS_PER_SAMPLE_24) {
    pref_cap.bitsPerSample = A2DP_LHDCV5_BITS_PER_SAMPLE_24;
  } else if (src_cap.bitsPerSample & A2DP_LHDCV5_BITS_PER_SAMPLE_16) {
    pref_cap.bitsPerSample = A2DP_LHDCV5_BITS_PER_SAMPLE_16;
  }

  /* Echo the source's negotiated target-bitrate range. Previously pref_cap kept
   * the default (min=64K / max=1000K), so the SET_CONFIGURATION response did NOT
   * match the bitrate the phone requested. When the user fixes a low target
   * bitrate (256 kbps sets MIN_BIT_RATE=256K=0x80), the phone saw the sink echo
   * min=64K, treated it as a config mismatch, and refused to start the stream ->
   * NO AUDIO at 256 kbps (higher fixed rates use a lower min and slipped through).
   * The sink decodes whatever frames arrive and advertises the full 64K..1000K
   * range, so echoing the phone's selected min/max is always valid. */
  pref_cap.maxTargetBitrate = src_cap.maxTargetBitrate;
  pref_cap.minTargetBitrate = src_cap.minTargetBitrate;

  pref_cap.hasFeatureAR = src_cap.hasFeatureAR;
  pref_cap.hasFeatureJAS = src_cap.hasFeatureJAS;
  pref_cap.hasFeatureMETA = src_cap.hasFeatureMETA;
  pref_cap.hasFeatureLL = src_cap.hasFeatureLL;
  pref_cap.hasFeatureLLESS48K = src_cap.hasFeatureLLESS48K;
  pref_cap.hasFeatureLLESS24Bit = src_cap.hasFeatureLLESS24Bit;
  pref_cap.hasFeatureLLESS96K = src_cap.hasFeatureLLESS96K;
  pref_cap.hasFeatureLLESSRaw = src_cap.hasFeatureLLESSRaw;

  return A2DP_BuildInfoLhdcV5(A2D_MEDIA_TYPE_AUDIO, &pref_cap, p_result) ==
         A2D_SUCCESS;
}

const tA2DP_DECODER_INTERFACE* A2DP_GetVendorDecoderInterfaceLhdcV5(
    const uint8_t* p_codec_info) {
  if (!A2DP_IsVendorPeerSinkCodecValidLhdcV5(p_codec_info)) return NULL;
  return &a2dp_decoder_interface_lhdcv5;
}

#endif /* defined(LHDCV5_DEC_INCLUDED) && LHDCV5_DEC_INCLUDED == TRUE) */
