/*
 * Copyright (C) 2016 The Android Open Source Project
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

//
// A2DP constants for LHDC codec
//

#ifndef A2DP_VENDOR_LHDC_CONSTANTS_H
#define A2DP_VENDOR_LHDC_CONSTANTS_H
#define A2DP_LHDC_SILENCE_LEVEL  1.0f
#define A2DP_LHDC_VERSION_NUMBER    0x01
#define A2DP_LHDC_VENDOR_CMD_MASK    0xC000
#define A2DP_LHDC_VENDOR_FEATURE_MASK    (0xFF000000)

// LHDC Quality Mode Index
//LHDC not supported auto bit rate now.
#define A2DP_LHDC_QUALITY_MAGIC_NUM 0x8000

/* LHDC quality supporting bit rate */
#define A2DP_LHDC_QUALITY_MASK   0xFF
#define A2DP_LHDC_QUALITY_ABR    9     // ABR mode
#define A2DP_LHDC_QUALITY_HIGH1  8     // 1000 (supported in LHDCV5+)
#define A2DP_LHDC_QUALITY_HIGH   7     // 900
#define A2DP_LHDC_QUALITY_MID    6     // 500
#define A2DP_LHDC_QUALITY_LOW    5     // 400
#define A2DP_LHDC_QUALITY_LOW4   4     // 320
#define A2DP_LHDC_QUALITY_LOW3   3     // 256
#define A2DP_LHDC_QUALITY_LOW2   2     // 192
#define A2DP_LHDC_QUALITY_LOW1   1     // 128(LHDCV3) / 160(LHDCV5)
#define A2DP_LHDC_QUALITY_LOW0   0     // 64

// LHDC Peer Max/Min Target Bitrate
#define A2DP_LHDC_PEER_MAX_BITRATE_MASK   (0xF00)
#define A2DP_LHDC_PEER_MIN_BITRATE_MASK   (0xF0000)

// LHDCV3/V4 peer min bitrate mode
#define A2DP_LHDC_PEER_MIN_BITRATE_ON     (0x10000)

// LHDCV3/V4 sub-type capabilities
#define A2DP_LHDC_CAP_V4_LLAC_MASK        (0xF00000)
#define A2DP_LHDC_CAP_V4_LLAC             (0x300000)
#define A2DP_LHDC_CAP_V4_ONLY             (0x200000)
#define A2DP_LHDC_CAP_LLAC_ONLY           (0x100000)
#define A2DP_LHDC_CAP_V3_ONLY             (0x0)



#define A2DP_LHDC_LATENCY_MAGIC_NUM 0xC000
#define A2DP_LHDC_LL_ENABLE	  1	// LL enabled
#define A2DP_LHDC_LL_DISABLE	0	// LL disabled

#define A2DP_LHDC_LATENCY_LOW	0	// 50-100 ms
#define A2DP_LHDC_LATENCY_MID	1	// default value, 150-200 ms
#define A2DP_LHDC_LATENCY_HIGH	2	// 300-500 ms


// Length of the LHDC Media Payload header
#define A2DP_LHDC_MPL_HDR_LEN 2

// LHDC Media Payload Header
#define A2DP_LHDC_HDR_F_MSK 0x80
#define A2DP_LHDC_HDR_S_MSK 0x40
#define A2DP_LHDC_HDR_L_MSK 0x20

#define A2DP_LHDCV3_HDR_NUM_MSK 0x0F
#define A2DP_LHDCV2_HDR_NUM_MSK 0x7
#define A2DP_LHDCV1_HDR_NUM_MSK 0x7
#define A2DP_LHDC_HDR_NUM_SHIFT 2
#define A2DP_LHDCV3_HDR_NUM_MAX 8
#define A2DP_LHDCV2_HDR_NUM_MAX 7
#define A2DP_LHDCV1_HDR_NUM_MAX 7

#define A2DP_LHDC_HDR_LATENCY_LOW   0x00
#define A2DP_LHDC_HDR_LATENCY_MID   0x01
#define A2DP_LHDC_HDR_LATENCY_HIGH  0x02
#define A2DP_LHDC_HDR_LATENCY_MSK   0x03

// LHDC codec specific settings
//#define A2DP_LHDCV3_CODEC_LEN 12
#define A2DP_LHDCV3_CODEC_LEN 11
#define A2DP_LHDCV2_CODEC_LEN 11
#define A2DP_LHDCV1_CODEC_LEN 9
#define A2DP_LHDC_LL_CODEC_LEN 9
#define A2DP_LHDCV5_CODEC_LEN 13

// [Octet 0-3] Vendor ID
#define A2DP_LHDC_VENDOR_ID 0x0000053A
// [Octet 4-5] Vendor Specific Codec ID
#define A2DP_LHDCV2_CODEC_ID 0x4C32
#define A2DP_LHDCV3_CODEC_ID 0x4C33
#define A2DP_LHDCV1_CODEC_ID 0x484C
#define A2DP_LHDCV1_LL_CODEC_ID 0x4C4C
#define A2DP_LHDCV5_CODEC_ID 0x4C35

// [Octet 6], [Bits 0-3] Sampling Frequency
#define A2DP_LHDC_SAMPLING_FREQ_MASK 0x0F
#define A2DP_LHDC_SAMPLING_FREQ_44100 0x08
#define A2DP_LHDC_SAMPLING_FREQ_48000 0x04
#define A2DP_LHDC_SAMPLING_FREQ_88200 0x02
#define A2DP_LHDC_SAMPLING_FREQ_96000 0x01
// [Octet 6], [Bits 3-4] Bit dipth
#define A2DP_BAD_BITS_PER_SAMPLE    0xff
#define A2DP_LHDC_BIT_FMT_MASK 	 0x30
#define A2DP_LHDC_BIT_FMT_24	 0x10
#define A2DP_LHDC_BIT_FMT_16	 0x20

// [Octet 6], [Bits 6-7] Bit dipth
#define A2DP_LHDC_FEATURE_AR		0x80
#define A2DP_LHDC_FEATURE_JAS		0x40

//[Octet 7:bit0..bit3]
#define A2DP_LHDC_VERSION_MASK 0x0F
//#define A2DP_LHDC_VERSION_2    0x01
//#define A2DP_LHDC_VERSION_3    0x02
//Supported version
typedef enum {
    A2DP_LHDC_VER2_BES  = 0,
    A2DP_LHDC_VER2 = 1,
    A2DP_LHDC_VER3 = 0x01,
    A2DP_LHDC_VER4 = 0x02,
    A2DP_LHDC_VER5 = 0x04,
    A2DP_LHDC_VER6 = 0x08,
    A2DP_LHDC_ERROR_VER,

    A2DP_LHDC_LAST_SUPPORTED_VERSION = A2DP_LHDC_VER4,
} A2DP_LHDC_VERSION;

//[Octet 7:bit4..bit5]
#define A2DP_LHDC_MAX_BIT_RATE_MASK       0x30
#define A2DP_LHDC_MAX_BIT_RATE_900K       0x00
#define A2DP_LHDC_MAX_BIT_RATE_500K       0x10		//500~600K
#define A2DP_LHDC_MAX_BIT_RATE_400K       0x20
//[Octet 7:bit6]
#define A2DP_LHDC_LL_MASK             0x40
#define A2DP_LHDC_LL_NONE             0x00
#define A2DP_LHDC_LL_SUPPORTED        0x40

//[Octet 7:bit7]
#define A2DP_LHDC_FEATURE_LLAC		0x80

//[Octet 8:bit0..bit3]
#define A2DP_LHDC_CH_SPLIT_MSK        0x0f
#define A2DP_LHDC_CH_SPLIT_NONE       0x01
#define A2DP_LHDC_CH_SPLIT_TWS        0x02
#define A2DP_LHDC_CH_SPLIT_TWS_PLUS   0x04

//[Octet 8:bit4..bit7]
#define A2DP_LHDC_FEATURE_META		0x10
#define A2DP_LHDC_FEATURE_MIN_BR	0x20
#define A2DP_LHDC_FEATURE_LARC		0x40
#define A2DP_LHDC_FEATURE_LHDCV4	0x80

//For LL used
#define A2DP_LHDC_CHANNEL_SEPARATION  0x40


//Only supported stereo
#define A2DP_LHDC_CHANNEL_MODE_STEREO 0x03

#define A2DP_LHDC_BITRATE_900K		0x01
#define A2DP_LHDC_BITRATE_600K		0x02
#define A2DP_LHDC_BITRATE_400K		0x04
#define A2DP_LHDC_BITRATE_320K		0x08
#define A2DP_LHDC_BITRATE_256K		0x10
#define A2DP_LHDC_BITRATE_192K		0x20
#define A2DP_LHDC_BITRATE_128K		0x40
#define A2DP_LHDC_BITRATE_64K		0x80
#define A2DP_LHDC_BITRATE_ALL		0xff


#define A2DP_LHDC_FEATURE_MAGIC_NUM (0x4C000000)
//LHDC Features: codec config specific field bitmap definition
//specific2
#define A2DP_LHDC_LL_ENABLED		0x1ULL
//specific3
#define A2DP_LHDC_JAS_ENABLED		0x1ULL
#define A2DP_LHDC_AR_ENABLED		0x2ULL
#define A2DP_LHDC_META_ENABLED		0x4ULL
#define A2DP_LHDC_LLAC_ENABLED		0x8ULL
#define A2DP_LHDC_MBR_ENABLED		0x10ULL
#define A2DP_LHDC_LARC_ENABLED		0x20ULL
#define A2DP_LHDC_V4_ENABLED		0x40ULL
/* Define the ?th bit(from least significant bit) in the specific, sync with the bitmap definition
 *  ex: A2DP_LHDC_AR_ENABLED = (2^A2DP_LHDC_AR_SPEC_BIT_POS)
 * */
//default in specific2
#define A2DP_LHDC_LL_SPEC_BIT_POS        (0x0)
//default in specific3
#define A2DP_LHDC_JAS_SPEC_BIT_POS       (0x0)
#define A2DP_LHDC_AR_SPEC_BIT_POS        (0x01)
#define A2DP_LHDC_META_SPEC_BIT_POS      (0x02)
#define A2DP_LHDC_LLAC_SPEC_BIT_POS      (0x03)
#define A2DP_LHDC_MBR_SPEC_BIT_POS       (0x04)
#define A2DP_LHDC_LARC_SPEC_BIT_POS      (0x05)
#define A2DP_LHDC_V4_SPEC_BIT_POS        (0x06)

/* bitmap for A2DP codec config selecting */
#define A2DP_LHDC_TO_A2DP_CODEC_CONFIG_         0x1ULL      //codec_config_
#define A2DP_LHDC_TO_A2DP_CODEC_CAP_            0x2ULL      //codec_capability_
#define A2DP_LHDC_TO_A2DP_CODEC_LOCAL_CAP_      0x4ULL      //codec_local_capability_
#define A2DP_LHDC_TO_A2DP_CODEC_SELECT_CAP_     0x8ULL      //codec_selectable_capability_
#define A2DP_LHDC_TO_A2DP_CODEC_USER_           0x10ULL     //codec_user_config_
#define A2DP_LHDC_TO_A2DP_CODEC_AUDIO_          0x20ULL     //codec_audio_config_

#define SETUP_A2DP_SPEC(cfg, spec, has, value)  do{   \
  if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC1_INDEX ) \
    (has) ? (cfg->codec_specific_1 |= value) : (cfg->codec_specific_1 &= ~value);   \
  if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC2_INDEX ) \
    (has) ? (cfg->codec_specific_2 |= value) : (cfg->codec_specific_2 &= ~value);   \
  if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC3_INDEX ) \
    (has) ? (cfg->codec_specific_3 |= value) : (cfg->codec_specific_3 &= ~value);   \
  if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC4_INDEX ) \
    (has) ? (cfg->codec_specific_4 |= value) : (cfg->codec_specific_4 &= ~value);   \
} while(0)

#define CHECK_IN_A2DP_SPEC(cfg, spec, value)  do{   \
  if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC1_INDEX ) \
    return (cfg->codec_specific_1 & value);   \
  if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC2_INDEX ) \
    return (cfg->codec_specific_2 & value);   \
  if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC3_INDEX ) \
    return (cfg->codec_specific_3 & value);   \
  if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC4_INDEX ) \
    return (cfg->codec_specific_4 & value);   \
  return false;   \
} while(0)

// TODO: return version macro to replace LHDC_CHECK_IN_A2DP_SPEC
#define LHDCV3_CHECK_IN_A2DP_SPEC(cfg, spec, value)  ({ \
  bool marco_ret = false; \
  do{   \
    if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC1_INDEX ) \
      marco_ret = (cfg->codec_specific_1 & value);   \
    if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC2_INDEX ) \
      marco_ret = (cfg->codec_specific_2 & value);   \
    if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC3_INDEX ) \
      marco_ret = (cfg->codec_specific_3 & value);   \
    if( spec == LHDC_EXTEND_FUNC_A2DP_SPECIFIC4_INDEX ) \
      marco_ret = (cfg->codec_specific_4 & value);   \
    } while(0);  \
  marco_ret;   \
})

//
// Savitech - LHDC aDSP configuration
//
// Lhdcv5Version: 1 << (below value-1)
#define A2DP_OFFLOAD_LHDCV2_VER_1                   0x01
#define A2DP_OFFLOAD_LHDCV3_V3_ONLY                 0x02
#define A2DP_OFFLOAD_LHDCV3_V4_ONLY                 0x03
#define A2DP_OFFLOAD_LHDCV3_LLAC                    0x04
#define A2DP_OFFLOAD_LHDCV5_VER_1                   0x01

// Lhdcv5QualityIndex
#define A2DP_OFFLOAD_LHDC_QUALITY_LOW0            0x01
#define A2DP_OFFLOAD_LHDC_QUALITY_LOW1            0x02
#define A2DP_OFFLOAD_LHDC_QUALITY_LOW2            0x04
#define A2DP_OFFLOAD_LHDC_QUALITY_LOW3            0x08
#define A2DP_OFFLOAD_LHDC_QUALITY_LOW4            0x10
#define A2DP_OFFLOAD_LHDC_QUALITY_LOW             0x20
#define A2DP_OFFLOAD_LHDC_QUALITY_MID             0x40
#define A2DP_OFFLOAD_LHDC_QUALITY_HIGH            0x80
#define A2DP_OFFLOAD_LHDC_QUALITY_HIGH1           0x100
#define A2DP_OFFLOAD_LHDC_QUALITY_ABR             0x8000

// Lhdcv5FrameDuration
#define A2DP_OFFLOAD_LHDC_FRAME_DURATION_5000US   0x01

// Lhdcv5DataInterval
#define A2DP_OFFLOAD_LHDC_DATA_INTERVAL_20MS      0x01
#define A2DP_OFFLOAD_LHDC_DATA_INTERVAL_10MS      0x02

// Lhdcv5Specific
#define A2DP_OFFLOAD_LHDC_SPECIFIC_FEATURE_AR     0x01
#define A2DP_OFFLOAD_LHDC_SPECIFIC_FEATURE_JAS    0x02
#define A2DP_OFFLOAD_LHDC_SPECIFIC_FEATURE_META   0x04

#define A2DP_OFFLOAD_LHDC_SPECIFIC_ACTION_AR_ON   0x01
#define A2DP_OFFLOAD_LHDC_SPECIFIC_FEATURE_SPLIT  0x80

// Lhdcv5Parameters
#define A2DP_OFFLOAD_LHDC_CFG_VER                   6
#define A2DP_OFFLOAD_LHDC_CFG_BITRATE_L             7
#define A2DP_OFFLOAD_LHDC_CFG_BITRATE_H             8
#define A2DP_OFFLOAD_LHDC_CFG_MAXBITRATE_L          9
#define A2DP_OFFLOAD_LHDC_CFG_MAXBITRATE_H          10
#define A2DP_OFFLOAD_LHDC_CFG_MINBITRATE_L          11
#define A2DP_OFFLOAD_LHDC_CFG_MINBITRATE_H          12
#define A2DP_OFFLOAD_LHDC_CFG_FRAMEDUR              13
#define A2DP_OFFLOAD_LHDC_CFG_INTERVAL              14
#define A2DP_OFFLOAD_LHDC_CFG_SPEC1                 15
#define A2DP_OFFLOAD_LHDC_CFG_SPEC2                 16
#define A2DP_OFFLOAD_LHDC_CFG_META                  17

#endif  // A2DP_VENDOR_LHDC_CONSTANTS_H