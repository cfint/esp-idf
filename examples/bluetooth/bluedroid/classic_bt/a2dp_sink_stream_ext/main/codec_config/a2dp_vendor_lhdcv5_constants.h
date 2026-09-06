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

#ifndef A2DP_VENDOR_LHDCV5_CONSTANTS_H
#define A2DP_VENDOR_LHDCV5_CONSTANTS_H

////////////////////////////////////////////////////////////////////
// LHDCV5 codec info (capabilities) format:
// Total Length: A2DP_LHDCV5_CODEC_LEN + 1(losc)
//  --------------------------------------------------------------------------------------
//  H0   |    H1     |    H2     |  P0-P3   | P4-P5   |
//  losc | mediaType | codecType | vendorId | codecId |
//  --------------------------------------------------------------------------------------
//  P6[5:0]     |
//  Sample Rate |
//  --------------------------------------------------------------------------------------
//  P7[7:6]     | P7[5:4]     | P7[2:0]   |
//  Min BitRate | Max BitRate | Bit Depth |
//  --------------------------------------------------------------------------------------
//  P8[4]       | P8[3:0]        |
//  FrameLen5ms | Version Number |
//  --------------------------------------------------------------------------------------
//  P9[7]         | P9[6]       | P9[5]         | P9[4]         | P9[2] | P9[1] | P9[0] |
//  Lossless48K   | Low Latency | Lossless24Bit | Lossless96K   | Meta  | JAS   | 3DAR  |
//  --------------------------------------------------------------------------------------
//  P10[7]         |
//  LosslessRaw48K |
//  --------------------------------------------------------------------------------------

// P0-P3 Vendor ID: A2DP_LHDC_VENDOR_ID (0x0000053a)
// P4-P5 Vendor Specific Codec ID: A2DP_LHDCV5_CODEC_ID (0x4C35)
// P6[5:0] Sampling Frequency
#define A2DP_LHDCV5_SAMPLING_FREQ_MASK    (0x35)
#define A2DP_LHDCV5_SAMPLING_FREQ_44100   (0x20)
#define A2DP_LHDCV5_SAMPLING_FREQ_48000   (0x10)
#define A2DP_LHDCV5_SAMPLING_FREQ_96000   (0x04)
#define A2DP_LHDCV5_SAMPLING_FREQ_192000  (0x01)
#define A2DP_LHDCV5_SAMPLING_FREQ_NS      (0x00)

// P7[2:0] Bit depth
#define A2DP_LHDCV5_BIT_FMT_MASK  (0x07)
#define A2DP_LHDCV5_BIT_FMT_16    (0x04)
#define A2DP_LHDCV5_BIT_FMT_24    (0x02)
#define A2DP_LHDCV5_BIT_FMT_32    (0x01)
#define A2DP_LHDCV5_BIT_FMT_NS    (0x00)

// P7[5:4] Max Bit Rate Type
#define A2DP_LHDCV5_MAX_BIT_RATE_MASK   (0x30)
#define A2DP_LHDCV5_MAX_BIT_RATE_900K   (0x30)
#define A2DP_LHDCV5_MAX_BIT_RATE_500K   (0x20)
#define A2DP_LHDCV5_MAX_BIT_RATE_400K   (0x10)
#define A2DP_LHDCV5_MAX_BIT_RATE_1000K  (0x00)  //equivalent to no upper limit

// P7[7:6] Min Bit Rate Type
#define A2DP_LHDCV5_MIN_BIT_RATE_MASK   (0xC0)
#define A2DP_LHDCV5_MIN_BIT_RATE_400K   (0xC0)
#define A2DP_LHDCV5_MIN_BIT_RATE_256K   (0x80)
#define A2DP_LHDCV5_MIN_BIT_RATE_160K   (0x40)
#define A2DP_LHDCV5_MIN_BIT_RATE_64K    (0x00)  //equivalent to no lower limit

// P8[3:0] Codec SubVersion (bitmap)
#define A2DP_LHDCV5_VERSION_MASK    (0x0F)
#define A2DP_LHDCV5_VER_1           (0x01)
#define A2DP_LHDCV5_VER_NS          (0x00)

// P8[5:4] Frame Length Type
#define A2DP_LHDCV5_FRAME_LEN_MASK  (0x10)
#define A2DP_LHDCV5_FRAME_LEN_5MS   (0x10)
#define A2DP_LHDCV5_FRAME_LEN_NS    (0x00)

// P9[0] 3DAR
// P9[1] JAS
// P9[2] Meta
// P9[4] Lossless96K
// P9[5] Lossless24Bit
// P9[6] LowLatency
// P9[7] Lossless48K
#define A2DP_LHDCV5_FEATURE_MASK        (0xC7)
#define A2DP_LHDCV5_FEATURE_LLESS48K    (0x80)
#define A2DP_LHDCV5_FEATURE_LL          (0x40)
#define A2DP_LHDCV5_FEATURE_LLESS24BIT  (0x20)
#define A2DP_LHDCV5_FEATURE_LLESS96K    (0x10)
#define A2DP_LHDCV5_FEATURE_META        (0x04)
#define A2DP_LHDCV5_FEATURE_JAS         (0x02)
#define A2DP_LHDCV5_FEATURE_AR          (0x01)

// P10[7] LosslessRaw48K
#define A2DP_LHDCV5_FEATURE_LLESS_RAW   (0x80)
////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////
//  attributes which not in codec info format
//    channel mode
//    channel separation mode
////////////////////////////////////////////////////////////////////
// channel mode:
#define A2DP_LHDCV5_CHANNEL_MODE_MASK   (0x07)
#define A2DP_LHDCV5_CHANNEL_MODE_MONO   (0x04)
#define A2DP_LHDCV5_CHANNEL_MODE_DUAL   (0x02)
#define A2DP_LHDCV5_CHANNEL_MODE_STEREO (0x01)
#define A2DP_LHDCV5_CHANNEL_MODE_NS     (0x00)
////////////////////////////////////////////////////////////////////

/************************************************
 * LHDC Feature Capabilities on A2DP specifics:
   * feature id:                          (1 byte)
   * target specific index:               (2 bits)
   * target bit index on a specific:      (decimal: 0~63)
************************************************/
#define A2DP_LHDCV5_FEATURE_MAGIC_NUM (0x5C000000)

// feature code:
#define LHDCV5_FEATURE_CODE_MASK     (0xFF)
#define LHDCV5_FEATURE_CODE_NA       (0x00)
#define LHDCV5_FEATURE_CODE_JAS      (0x01)
#define LHDCV5_FEATURE_CODE_AR       (0x02)
#define LHDCV5_FEATURE_CODE_META     (0x03)
#define LHDCV5_FEATURE_CODE_LL       (0x08)
#define LHDCV5_FEATURE_CODE_LLESS    (0x09)
#define LHDCV5_FEATURE_CODE_LLESS_RAW (0x0A)

// target specific index:
#define LHDCV5_FEATURE_ON_A2DP_SPECIFIC_1    (0x00)     //2-bit:00
#define LHDCV5_FEATURE_ON_A2DP_SPECIFIC_2    (0x40)     //2-bit:01
#define LHDCV5_FEATURE_ON_A2DP_SPECIFIC_3    (0x80)     //2-bit:10
#define LHDCV5_FEATURE_ON_A2DP_SPECIFIC_4    (0xC0)     //2-bit:11

// target bit index on the specific:
//  specific@1
#define LHDCV5_FEATURE_QM_SPEC_BIT_POS        (0x00)
//  specific@2
#define LHDCV5_FEATURE_LL_SPEC_BIT_POS        (0x00)
//  specific@3
#define LHDCV5_FEATURE_JAS_SPEC_BIT_POS       (0x00)
#define LHDCV5_FEATURE_AR_SPEC_BIT_POS        (0x01)
#define LHDCV5_FEATURE_META_SPEC_BIT_POS      (0x02)
#define LHDCV5_FEATURE_LLESS_SPEC_BIT_POS     (0x07)
#define LHDCV5_FEATURE_LLESS_RAW_SPEC_BIT_POS (0x08)
// Notice: the highest bit position is limited by A2DP_LHDC_FEATURE_MAGIC_NUM(0x4C000000)
//  ie., available range in a specific: int64[24:0]
#define LHDCV5_FEATURE_MAX_SPEC_BIT_POS       (0x19)

#define LHDC_SETUP_A2DP_SPEC(cfg, spec, has, value)  do{   \
  if( spec == LHDCV5_FEATURE_ON_A2DP_SPECIFIC_1 ) \
    (has) ? (cfg->codec_specific_1 |= value) : (cfg->codec_specific_1 &= ~value);   \
  if( spec == LHDCV5_FEATURE_ON_A2DP_SPECIFIC_2 ) \
    (has) ? (cfg->codec_specific_2 |= value) : (cfg->codec_specific_2 &= ~value);   \
  if( spec == LHDCV5_FEATURE_ON_A2DP_SPECIFIC_3 ) \
    (has) ? (cfg->codec_specific_3 |= value) : (cfg->codec_specific_3 &= ~value);   \
  if( spec == LHDCV5_FEATURE_ON_A2DP_SPECIFIC_4 ) \
    (has) ? (cfg->codec_specific_4 |= value) : (cfg->codec_specific_4 &= ~value);   \
} while(0)

#define LHDCV5_CHECK_IN_A2DP_SPEC(cfg, spec, value)  ({ \
  bool marco_ret = false; \
  do{   \
    if( spec == LHDCV5_FEATURE_ON_A2DP_SPECIFIC_1 ) \
      marco_ret = (cfg->codec_specific_1 & value);   \
    if( spec == LHDCV5_FEATURE_ON_A2DP_SPECIFIC_2 ) \
      marco_ret = (cfg->codec_specific_2 & value);   \
    if( spec == LHDCV5_FEATURE_ON_A2DP_SPECIFIC_3 ) \
      marco_ret = (cfg->codec_specific_3 & value);   \
    if( spec == LHDCV5_FEATURE_ON_A2DP_SPECIFIC_4 ) \
      marco_ret = (cfg->codec_specific_4 & value);   \
    } while(0);  \
  marco_ret;   \
})

//
// Savitech - LHDC Extended API Start
//
/* LHDC Extend API Category */
// A2DP Type API: handled in bt stack
#define LHDCV5_EXTEND_API_CODE_A2DP_TYPE            (0x0A)
// Lib Type API: handled by codec lib
#define LHDCV5_EXTEND_API_CODE_LIB_TYPE             (0x0C)

#define LHDCV5_EXTEND_API_A2DP_SPEC_CODE_HEAD       (4)   /* position of API command code in buffer field */
#define LHDCV5_EXTEND_API_A2DP_SPEC_ID_HEAD         (8)   /* position of codec config id in buffer field */

//
// A2DP Type API: Get info from A2DP codec config's specifics
//
#define LHDCV5_EXTEND_API_A2DP_SPEC_CODE      (0x0A010001)
#define LHDCV5_EXTEND_API_A2DP_SPEC_VER2      (0x02000000)

/* id for A2DP codec config
 * 0x01: codec_config_
 * 0x02: codec_capability_
 * 0x03: codec_local_capability_
 * 0x04: codec_selectable_capability_
 * 0x05: codec_user_config_
 * 0x06: codec_audio_config_
 */
#define LHDCV5_EXTEND_API_A2DP_SPEC_CFG                (0x01)
#define LHDCV5_EXTEND_API_A2DP_SPEC_CAP                (0x02)
#define LHDCV5_EXTEND_API_A2DP_SPEC_LOCAL_CAP          (0x03)
#define LHDCV5_EXTEND_API_A2DP_SPEC_SELECT_CAP         (0x04)
#define LHDCV5_EXTEND_API_A2DP_SPEC_USER_CFG           (0x05)
#define LHDCV5_EXTEND_API_A2DP_SPEC_AUDIO_CFG          (0x06)
/* ************************************************************************
 * Fields in buffer for LHDCV5_EXTEND_API_VER_GET_SPECIFIC_V2
 * total 64 bytes:
   * API Version:                   (4 bytes)
   * API Code:                      (4 bytes)
   * A2DP Codec Config Id:          (1 bytes)
   * Reserved:                      (7 bytes)
   * A2dp Specific1:                (8 bytes)
   * A2dp Specific2:                (8 bytes)
   * A2dp Specific3:                (8 bytes)
   * A2dp Specific4:                (8 bytes)
   * Info fields:                   (5*2 bytes)
     * [0~1]: AR
     * [2~3]: JAS
     * [4~5]: META
     * [6~7]: Low Latency
     * [8~9]: Loss Less
   * Pad:                           (6 bytes)
 * ************************************************************************/
#define LHDCV5_EXTEND_API_A2DP_SPEC_VER_SIZE        4       /* API version */
#define LHDCV5_EXTEND_API_A2DP_SPEC_CODE_SIZE       4       /* API index code */
#define LHDCV5_EXTEND_API_A2DP_SPEC_CFGID_SIZE      1       /* A2DP codec config code */
#define LHDCV5_EXTEND_API_A2DP_SPEC_RSVD_V2         7       /* Reserved bytes */
#define LHDCV5_EXTEND_API_A2DP_SPEC_1_SIZE          8       /* Specific 1 */
#define LHDCV5_EXTEND_API_A2DP_SPEC_2_SIZE          8       /* Specific 2 */
#define LHDCV5_EXTEND_API_A2DP_SPEC_3_SIZE          8       /* Specific 3 */
#define LHDCV5_EXTEND_API_A2DP_SPEC_4_SIZE          8       /* Specific 4 */
#define LHDCV5_EXTEND_API_A2DP_SPEC_INFO_SIZE_V2    (5<<1)  /* Info fields */
// total size of buffer fields (64)
#define LHDCV5_EXTEND_API_A2DP_SPEC_TOTAL_SIZE_V2   (64)

#define LHDCV5_EXTEND_API_A2DP_SPEC1_HEAD_V2        (16)
#define LHDCV5_EXTEND_API_A2DP_SPEC2_HEAD_V2        (24)
#define LHDCV5_EXTEND_API_A2DP_SPEC3_HEAD_V2        (32)
#define LHDCV5_EXTEND_API_A2DP_SPEC4_HEAD_V2        (40)
#define LHDCV5_EXTEND_API_A2DP_SPEC_INFO_HEAD_V2    (48)

//
// Savitech - LHDC Extended API End
//
#endif  // A2DP_VENDOR_LHDCV5_CONSTANTS_H