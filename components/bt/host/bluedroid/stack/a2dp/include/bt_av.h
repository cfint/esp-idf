/*
 * SPDX-FileCopyrightText: 2016 The Android Open Source Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ANDROID_INCLUDE_BT_AV_H
#define ANDROID_INCLUDE_BT_AV_H

#include "common/bt_target.h"

/*
 * Enum values for each A2DP supported codec.
 * There should be a separate entry for each A2DP codec that is supported
 * for encoding (SRC), and for decoding purpose (SINK).
 */
typedef enum {
  BTAV_A2DP_CODEC_INDEX_SOURCE_MIN = 0,

  // Add an entry for each source codec here.
  BTAV_A2DP_CODEC_INDEX_SOURCE_SBC = 0,
#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  BTAV_A2DP_CODEC_INDEX_SOURCE_APTX,
#endif /* APTX_DEC_INCLUDED */

  BTAV_A2DP_CODEC_INDEX_SOURCE_MAX,

  BTAV_A2DP_CODEC_INDEX_SINK_MIN = BTAV_A2DP_CODEC_INDEX_SOURCE_MAX,

  // Add an entry for each sink codec here
  BTAV_A2DP_CODEC_INDEX_SINK_SBC = BTAV_A2DP_CODEC_INDEX_SINK_MIN,
#if (defined(APTX_DEC_INCLUDED) && APTX_DEC_INCLUDED == TRUE)
  BTAV_A2DP_CODEC_INDEX_SINK_APTX,
#endif /* APTX_DEC_INCLUDED */

  BTAV_A2DP_CODEC_INDEX_SINK_MAX,

  BTAV_A2DP_CODEC_INDEX_MIN = BTAV_A2DP_CODEC_INDEX_SOURCE_MIN,
  BTAV_A2DP_CODEC_INDEX_MAX = BTAV_A2DP_CODEC_INDEX_SINK_MAX
} btav_a2dp_codec_index_t;

typedef enum {
  BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE = 0x0,
  BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16 = 0x1 << 0,
  BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24 = 0x1 << 1,
  BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32 = 0x1 << 2
} btav_a2dp_codec_bits_per_sample_t;

#endif /* ANDROID_INCLUDE_BT_AV_H */
