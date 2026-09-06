/**
 * SPDX-License-Identifier: Apache-2.0
 * 更新于：2025年9月11日，by MLX
 * 增加了编码类型返回值的定义
 */

#ifndef __CODEC_CONFIG__
#define __CODEC_CONFIG__

#include <stdint.h>
#include "esp_a2dp_api.h"

#define CODEC_CONFIG_TAG       "CODEC_CONFIG"

#ifdef __cplusplus
extern "C"
{
#endif  /* __cplusplus */

// 编码类型定义，用于返回编码类型
typedef enum {
    CODEC_SBC,
    CODEC_APTX,
    CODEC_APTX_LL,
    CODEC_APTX_HD,
    CODEC_LDAC,
    CODEC_OPUS,
    CODEC_LC3PLUS,
    CODEC_AAC, // 也称为M24
    CODEC_LHDCV5,
    CODEC_UNKNOWN
} codec_type_t;

bool get_codec_config(esp_a2d_cb_param_t *a2d, uint32_t* sr, uint8_t* bps,
                      uint8_t* ch, codec_type_t* codec_type);

#ifdef __cplusplus
}   /* extern "C" */
#endif /* __cplusplus */

#endif /* __CODEC_CONFIG__ */
