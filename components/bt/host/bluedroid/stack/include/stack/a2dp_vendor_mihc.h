/*
 * SPDX-FileCopyrightText: 2025 The Android Open Source Project
 *
 * SPDX-License-Identifier: Apache-2.0
 * 
 * a2dp_vendor_ldac.h
 */

//
// A2DP Codec API for MIHC
//

#ifndef A2DP_VENDOR_MIHC_H
#define A2DP_VENDOR_MIHC_H

#include "a2d_api.h"
#include "a2dp_codec_api.h"
#include "a2dp_vendor_mihc_constants.h"
#include "a2dp_shim.h"
#include "avdt_api.h"
#include "bt_av.h"

/*****************************************************************************
**  Type Definitions
*****************************************************************************/
// data type for the MIHC Codec Information Element */
// NOTE: bits_per_sample is needed only for MIHC encoder initialization.
typedef struct {
  uint32_t vendorId;
  uint16_t codecId;    /* Codec ID for MIHC */
  uint8_t sampleRate;  /* Sampling Frequency */
  uint8_t channelMode; /* STEREO/DUAL/MONO */
  btav_a2dp_codec_bits_per_sample_t bits_per_sample;
} tA2DP_MIHC_CIE;

/*****************************************************************************
**  External Function Declarations
*****************************************************************************/
#ifdef __cplusplus
extern "C"
{
#endif

// MIHC Functions

#ifdef __cplusplus
}
#endif

#endif  // A2DP_VENDOR_MIHC_H
