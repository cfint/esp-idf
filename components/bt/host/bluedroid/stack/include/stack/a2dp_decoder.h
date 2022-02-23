/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef A2DP_DECODER_H
#define A2DP_DECODER_H

/*****************************************************************************
**  Type Definitions
*****************************************************************************/
struct __attribute__ ((packed)) media_packet_header {
    uint8_t cc:4;
    uint8_t x:1;
    uint8_t p:1;
    uint8_t v:2;

    uint8_t pt:7;
    uint8_t marker:1;

    uint16_t seq;
    uint32_t timestamp;

    uint32_t ssrc;
    uint32_t csrc[0];
};

#endif // A2DP_DECODER_H
