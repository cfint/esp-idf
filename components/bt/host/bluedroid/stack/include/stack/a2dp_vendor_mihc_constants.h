#ifndef A2DP_VENDOR_MIHC_CONSTANTS_H
#define A2DP_VENDOR_MIHC_CONSTANTS_H

// MIHC codec specific settings
#define A2DP_MIHC_CODEC_LEN 13  // perhap
// [Octet 0-3] Vendor ID
#define A2DP_MIHC_VENDOR_ID              0x0000038F
// [Octet 4-5] Vendor Specific Codec ID
#define A2DP_MIHC_CODEC_ID               0x4D31
// [Octet 6] Version
#define A2DP_MIHC_VERSION_1              1
// [Octet 7] Sampling Frequency
#define A2DP_MIHC_SAMPLING_FREQ_RTA_0x80 0x10  // perhap
#define A2DP_MIHC_SAMPLING_FREQ_16000    0x40
#define A2DP_MIHC_SAMPLING_FREQ_24000    0x20
#define A2DP_MIHC_SAMPLING_FREQ_RTA_0x10 0x10  // perhap
#define A2DP_MIHC_SAMPLING_FREQ_44100    0x08
#define A2DP_MIHC_SAMPLING_FREQ_48000    0x04
#define A2DP_MIHC_SAMPLING_FREQ_88200    0x02  // perhap
#define A2DP_MIHC_SAMPLING_FREQ_96000    0x01  // perhap
// [Octet 8], [Bits 0] Is CBR
#define A2DP_MIHC_CBR_ON                 0x01
// [Octet 8], [Bits 2-3] Frame Length
#define A2DP_MIHC_DEFAULT_FRLEN          0x04
#define A2DP_MIHC_5MS_FRLEN              0x08
// [Octet 8], [Bits 5-7] Bit dipth
#define A2DP_MIHC_BIT_FMT_32             0x20
#define A2DP_MIHC_BIT_FMT_24             0x40
#define A2DP_MIHC_BIT_FMT_16             0x80
// [Octet 9], [Bits 0-1] Channle Mode
#define A2DP_MIHC_CHANNEL_MODE_STEREO    0x01
#define A2DP_MIHC_CHANNEL_MODE_MONO      0x02
// [Octet 9], [Bits 4-7] Audio Mode
// [Octet 10] Bit Rate
#define A2DP_MIHC_MIN_BIT_RATE_32K       0x10
#define A2DP_MIHC_MIN_BIT_RATE_64K       0x20
#define A2DP_MIHC_MIN_BIT_RATE_96K       0x40
#define A2DP_MIHC_MIN_BIT_RATE_128K      0x80
#endif