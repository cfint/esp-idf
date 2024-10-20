/*
 * SPDX-FileCopyrightText: 2016 The Android Open Source Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include "common/bt_trace.h"
#include "libAACdec/aacdecoder_lib.h"
#include "stack/a2dp_aac.h"
#include "stack/a2dp_aac_decoder.h"
#include "stack/a2dp_decoder.h"
#include "osi/allocator.h"
#include "osi/future.h"

#define DECODE_BUF_LEN (8 * 1024)

typedef struct {
  HANDLE_AACDECODER aac_handle;
  bool has_aac_handle;
  INT_PCM* output_buffer;
  decoded_data_callback_t decode_callback;
} tA2DP_AAC_DECODER_CB;

static tA2DP_AAC_DECODER_CB a2dp_aac_decoder_cb;


bool a2dp_aac_decoder_init(decoded_data_callback_t decode_callback) {
  a2dp_aac_decoder_cleanup();

  a2dp_aac_decoder_cb.aac_handle =
      aacDecoder_Open(TT_MP4_LATM_MCP1, 1 /* nrOfLayers */);
  if (a2dp_aac_decoder_cb.aac_handle == NULL) {
    LOG_ERROR("%s: couldn't initialize aac decoder", __func__);
    a2dp_aac_decoder_cb.has_aac_handle = false;    
    return false;
  }

  a2dp_aac_decoder_cb.output_buffer = (INT_PCM*) FDKcalloc(DECODE_BUF_LEN,
                                                           sizeof(INT_PCM));
  assert(a2dp_aac_decoder_cb.output_buffer != NULL);
  if (a2dp_aac_decoder_cb.output_buffer == NULL){
    LOG_ERROR("%s: failed to alloc output_buffer");
    return false;
  } 

  a2dp_aac_decoder_cb.has_aac_handle = true;
  a2dp_aac_decoder_cb.decode_callback = decode_callback;
  return true;
}

void a2dp_aac_decoder_cleanup(void) {
  if (a2dp_aac_decoder_cb.has_aac_handle)
    aacDecoder_Close(a2dp_aac_decoder_cb.aac_handle);

  if (a2dp_aac_decoder_cb.output_buffer) {
    FDKfree(a2dp_aac_decoder_cb.output_buffer);
    a2dp_aac_decoder_cb.output_buffer = NULL;
  }
  memset(&a2dp_aac_decoder_cb, 0, sizeof(a2dp_aac_decoder_cb));
}

bool a2dp_aac_decoder_reset(void) {
  return true;
}

ssize_t a2dp_aac_decoder_decode_packet_header(BT_HDR* p_buf) {
  size_t header_len = sizeof(struct media_packet_header);
  p_buf->offset += header_len;
  p_buf->len -= header_len;

  return 0;
}

bool a2dp_aac_decoder_decode_packet(BT_HDR* p_buf, unsigned char* buf,
                                    size_t buf_len)
{
  UCHAR* pBuffer = (UCHAR*)(p_buf->data + p_buf->offset);
  UINT bufferSize = p_buf->len;
  UINT bytesValid = p_buf->len;

  if (a2dp_aac_decoder_cb.aac_handle == NULL) {
    LOG_ERROR("%s: decoder handle not initialized", __func__);
    return false;
  }

  while (bytesValid > 0) {
    AAC_DECODER_ERROR err = aacDecoder_Fill(a2dp_aac_decoder_cb.aac_handle,
                                            &pBuffer, &bufferSize, &bytesValid);
    if (err != AAC_DEC_OK) {
      LOG_ERROR("%s: aacDecoder_Fill failed: 0x%x", __func__,
                (unsigned int)(err));
      return false;
    }

    while (true) {
      err = aacDecoder_DecodeFrame(a2dp_aac_decoder_cb.aac_handle,
                                   (INT_PCM*)a2dp_aac_decoder_cb.output_buffer,
                                   DECODE_BUF_LEN,
                                   0 /* flags */);

      if (err == AAC_DEC_NOT_ENOUGH_BITS) {
        break;
      }
      if (err != AAC_DEC_OK) {
        LOG_ERROR("%s: aacDecoder_DecodeFrame failed: 0x%x", __func__,
                  (int)(err));
        break;
      }

      CStreamInfo* info =
          aacDecoder_GetStreamInfo(a2dp_aac_decoder_cb.aac_handle);
      if (!info || info->sampleRate <= 0) {
        LOG_ERROR("%s: Invalid stream info", __func__);
        break;
      }

      size_t frame_len = info->frameSize * info->numChannels * sizeof(INT_PCM);
      a2dp_aac_decoder_cb.decode_callback(
                                    (uint8_t*)a2dp_aac_decoder_cb.output_buffer,
                                    frame_len);
    }
  }

  return true;
}

void a2dp_aac_decoder_configure(const uint8_t* p_codec_info) {
  tA2DP_AAC_CIE cie;
  tA2D_STATUS status;
  
  status = A2DP_ParseInfoAac(&cie, p_codec_info, FALSE);
  if (status != A2D_SUCCESS) {
    LOG_ERROR("%s: failed to parse codec info", __func__);
    return;
  }

  int res;

  int channels = 2;
  switch (cie.channelMode) {
    case A2DP_AAC_CHANNEL_MODE_MONO:
      channels = 1;
      break;
    case A2DP_AAC_CHANNEL_MODE_STEREO:
      channels = 2;
      break;
    default:
      LOG_ERROR("%s: Invalid channel mode %u", __func__, cie.channelMode);
      return;
  }

  res = aacDecoder_SetParam(a2dp_aac_decoder_cb.aac_handle,
                            AAC_PCM_MIN_OUTPUT_CHANNELS, channels);
  if (res != AAC_DEC_OK) {
    LOG_ERROR("Couldn't set output channels: 0x%04X", res);
  }

  res = aacDecoder_SetParam(a2dp_aac_decoder_cb.aac_handle,
                            AAC_PCM_MAX_OUTPUT_CHANNELS, channels);
  if (res != AAC_DEC_OK) {
    LOG_ERROR("Couldn't set output channels: 0x%04X", res);
  }
}
