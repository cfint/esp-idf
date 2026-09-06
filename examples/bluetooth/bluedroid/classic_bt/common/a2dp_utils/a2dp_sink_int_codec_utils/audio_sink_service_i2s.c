/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_a2dp_api.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/ringbuf.h"
#include "driver/i2s_std.h"
#include "audio_sink_service.h"

#if defined(CONFIG_EXAMPLE_A2DP_SINK_OUTPUT_EXTERNAL_I2S)

/* log tag */
#define AUDIO_SNK_SRV_I2S_TAG    "SNK_SRV_I2S"

typedef struct {
    i2s_chan_handle_t tx_chan;        /* handle of i2s channel */
    audio_sink_chan_st_t chan_st;     /* i2s channel status */
    TaskHandle_t write_task_handle;   /* handle of writing task */
    RingbufHandle_t ringbuf;          /* handle of ringbuffer */
    SemaphoreHandle_t write_semaphore;/* handle of write semaphore */
    uint16_t ringbuffer_mode;         /* ringbuffer mode */
    uint8_t  cur_bits;                /* current codec decoder PCM width: 16/24/32 */
} audio_sink_srv_i2s_cb_t;

/*******************************
 * STATIC FUNCTION DECLARATIONS
 ******************************/

/* task handler for writing data to i2s */
static void audio_sink_srv_i2s_task_handler(void *arg);

/*******************************
 * STATIC VARIABLE DEFINITIONS
 ******************************/

/* audio sink service for i2s control block */
static audio_sink_srv_i2s_cb_t s_i2s_cb;

/*******************************
 * STATIC FUNCTION DEFINITIONS
 ******************************/

static void audio_sink_srv_i2s_task_handler(void *arg)
{
    uint8_t *data = NULL;
    size_t item_size = 0;
    /**
     * The total length of DMA buffer of I2S is:
     * `dma_frame_num * dma_desc_num * i2s_channel_num * i2s_data_bit_width / 8`.
     * Transmit `dma_frame_num * dma_desc_num` bytes to DMA is trade-off.
     */
    const size_t item_size_upto = 240 * 6;
    size_t bytes_written = 0;

    for (;;) {
        if (pdTRUE == xSemaphoreTake(s_i2s_cb.write_semaphore, portMAX_DELAY)) {
            for (;;) {
                item_size = 0;
                /* receive data from ringbuffer and write it to I2S DMA transmit buffer */
                data = (uint8_t *)xRingbufferReceiveUpTo(s_i2s_cb.ringbuf, &item_size, (TickType_t)pdMS_TO_TICKS(20), item_size_upto);
                if (item_size == 0) {
                    ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "ringbuffer underflowed! mode changed: RINGBUFFER_MODE_PREFETCHING");
                    s_i2s_cb.ringbuffer_mode = RINGBUFFER_MODE_PREFETCHING;
                    break;
                }

                if (s_i2s_cb.chan_st == CHANNEL_STATUS_ENABLED) {
                    i2s_channel_write(s_i2s_cb.tx_chan, data, item_size, &bytes_written, portMAX_DELAY);
                }
                vRingbufferReturnItem(s_i2s_cb.ringbuf, (void *)data);
            }
        }
    }
}

/*******************************
 * EXTERNAL FUNCTION DEFINITIONS
 ******************************/

void audio_sink_srv_open(void)
{
    if (s_i2s_cb.chan_st != CHANNEL_STATUS_IDLE) {
        ESP_LOGW(AUDIO_SNK_SRV_I2S_TAG, "Service already open, skipping initialization");
        return;
    }
    i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    chan_cfg.auto_clear = true;              /* play silence (not stale data) on underrun */
    chan_cfg.dma_desc_num = 6;               /* match old project: 6 x 128 = 768-frame DMA */
    chan_cfg.dma_frame_num = 128;            /* ~8 ms @96k / ~17 ms @48k render bridge */
    i2s_std_config_t std_cfg = {
        .clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(44100),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_32BIT, I2S_SLOT_MODE_STEREO),
        .gpio_cfg = {
            .mclk = I2S_GPIO_UNUSED,
            .bclk = CONFIG_EXAMPLE_I2S_BCK_PIN,
            .ws = CONFIG_EXAMPLE_I2S_LRCK_PIN,
            .dout = CONFIG_EXAMPLE_I2S_DATA_PIN,
            .din = I2S_GPIO_UNUSED,
            .invert_flags = {
                .mclk_inv = false,
                .bclk_inv = false,
                .ws_inv = false,
            },
        },
    };
    /* initialize I2S channel */
    ESP_ERROR_CHECK(i2s_new_channel(&chan_cfg, &s_i2s_cb.tx_chan, NULL));
    ESP_ERROR_CHECK(i2s_channel_init_std_mode(s_i2s_cb.tx_chan, &std_cfg));
    s_i2s_cb.chan_st = CHANNEL_STATUS_OPENED;
}

void audio_sink_srv_close(void)
{
    audio_sink_srv_stop();

    if (s_i2s_cb.write_task_handle) {
        vTaskDelete(s_i2s_cb.write_task_handle);
        s_i2s_cb.write_task_handle = NULL;
    }
    if (s_i2s_cb.ringbuf) {
        vRingbufferDelete(s_i2s_cb.ringbuf);
        s_i2s_cb.ringbuf = NULL;
    }
    if (s_i2s_cb.write_semaphore) {
        vSemaphoreDelete(s_i2s_cb.write_semaphore);
        s_i2s_cb.write_semaphore = NULL;
    }
    if (s_i2s_cb.chan_st == CHANNEL_STATUS_OPENED) {
        ESP_ERROR_CHECK(i2s_del_channel(s_i2s_cb.tx_chan));
        s_i2s_cb.chan_st = CHANNEL_STATUS_IDLE;
    }
    memset(&s_i2s_cb, 0, sizeof(audio_sink_srv_i2s_cb_t));
}

void audio_sink_srv_start(void)
{
    if (s_i2s_cb.chan_st == CHANNEL_STATUS_ENABLED) {
        return;  /* already streaming (e.g. AUDIO_STATE STARTED right after a fresh connect) */
    }
    if (s_i2s_cb.chan_st != CHANNEL_STATUS_OPENED) {
        ESP_LOGE(AUDIO_SNK_SRV_I2S_TAG, "%s, TX channel wrong state: %d", __func__, s_i2s_cb.chan_st);
        return;
    }
    ESP_ERROR_CHECK(i2s_channel_enable(s_i2s_cb.tx_chan));

    ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "ringbuffer data empty! mode changed: RINGBUFFER_MODE_PREFETCHING");
    s_i2s_cb.ringbuffer_mode = RINGBUFFER_MODE_PREFETCHING;
    if ((s_i2s_cb.write_semaphore == NULL) && (s_i2s_cb.write_semaphore = xSemaphoreCreateBinary()) == NULL) {
        ESP_LOGE(AUDIO_SNK_SRV_I2S_TAG, "%s, Semaphore create failed", __func__);
        goto err_sem;
    }
    if ((s_i2s_cb.ringbuf == NULL) &&
        (s_i2s_cb.ringbuf = xRingbufferCreate(RINGBUF_HIGHEST_WATER_LEVEL, RINGBUF_TYPE_BYTEBUF)) == NULL) {
        ESP_LOGE(AUDIO_SNK_SRV_I2S_TAG, "%s, ringbuffer create failed", __func__);
        goto err_rb;
    }
    if (s_i2s_cb.write_task_handle == NULL) {
        /* Pin the I2S render task to core 0 (with the BT controller + host); the
         * heavy A2DP decode owns core 1, so this light task must not land there. */
        if (xTaskCreatePinnedToCore(audio_sink_srv_i2s_task_handler, "BtI2STask", 4 * 1024, NULL,
                        configMAX_PRIORITIES - 3, &s_i2s_cb.write_task_handle, 0) != pdPASS) {
            ESP_LOGE(AUDIO_SNK_SRV_I2S_TAG, "%s, Task create failed", __func__);
            goto err_task;
        }
    }
    s_i2s_cb.chan_st = CHANNEL_STATUS_ENABLED;
    return;

err_task:
    vRingbufferDelete(s_i2s_cb.ringbuf);
    s_i2s_cb.ringbuf = NULL;
err_rb:
    vSemaphoreDelete(s_i2s_cb.write_semaphore);
    s_i2s_cb.write_semaphore = NULL;
err_sem:
    i2s_channel_disable(s_i2s_cb.tx_chan);
}

void audio_sink_srv_stop(void)
{
    if (s_i2s_cb.chan_st == CHANNEL_STATUS_ENABLED) {
        /* Stop I2S output immediately; auto_clear zeros the DMA so no residual plays. */
        i2s_channel_disable(s_i2s_cb.tx_chan);
        s_i2s_cb.chan_st = CHANNEL_STATUS_OPENED;
    }
    /* Clear the audio still buffered so nothing lingers/plays on the next stream.
     * The write task no longer outputs (channel disabled); drain and discard the
     * ring here, then reset the fill state to prefetch fresh audio. */
    if (s_i2s_cb.ringbuf) {
        size_t item_size = 0;
        void *item;
        while ((item = xRingbufferReceiveUpTo(s_i2s_cb.ringbuf, &item_size, 0, RINGBUF_HIGHEST_WATER_LEVEL)) != NULL) {
            vRingbufferReturnItem(s_i2s_cb.ringbuf, item);
        }
    }
    s_i2s_cb.ringbuffer_mode = RINGBUFFER_MODE_PREFETCHING;
    ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "I2S output stopped, buffer cleared");
}

/* Vendor codec IDs (AOSP A2DP) for parsing NON_A2DP raw CIE bytes */
#define A2DP_LDAC_VENDOR_ID     0x0000012DUL
#define A2DP_LDAC_CODEC_ID      0x00AA
#define A2DP_APTX_VENDOR_ID     0x0000004FUL
#define A2DP_APTX_CODEC_ID      0x0001
#define A2DP_APTXHD_VENDOR_ID   0x000000D7UL
#define A2DP_APTXHD_CODEC_ID    0x0024
#define A2DP_APTXLL_VENDOR_ID   0x0000000AUL
#define A2DP_APTXLL_CODEC_ID    0x0002
#define A2DP_OPUS_VENDOR_ID     0x000005F1UL
#define A2DP_OPUS_CODEC_ID      0x1005
#define A2DP_LHDCV5_VENDOR_ID   0x0000053AUL
#define A2DP_LHDCV5_CODEC_ID    0x4C35

void audio_sink_srv_codec_info_update(esp_a2d_mcc_t *mcc)
{
    ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "A2DP audio stream configuration, codec type: %d", mcc->type);

    /* On a codec switch the peer briefly disconnects, which closes/deletes the
     * I2S channel (tx_chan == NULL). The new codec's AUDIO_CFG can arrive before
     * the channel is re-opened, so recreate it here — otherwise the reconfig
     * calls below get a NULL handle and abort. */
    if (s_i2s_cb.tx_chan == NULL) {
        audio_sink_srv_open();
    }
    if (s_i2s_cb.tx_chan == NULL) {
        ESP_LOGE(AUDIO_SNK_SRV_I2S_TAG, "I2S channel unavailable, skipping codec config");
        return;
    }
    audio_sink_srv_stop();

    /* Determine sample rate, decoder output bit depth and channel count for
     * every codec (SBC/AAC + vendor codecs), then configure I2S to match.
     * Mirrors the old bt_audio_sink project's per-codec I2S setup. */
    int sample_rate = 44100;
    int ch_count = 2;
    int bits = 16;              /* decoder PCM width: 16 (SBC/AAC/Opus), 24 (LDAC), 32 (aptX/LHDC) */

    if (mcc->type == ESP_A2D_MCT_SBC) {
        if (mcc->cie.sbc_info.samp_freq & ESP_A2D_SBC_CIE_SF_32K)      sample_rate = 32000;
        else if (mcc->cie.sbc_info.samp_freq & ESP_A2D_SBC_CIE_SF_44K) sample_rate = 44100;
        else if (mcc->cie.sbc_info.samp_freq & ESP_A2D_SBC_CIE_SF_48K) sample_rate = 48000;
        else                                                          sample_rate = 16000;
        if (mcc->cie.sbc_info.ch_mode & ESP_A2D_SBC_CIE_CH_MODE_MONO)  ch_count = 1;
        bits = 16;
    } else if (mcc->type == ESP_A2D_MCT_M24) {
        if (mcc->cie.m24_info.samp_freq2 & ESP_A2D_M24_CIE_SF2_96K)      sample_rate = 96000;
        else if (mcc->cie.m24_info.samp_freq2 & ESP_A2D_M24_CIE_SF2_88K) sample_rate = 88200;
        else if (mcc->cie.m24_info.samp_freq2 & ESP_A2D_M24_CIE_SF2_64K) sample_rate = 64000;
        else if (mcc->cie.m24_info.samp_freq2 & ESP_A2D_M24_CIE_SF2_48K) sample_rate = 48000;
        else if (mcc->cie.m24_info.samp_freq1 & ESP_A2D_M24_CIE_SF1_44K) sample_rate = 44100;
        else if (mcc->cie.m24_info.samp_freq1 & ESP_A2D_M24_CIE_SF1_32K) sample_rate = 32000;
        else if (mcc->cie.m24_info.samp_freq1 & ESP_A2D_M24_CIE_SF1_24K) sample_rate = 24000;
        else if (mcc->cie.m24_info.samp_freq1 & ESP_A2D_M24_CIE_SF1_22K) sample_rate = 22050;
        else if (mcc->cie.m24_info.samp_freq1 & ESP_A2D_M24_CIE_SF1_16K) sample_rate = 16000;
        else                                                            sample_rate = 44100;
        if (mcc->cie.m24_info.ch & ESP_A2D_M24_CIE_CH_1) ch_count = 1;
        bits = 16;
    } else if (mcc->type == ESP_A2D_MCT_NON_A2DP) {
        const uint8_t *raw = (const uint8_t *)&mcc->cie;   /* vendor CIE bytes */
        uint32_t vendor_id = (uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
                             ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 24);
        uint16_t codec_id  = (uint16_t)raw[4] | ((uint16_t)raw[5] << 8);
        if (vendor_id == A2DP_LDAC_VENDOR_ID && codec_id == A2DP_LDAC_CODEC_ID) {
            uint8_t sf = raw[6] & 0x3F;
            if (sf & 0x20)      sample_rate = 44100;
            else if (sf & 0x10) sample_rate = 48000;
            else if (sf & 0x08) sample_rate = 88200;
            else if (sf & 0x04) sample_rate = 96000;
            else if (sf & 0x02) sample_rate = 176400;
            else if (sf & 0x01) sample_rate = 192000;
            if ((raw[7] & 0x07) == 0x04) ch_count = 1;
            bits = 24;      /* LDACBT decoder outputs S24 */
            ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "Vendor codec: LDAC");
        } else if (vendor_id == A2DP_APTX_VENDOR_ID && codec_id == A2DP_APTX_CODEC_ID) {
            if (raw[6] & 0x20)      sample_rate = 44100;
            else if (raw[6] & 0x10) sample_rate = 48000;
            if ((raw[6] & 0x0F) == 0x01) ch_count = 1;
            bits = 32;      /* 24-bit in 32-bit LE containers */
            ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "Vendor codec: aptX");
        } else if (vendor_id == A2DP_APTXHD_VENDOR_ID && codec_id == A2DP_APTXHD_CODEC_ID) {
            if (raw[6] & 0x20)      sample_rate = 44100;
            else if (raw[6] & 0x10) sample_rate = 48000;
            if ((raw[6] & 0x0F) == 0x01) ch_count = 1;
            bits = 32;
            ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "Vendor codec: aptX-HD");
        } else if (vendor_id == A2DP_APTXLL_VENDOR_ID && codec_id == A2DP_APTXLL_CODEC_ID) {
            sample_rate = 48000; bits = 32;
            ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "Vendor codec: aptX-LL");
        } else if (vendor_id == A2DP_OPUS_VENDOR_ID && codec_id == A2DP_OPUS_CODEC_ID) {
            sample_rate = 48000; bits = 16;   /* Opus decoder outputs 48k/16-bit */
            ch_count = (raw[6] == 1) ? 1 : 2;
            ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "Vendor codec: Opus");
        } else if (vendor_id == A2DP_LHDCV5_VENDOR_ID && codec_id == A2DP_LHDCV5_CODEC_ID) {
            uint8_t sf = raw[6] & 0x35;
            if (sf & 0x01)      sample_rate = 192000;
            else if (sf & 0x04) sample_rate = 96000;
            else if (sf & 0x10) sample_rate = 48000;
            else if (sf & 0x20) sample_rate = 44100;
            bits = ((raw[7] & 0x04)) ? 16 : 32;   /* 24-bit source up-packed to 32-bit container */
            ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "Vendor codec: LHDC-v5");
        } else {
            sample_rate = 48000; bits = 32;
            ESP_LOGW(AUDIO_SNK_SRV_I2S_TAG, "Unknown vendor codec vid=0x%08x cid=0x%04x", vendor_id, codec_id);
        }
    }

    /* Old-project model: I2S is ALWAYS 32-bit stereo; only the sample rate
     * changes per codec. The decoder's native PCM (16/24/32-bit) is up-converted
     * to 32-bit in audio_sink_srv_data_output(). Using 32-bit slots (256x MCLK)
     * avoids the 24-bit "sample rate too large" (384x MCLK) failure at 96 kHz. */
    s_i2s_cb.cur_bits = (uint8_t)bits;

    i2s_std_slot_config_t slot_cfg =
        I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_32BIT, I2S_SLOT_MODE_STEREO);
    ESP_ERROR_CHECK(i2s_channel_reconfig_std_slot(s_i2s_cb.tx_chan, &slot_cfg));

    /* High sample rates (LDAC 96k, LHDC 192k) need the Audio PLL; the default
     * I2S clock source cannot synthesize them ("sample rate too large").
     * Try APLL first, fall back to default PLL. Never ESP_ERROR_CHECK here: a
     * rate the hardware cannot produce must not crash the device. */
    i2s_std_clk_config_t clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG((uint32_t)sample_rate);
    clk_cfg.clk_src = I2S_CLK_SRC_APLL;
    clk_cfg.mclk_multiple = I2S_MCLK_MULTIPLE_256;
    esp_err_t clk_err = i2s_channel_reconfig_std_clock(s_i2s_cb.tx_chan, &clk_cfg);
    if (clk_err != ESP_OK) {
        ESP_LOGW(AUDIO_SNK_SRV_I2S_TAG, "APLL clock @%d Hz failed (%s), trying default PLL",
                 sample_rate, esp_err_to_name(clk_err));
        clk_cfg.clk_src = I2S_CLK_SRC_DEFAULT;
        clk_err = i2s_channel_reconfig_std_clock(s_i2s_cb.tx_chan, &clk_cfg);
        if (clk_err != ESP_OK) {
            ESP_LOGE(AUDIO_SNK_SRV_I2S_TAG, "I2S clock @%d Hz unsupported (%s)",
                     sample_rate, esp_err_to_name(clk_err));
        }
    }

    ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG,
             "I2S CONFIG => Fs(LRCK)=%d Hz | decoder=%d-bit -> I2S 32-bit | ch=%d | fmt=Philips | role=MASTER",
             sample_rate, bits, ch_count);
    ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG,
             "I2S PINS   => BCLK=GPIO%d  WS/LRCK=GPIO%d  DOUT=GPIO%d  MCLK=unused",
             CONFIG_EXAMPLE_I2S_BCK_PIN, CONFIG_EXAMPLE_I2S_LRCK_PIN, CONFIG_EXAMPLE_I2S_DATA_PIN);
}

size_t audio_sink_srv_data_output(const uint8_t *data, size_t size)
{
    size_t item_size = 0;
    BaseType_t done = pdFALSE;

    if (s_i2s_cb.ringbuf == NULL) {
        return 0;
    }

    /* Up-convert the decoder's native PCM to 32-bit for the fixed 32-bit I2S
     * slots (matches the old project, which always ran 32-bit). A single fixed
     * static scratch buffer (no per-packet malloc/free) keeps this on internal
     * RAM without heap churn/fragmentation; larger packets are chunked. Called
     * only from the single A2DP sink data task, so the static buffer is safe. */
    static int32_t s_conv[1024];                    /* 4 KB scratch, 1024 samples */
    const size_t chunk_samples = sizeof(s_conv) / sizeof(s_conv[0]);
    int bits = s_i2s_cb.cur_bits ? s_i2s_cb.cur_bits : 16;
    done = pdTRUE;
    if (bits == 32) {
        done = xRingbufferSend(s_i2s_cb.ringbuf, (void *)data, size, (TickType_t)0);
    } else if (bits == 16) {
        const int16_t *in = (const int16_t *)data;
        size_t total = size >> 1, off = 0;
        while (off < total) {
            size_t n = total - off; if (n > chunk_samples) n = chunk_samples;
            for (size_t i = 0; i < n; i++) s_conv[i] = ((int32_t)in[off + i]) << 16;
            if (!xRingbufferSend(s_i2s_cb.ringbuf, s_conv, n * sizeof(int32_t), (TickType_t)0)) { done = pdFALSE; break; }
            off += n;
        }
    } else {                                        /* 24-bit, 3-byte packed LE */
        size_t total = size / 3, off = 0;
        while (off < total) {
            size_t n = total - off; if (n > chunk_samples) n = chunk_samples;
            for (size_t i = 0; i < n; i++) {
                const uint8_t *p = data + (off + i) * 3;
                int32_t s = (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16));
                if (s & 0x00800000) s |= (int32_t)0xFF000000;   /* sign-extend 24 -> 32 */
                s_conv[i] = s << 8;                             /* left-justify in 32-bit slot */
            }
            if (!xRingbufferSend(s_i2s_cb.ringbuf, s_conv, n * sizeof(int32_t), (TickType_t)0)) { done = pdFALSE; break; }
            off += n;
        }
    }

    if (!done) {
        /* Buffer full: the phone is streaming ahead of realtime. Drop ONLY this
         * chunk (graceful, bounded) instead of bulk-draining the whole cushion,
         * which is what caused the audible gaps. The cushion stays deep so the
         * I2S render never starves; only the source's realtime surplus is shed. */
        static uint32_t s_drop_count = 0;
        if ((++s_drop_count & 0x1FF) == 0) {
            ESP_LOGW(AUDIO_SNK_SRV_I2S_TAG, "source ahead of realtime, dropped %u chunks", (unsigned)s_drop_count);
        }
    }

    if (s_i2s_cb.ringbuffer_mode == RINGBUFFER_MODE_PREFETCHING) {
        vRingbufferGetInfo(s_i2s_cb.ringbuf, NULL, NULL, NULL, NULL, &item_size);
        if (item_size >= RINGBUF_PREFETCH_WATER_LEVEL) {
            ESP_LOGI(AUDIO_SNK_SRV_I2S_TAG, "ringbuffer data increased! mode changed: RINGBUFFER_MODE_PROCESSING");
            s_i2s_cb.ringbuffer_mode = RINGBUFFER_MODE_PROCESSING;
            if (pdFALSE == xSemaphoreGive(s_i2s_cb.write_semaphore)) {
                ESP_LOGE(AUDIO_SNK_SRV_I2S_TAG, "semaphore give failed");
            }
        }
    }

    return done ? size : 0;
}

#endif /* defined(CONFIG_EXAMPLE_A2DP_SINK_OUTPUT_EXTERNAL_I2S) */
