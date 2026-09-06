/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_bt_device.h"
#include "esp_gap_bt_api.h"
#include "esp_avrc_api.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "bt_app_core_utils.h"
#include "bt_app_av.h"
#include "driver/i2s_std.h"

/* v5.1.4 适配：A2DP 音频输出（原始 a2dp_sink 实现） */
static uint32_t s_pkt_cnt = 0;               /* count for audio packet */
#ifndef CONFIG_EXAMPLE_A2DP_SINK_OUTPUT_INTERNAL_DAC
i2s_chan_handle_t tx_chan = NULL;            /* I2S TX channel，供 bt_app_core_utils 使用 */
#endif
#include "avrcp_utils_tags.h"
#include "avrcp_common_utils.h"
#include "avrcp_metadata_service.h"
#include "avrcp_metadata_utils.h"
#include "a2dp_utils_tags.h"
#include "avrcp_cover_art_service.h"
#include "avrcp_cover_art_utils.h"

/********************************
 * STATIC FUNCTION DEFINITIONS
 *******************************/

static void bt_app_avrc_ct_evt_hdl(uint16_t event, void *param)
{
    ESP_LOGD(BT_RC_CT_TAG, "%s event: %d", __func__, event);

    esp_avrc_ct_cb_param_t *rc = (esp_avrc_ct_cb_param_t *)(param);

    switch (event) {
    case ESP_AVRC_CT_PASSTHROUGH_RSP_EVT: {
        bt_avrc_common_ct_evt_def_hdl(event, param);
        break;
    }
    case ESP_AVRC_CT_CONNECTION_STATE_EVT: {
        bt_avrc_md_ct_evt_hdl(event, param);
        bt_avrc_ca_ct_evt_hdl(event, param);
        if (rc->conn_stat.connected) {
            /* get remote supported event_ids of peer AVRCP Target */
            bt_avrc_common_ct_get_peer_rn_cap();
        } else {
            /* clear peer notification capability record */
            bt_avrc_common_ct_set_peer_rn_cap(0);
        }
        break;
    }
    case ESP_AVRC_CT_CHANGE_NOTIFY_EVT: {
        bt_avrc_md_ct_evt_hdl(event, param);
        bt_avrc_ca_ct_evt_hdl(event, param);
        bt_avrc_common_ct_notify_evt_handler(rc->change_ntf.event_id, &rc->change_ntf.event_parameter);
        break;
    }
    case ESP_AVRC_CT_GET_RN_CAPABILITIES_RSP_EVT: {
        /* set peer notification capability record */
        bt_avrc_common_ct_set_peer_rn_cap(rc->get_rn_caps_rsp.evt_set.bits);
        bt_avrc_common_ct_rn_track_changed();
        bt_avrc_common_ct_rn_play_status_changed();
        bt_avrc_common_ct_rn_play_pos_changed();

        bt_avrc_md_ct_evt_hdl(event, param);
        bt_avrc_ca_ct_evt_hdl(event, param);
        break;
    }
    case ESP_AVRC_CT_METADATA_RSP_EVT: {
        if (rc->meta_rsp.attr_id == ESP_AVRC_MD_ATTR_COVER_ART) {
            bt_avrc_ca_ct_evt_hdl(event, param);
        } else {
            bt_avrc_md_ct_evt_hdl(event, param);
        }
        break;
    }
    case ESP_AVRC_CT_REMOTE_FEATURES_EVT: {
        bt_avrc_ca_ct_evt_hdl(event, param);
        break;
    }
    case ESP_AVRC_CT_COVER_ART_STATE_EVT:
    case ESP_AVRC_CT_COVER_ART_DATA_EVT: {
        bt_avrc_ca_ct_evt_hdl(event, param);
        break;
    }
    default:
        ESP_LOGE(BT_RC_CT_TAG, "Invalid AVRC event: %d", event);
        break;
    }
}

/********************************
 * EXTERNAL FUNCTION DEFINITIONS
 *******************************/

static void bt_av_hdl_a2d_evt(uint16_t event, void *p_param);
static void bt_i2s_driver_install(void);
static void bt_i2s_driver_uninstall(void);

/* v5.1.4 适配：A2DP 事件统一走原始 handler（含 I2S 启停） */
void bt_app_a2d_cb(esp_a2d_cb_event_t event, esp_a2d_cb_param_t *param)
{
    bt_app_work_dispatch(bt_av_hdl_a2d_evt, event, param, sizeof(esp_a2d_cb_param_t), NULL, NULL);
}

#if CONFIG_EXAMPLE_A2DP_SINK_STREAM_ENABLE
/* v5.1.4 适配：音频数据直接用 v5.1.4 原始 a2dp_sink 的 write_ringbuf 输出到 I2S */
void bt_app_a2d_data_cb(const uint8_t *data, uint32_t len)
{
    write_ringbuf(data, len);
    /* log the number every 1000 packets */
    if (++s_pkt_cnt % 1000 == 0) {
        ESP_LOGD(BT_AV_TAG, "Audio packet count: %"PRIu32, s_pkt_cnt);
    }
}

/* v5.1.4 适配：I2S 驱动初始化（原始 a2dp_sink 实现，固定引脚） */
void bt_i2s_driver_install(void)
{
    i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    chan_cfg.auto_clear = true;
    i2s_std_config_t std_cfg = {
        .clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(44100),
        .slot_cfg = I2S_STD_MSB_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_STEREO),
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
    /* enable I2S */
    ESP_ERROR_CHECK(i2s_new_channel(&chan_cfg, &tx_chan, NULL));
    ESP_ERROR_CHECK(i2s_channel_init_std_mode(tx_chan, &std_cfg));
    ESP_ERROR_CHECK(i2s_channel_enable(tx_chan));
}

void bt_i2s_driver_uninstall(void)
{
    ESP_ERROR_CHECK(i2s_channel_disable(tx_chan));
    ESP_ERROR_CHECK(i2s_del_channel(tx_chan));
    tx_chan = NULL;
}

/* v5.1.4 适配：A2DP 事件处理器（原始 a2dp_sink 实现，含 I2S 启停） */
static void bt_av_hdl_a2d_evt(uint16_t event, void *p_param)
{
    ESP_LOGD(BT_AV_TAG, "%s event: %d", __func__, event);

    esp_a2d_cb_param_t *a2d = NULL;

    switch (event) {
    /* when connection state changed, this event comes */
    case ESP_A2D_CONNECTION_STATE_EVT: {
        a2d = (esp_a2d_cb_param_t *)(p_param);
        uint8_t *bda = a2d->conn_stat.remote_bda;
        ESP_LOGI(BT_AV_TAG, "A2DP connection state: %s, [%02x:%02x:%02x:%02x:%02x:%02x]",
            "Unknown", bda[0], bda[1], bda[2], bda[3], bda[4], bda[5]);
        if (a2d->conn_stat.state == ESP_A2D_CONNECTION_STATE_DISCONNECTED) {
            esp_bt_gap_set_scan_mode(ESP_BT_CONNECTABLE, ESP_BT_GENERAL_DISCOVERABLE);
            bt_i2s_driver_uninstall();
            bt_i2s_task_shut_down();
        } else if (a2d->conn_stat.state == ESP_A2D_CONNECTION_STATE_CONNECTED){
            esp_bt_gap_set_scan_mode(ESP_BT_NON_CONNECTABLE, ESP_BT_NON_DISCOVERABLE);
            bt_i2s_task_start_up();
        } else if (a2d->conn_stat.state == ESP_A2D_CONNECTION_STATE_CONNECTING) {
            bt_i2s_driver_install();
        }
        break;
    }
    /* when audio stream transmission state changed, this event comes */
    case ESP_A2D_AUDIO_STATE_EVT: {
        a2d = (esp_a2d_cb_param_t *)(p_param);
        ESP_LOGI(BT_AV_TAG, "A2DP audio state: %d", a2d->audio_stat.state);
        break;
    }
    /* when audio codec is configured, this event comes */
    case ESP_A2D_AUDIO_CFG_EVT: {
        a2d = (esp_a2d_cb_param_t *)(p_param);
        ESP_LOGI(BT_AV_TAG, "A2DP audio stream configuration, codec type: %d", a2d->audio_cfg.mcc.type);
        break;
    }
    default:
        ESP_LOGE(BT_AV_TAG, "%s unhandled event: %d", __func__, event);
        break;
    }
}
#endif

void bt_app_rc_ct_cb(esp_avrc_ct_cb_event_t event, esp_avrc_ct_cb_param_t *param)
{
    switch (event) {
    case ESP_AVRC_CT_METADATA_RSP_EVT: {
        bt_app_work_dispatch(bt_app_avrc_ct_evt_hdl, event, param, sizeof(esp_avrc_ct_cb_param_t),
                             bt_avrc_common_copy_metadata, bt_avrc_common_free_metadata);
        break;
    }
    case ESP_AVRC_CT_COVER_ART_DATA_EVT: {
        /* we must handle ESP_AVRC_CT_COVER_ART_DATA_EVT in avrcp controller callback, */
        /* copy image data to other buff before return if need */
        if (param->cover_art_data.status == ESP_BT_STATUS_SUCCESS) {
            avrc_cover_art_srv_save_image_data(param->cover_art_data.p_data, param->cover_art_data.data_len);
        } else {
            ESP_LOGE(BT_RC_CT_TAG, "Cover Art Client get operation failed");
            break;
        }
        bt_app_work_dispatch(bt_app_avrc_ct_evt_hdl, event, param, sizeof(esp_avrc_ct_cb_param_t), NULL, NULL);
        break;
    }
    case ESP_AVRC_CT_CONNECTION_STATE_EVT:
    case ESP_AVRC_CT_PASSTHROUGH_RSP_EVT:
    case ESP_AVRC_CT_CHANGE_NOTIFY_EVT:
    case ESP_AVRC_CT_REMOTE_FEATURES_EVT:
    case ESP_AVRC_CT_GET_RN_CAPABILITIES_RSP_EVT:
    case ESP_AVRC_CT_COVER_ART_STATE_EVT:
        bt_app_work_dispatch(bt_app_avrc_ct_evt_hdl, event, param, sizeof(esp_avrc_ct_cb_param_t), NULL, NULL);
        break;
    default:
        ESP_LOGE(BT_RC_CT_TAG, "Invalid AVRC event: %d", event);
        break;
    }
}

void bt_app_rc_tg_cb(esp_avrc_tg_cb_event_t event, esp_avrc_tg_cb_param_t *param)
{
    switch (event) {
    case ESP_AVRC_TG_CONNECTION_STATE_EVT:
    case ESP_AVRC_TG_REMOTE_FEATURES_EVT:
    case ESP_AVRC_TG_PASSTHROUGH_CMD_EVT:
    case ESP_AVRC_TG_SET_ABSOLUTE_VOLUME_CMD_EVT:
    case ESP_AVRC_TG_REGISTER_NOTIFICATION_EVT:
    case ESP_AVRC_TG_SET_PLAYER_APP_VALUE_EVT:
        bt_app_work_dispatch(bt_avrc_common_tg_evt_def_hdl, event, param, sizeof(esp_avrc_tg_cb_param_t), NULL, NULL);
        break;
    default:
        ESP_LOGE(BT_RC_TG_TAG, "Invalid AVRC event: %d", event);
        break;
    }
}
