| Supported Targets | ESP32 | ESP32-S31 |
| ----------------- | ----- | --------- |

AVRCP-CT-COVER-ART EXAMPLE
======================

This is an example demonstrating the API for implementing Audio/Video Remote Control Profile to get and display cover art image.

## Required components

- [bt_app_core_utils](../common/bt_app_core_utils)
- [bredr_app_common_utils](../common/bredr_app_common_utils)
- [a2dp_sink_common_utils](../common/a2dp_utils/a2dp_sink_common_utils)
- [a2dp_sink_int_codec_utils](../common/a2dp_utils/a2dp_sink_int_codec_utils)
- [a2dp_sink_ext_codec_utils](../common/a2dp_utils/a2dp_sink_ext_codec_utils)
- [avrcp_common_utils](../common/avrcp_utils/avrcp_common_utils)
- [avrcp_metadata_utils](../common/avrcp_utils/avrcp_metadata_utils)
- [avrcp_cover_art_utils](../common/avrcp_utils/avrcp_cover_art_utils)

```
+---------------------------------------------------+---------------------+
|                avrcp_cover_art_utils              |                     |
+---------------------------------------------------+                     |
|                avrcp_metadata_utils               |                     |
+---------------------------------------------------+                     |
|                 avrcp_common_utils                |                     |
+-------------------------+-------------------------+  bt_app_core_utils  |
|a2dp_sink_int_codec_utils|a2dp_sink_ext_codec_utils|                     |
+-------------------------+-------------------------+                     |
|               a2dp_sink_common_utils              |                     |
+---------------------------------------------------+                     |
|               bredr_app_common_utils              |                     |
+---------------------------------------------------+---------------------+
```

Detailed information can be viewed through the [../common/README.md](../common/README.md).

## How to use this example

### Hardware Required

* An ESP32 or ESP32-S31 development board
* A SPI-interfaced LCD
* A USB cable for power supply and programming

### Hardware Connection

The connection between development board and the LCD is as follows:

```
   Development Board                       LCD Screen
      +---------+              +---------------------------------+
      |         |              |                                 |
      |     3V3 +--------------+ VCC   +----------------------+  |
      |         |              |       |                      |  |
      |     GND +--------------+ GND   |                      |  |
      |         |              |       |                      |  |
      |   DATA0 +--------------+ MOSI  |                      |  |
      |         |              |       |                      |  |
      |    PCLK +--------------+ SCK   |                      |  |
      |         |              |       |                      |  |
      |      CS +--------------+ CS    |                      |  |
      |         |              |       |                      |  |
      |     D/C +--------------+ D/C   |                      |  |
      |         |              |       |                      |  |
      |     RST +--------------+ RST   |                      |  |
      |         |              |       |                      |  |
      |BK_LIGHT +--------------+ BCKL  +----------------------+  |
      |         |              |                                 |
      +---------+              +---------------------------------+
```

The GPIO number used by this example can be changed in [avrcp_cover_art_service.c](../common/avrcp_utils/avrcp_cover_art_utils/avrcp_cover_art_service.c), where:

| GPIO number              | LCD pin |
| ------------------------ | ------- |
| EXAMPLE_PIN_NUM_PCLK     | SCK     |
| EXAMPLE_PIN_NUM_CS       | CS      |
| EXAMPLE_PIN_NUM_DC       | DC      |
| EXAMPLE_PIN_NUM_RST      | RST     |
| EXAMPLE_PIN_NUM_DATA0    | MOSI    |
| EXAMPLE_PIN_NUM_BK_LIGHT | BCKL    |

Note that the level used to turn on the LCD backlight may vary: some LCD modules need a low level to turn it on, while others require a high level. You can change the backlight level macro `EXAMPLE_LCD_BK_LIGHT_ON_LEVEL` in [avrcp_cover_art_service.c](../common/avrcp_utils/avrcp_cover_art_utils/avrcp_cover_art_service.c).

### Configure the project

```
idf.py menuconfig
```

* The AVRCP CT Cover Art feature is enabled by default. We can disable it by unselecting the menuconfig option `Component config --> Bluetooth --> Bluedroid Options --> Classic Bluetooth --> AVRCP Features --> AVRCP CT Cover Art`. This example will try to use the AVRCP CT Cover Art feature to get the cover art image, count the image size, and display it if the peer device supports it.
* **Memory Configuration**: To ensure that the A2DP sink stream and the display of AVRCP cover art on the LCD can run simultaneously, the following configurations are required and have been set in `sdkconfig.defaults`:
  * `CONFIG_SPIRAM=y`: Enables external SPI RAM (PSRAM) support. This provides additional memory space needed for buffering audio data during A2DP streaming while simultaneously handling cover art image decoding and display operations. Without this, the application may run out of internal RAM when processing both audio streams and image data.
  * `CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y`: Selects the single large app partition table scheme, which allocates more space for the application binary. This is necessary because the example application includes multiple Bluetooth profiles (A2DP, AVRCP), image decoding libraries, and LCD display drivers, requiring a larger application partition than the default partition table provides.

### Build and Flash

Build the project and flash it to the board, then run monitor tool to view serial output.

```
idf.py -p PORT flash monitor
```

(To exit the serial monitor, type ``Ctrl-]``.)

## Example Output

The output when receiving a cover art image:

```
I (31579) RC_CT: AVRC metadata rsp: attribute id 0x80, 1000526
I (32039) RC_CA_SRV: Cover Art Client final data event, image size: 12315 bytes
I (32119) RC_CA_SRV: JPEG image decoded! Size of the decoded image is: 200px x 200px.
```

And then, the LCD screen will display the cover art image.

## Troubleshooting

For any technical queries, please open an [issue](https://github.com/espressif/esp-idf/issues) on GitHub. We will get back to you soon.

## v5.1.4 移植说明（2026-08-12，DeepSeek-V4-Flash）

本目录从 esp-idf v6.1.0 移植（avrcp_ct_cover_art 例程 + common 组件），
配合 v5.1.4 框架的 AVRCP Cover Art 移植（见 components/bt 的 coverart 改动）。

**已知差异（v5.1.4 适配）**：
- 例程的 A2DP 流部分依赖 v6.1.0 组件架构（esp_driver_i2s/esp_driver_dac），
  v5.1.4 无此组件拆分；如需完整编译请按 v5.1.4 a2dp_sink 例程适配
- cover art 核心逻辑（avrcp_cover_art_utils：JPEG 接收/解码/显示）不依赖
  A2DP 流，可独立使用；显示层需适配实际屏幕（例程为 ST7789 LCD）
- 依赖 esp_jpeg 组件（idf.py add-dependency esp_jpeg 拉取）
- 需要 v5.1.4 框架开启 CONFIG_BT_AVRCP_CT_COVER_ART_ENABLED（默认 y）

## v5.1.4 适配更新（2026-08-12，DeepSeek-V4-Flash）

本例程已适配 esp-idf v5.1.4 并编译通过（`avrcp_ct_cover_art.bin` 868KB，含 A2DP 音频流）。

**音频流**：使用 v5.1.4 原始 a2dp_sink 例程的 I2S 实现
（`driver/i2s_std.h` 新 I2S API，v5.1.4 driver 组件自带），
不再依赖 v6.1.0 的 a2dp_sink_int/ext_codec_utils 组件。
- bt_app_core_utils 内置 ringbuffer + I2S 任务（write_ringbuf/bt_i2s_task_start_up）
- bt_app_av.c 内置 I2S 驱动初始化（固定引脚 26/22/25，可在
  Kconfig.projbuild 的 EXAMPLE_I2S_BCK/LRCK/DATA_PIN 调整）
- I2S 引脚 Kconfig 已补充（v5.1.4 原始 a2dp_sink 默认值）

**适配内容**：
- idf_component.yml 移除 a2dp_sink_int/ext_codec_utils 依赖
- 移除 v6.1.0 特有 API（v5.1.4 无）：
  - bredr_app_common_utils：esp_bt_dev_cb_event_t（device 回调）、
    esp_bluedroid_init_with_cfg（改用 esp_bluedroid_init）、
    auth_cmpl.lk_type、ESP_BT_GAP_ENC_CHG_EVT、mode_chg.interval
  - a2dp_sink_common_utils：ESP_A2D_SEP_REG_STATE_EVT
  - avrcp_common_utils：ESP_AVRC_CT/TG_PROF_STATE_EVT
  - avrcp_metadata_service：补 #include <string.h>
  - bt_app_av.h：移除 esp_a2d_audio_data_cb（v6.1.0 类型）
  - main.c：esp_bt_gap_set_device_name → esp_bt_dev_set_device_name
  - A2DP 事件：ESP_A2D_AUDIO_CFG_EVT 用 a2d->audio_cfg.mcc.type（v5.1.4 结构）
- avrcp_cover_art_utils CMakeLists：加 driver 依赖（v5.1.4 SPI 在 driver 组件）
- bt_app_core_utils CMakeLists：加 esp_ringbuf/driver 依赖（v5.1.4 组件归属）

**配套框架修复**（components/bt）：
- bte_init.c 补 OBEX_Init/GOEPC_Init（v6.1.0 初始化接线）
- GOEP/OBEX 采用 v5.5.2 验证版
- bta_av_rc_disc：SDP 查询补 ATTR_ID_ADDITION_PROTO_DESC_LISTS + num_attr 4
- btc_av.c：BTA_AV_CA_STATUS/DATA_EVT 路由到 btc_rc_handler
- obex_int.h：宏名 OBEX_TL_L2CAP_BT_HDR_OFFSET_MIN → MIN_OFFSET

**依赖**：esp_jpeg 组件（idf.py add-dependency 自动拉取）
