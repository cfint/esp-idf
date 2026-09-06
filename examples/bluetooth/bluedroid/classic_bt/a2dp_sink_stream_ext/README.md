# A2DP Sink Stream EXT (多 A2DP Audio Codec) Example

基于 v5.1.4 原始 a2dp_sink 例程增强，支持**多种 A2DP 音频 Codec**（不仅 SBC）。

本框架（esp-idf v5.1.4，cfint/sprlightning 多 codec 分支）的蓝牙组件移植了
AOSP 的多 codec 解码框架，`esp_a2d_sink_init()` 自动注册所有启用的 codec SEP，
解码后 PCM 经 `esp_a2d_sink_register_data_callback()` 回调输出。

## 支持的 Codec

| Codec | sdkconfig 开关 | 说明 |
|-------|---------------|------|
| SBC | `CONFIG_BT_A2DP_SBC_DECODER` | 默认 |
| AAC (MPEG-2/4) | `CONFIG_BT_A2DP_AAC_DECODER` | |
| aptX / aptX-HD / aptX-LL | `CONFIG_BT_A2DP_APTX_DECODER` | |
| LDAC | `CONFIG_BT_A2DP_LDAC_DECODER` | 最高 96kHz/32bit |
| LHDC V5 | `CONFIG_BT_A2DP_LHDCV5_DECODER` | 最高 96kHz/32bit |
| OPUS | `CONFIG_BT_A2DP_OPUS_DECODER` | |
| LC3 Plus | `CONFIG_BT_A2DP_LC3PLUS_DECODER` | |

> 可在 menuconfig 中按需启用/禁用各 codec（`Component config → Bluetooth → Bluedroid Options → A2DP`）。

## 与原始 a2dp_sink 的差异

1. **多 codec 解析**：`main/codec_config/`（移植自 cfint 多 codec 项目）解析
   `ESP_A2D_AUDIO_CFG_EVT` 的 `mcc`，支持任意 codec 的采样率/位深/声道，
   并驱动 I2S 输出（含 32-bit 采样率，如 LDAC 96kHz/32bit）。
   原始例程仅支持 SBC 16-bit。
2. **16MB flash 分区**：多 codec 固件较大（~1.97MB），使用
   `partitions.csv`（16MB 自定义分区，与 cfint 多 codec 项目一致）。
3. **I2S 引脚**：默认 26/22/25（BCK/LRCK/DATA），可在 menuconfig 调整。

## 硬件连接

| ESP pin | I2S signal |
|---------|-----------|
| GPIO26  | BCK |
| GPIO22  | LRCK |
| GPIO25  | DATA |

（外部 I2S DAC，如 PCM5102）

## 编译与烧录

```bash
idf.py set-target esp32
idf.py build
idf.py -p PORT flash
```

## 验证

连接手机蓝牙播放时，串口日志显示实际协商的 codec：
```
A2DP audio stream configuration, codec type: 255   (NON_A2DP = vendor codec)
Codec: 5, sample rate: 96000, bit depth: 32, channels: 2   (LDAC 96k/32bit)
```

## 文件结构

```
a2dp_sink_stream_ext/
├── partitions.csv          # 16MB 自定义分区（多 codec 大固件）
├── main/
│   ├── bt_app_av.c/h      # A2DP 事件处理（含多 codec I2S 配置）
│   ├── bt_app_core.c/h    # 应用任务 + I2S 输出
│   ├── main.c
│   ├── codec_config/      # 多 codec mcc 解析（移植自 cfint 多 codec 项目）
│   └── Kconfig.projbuild
└── sdkconfig.defaults     # 启用全部 codec + 16MB 分区
```
