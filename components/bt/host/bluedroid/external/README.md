# external of bluedroid

这里是Bluedroid存放第三方Codecs的地方，每种Codecs都要在`components/bt/CMakeLists.txt`中包含头文件路径，并包含关键源文件；此外每种Codecs都有对应的`integration`文件，包括a2dp_vendor_xxx.c/.h，它们都分别位于`components/bt/host/bluedroid/stack/a2dp`和`components/bt/host/bluedroid/stack/include/stack`，并且源文件也添加到了`components/bt/CMakeLists.txt`里。它们都受各自的宏定义条件编译。

---

## 关于a2dp_vendor

a2dp_vendor是cfint从AOSP移植而来的一种统一接口，可以通过各个解码器的`integration`文件接入解码器，其中`components/bt/host/bluedroid/stack/a2dp`和`components/bt/host/bluedroid/stack/include/stack`就是存放`a2dp_vendor`和各个解码器`integration`文件的地方。

---

## 关于PSRAM

SBC和aptX可以不需要PSRAM，但是AAC、LDAC、LHDC V5必须要有PSRAM才能正常运行。

---

## Configuration

Key sdkconfig settings for optimal performance:
```
# Flash and Memory
CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y
CONFIG_ESPTOOLPY_FLASHFREQ_80M=y
CONFIG_SPIRAM_SPEED_80M=y

# CPU Performance
CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_240=y

# Bluetooth
CONFIG_BTDM_CTRL_MODE_BTDM=y
CONFIG_BT_A2DP_ENABLE=y
CONFIG_BT_A2DP_LDAC_DECODER=y
CONFIG_BT_A2DP_APTX_DECODER=y
CONFIG_BT_A2DP_AAC_DECODER=y
CONFIG_BT_A2DP_LHDCV5_DECODER=y
```

---

## Troubleshooting

### LDAC / LHDC V5 Low/Medium Quality causes buffer overflow

Edit `components/bt/host/bluedroid/btc/profile/std/a2dp/btc_a2dp_sink.c`:

```
// Change from:
#define BT_A2DP_SINK_BUF_SIZE   8192
// To:
#define BT_A2DP_SINK_BUF_SIZE   32768
```

> 实际测试设置16384会比较好，如果设置成32768，那么编译会提示IRAM超容量报错，则需要修改代码改成buffer分配到PSRAM。

Then rebuild with `idf.py fullclean && idf.py build`.

### AAC / LHDC V5 decoder fails to initialize

Ensure PSRAM is enabled and running at 80MHz. Check that your ESP32 board has PSRAM (WROVER, not WROOM).

### Bluetooth pairing issues on Linux

Clear the Bluetooth cache:

```
sudo rm -rf /var/lib/bluetooth/<adapter-mac>/cache/<device-mac>
Then re-pair the device.
```

### Where is LHDC V5 ?

已知 [O2C14](https://github.com/O2C14) 和 [O11111(anonymix007)](https://github.com/anonymix007) 是早期逆向LHDC的开发者，不过它们目前并没有开源；目前唯一彻底开源LHDC V5解码器的开发者是 [WillyBilly06](https://github.com/WillyBilly06)，它是基于手机的.so动态库完成了逆向。

### Audio stutters at LDAC 96 kHz

- Confirm that CONFIG_FREERTOS_HZ=1000 is set.
- Reduce BLE meter update rate if needed.
- Check that the source device is not forcing an unstable radio condition.
- Keep the ESP32 close to the source device during testing.

---

## Credits

This project builds upon the excellent work of the open-source community:

### ESP-IDF with Codec Interface

| Project | Tree | Author | Description |
|---------|------|--------|-------------|
| [esp32-a2dp-sink](https://github.com/cfint/esp32-a2dp-sink) | v5.1 | cfint | Example of A2DP sink with codecs |
| [esp-idf](https://github.com/cfint/esp-idf) | v5.1.4-a2dp-codecs | cfint | ESP-IDF fork with codec support |
| [esp32-a2dp-sink-with-LDAC-APTX-AAC](https://github.com/WillyBilly06/esp32-a2dp-sink-with-LDAC-APTX-AAC) | main | cfint/WillyBilly06 | ESP-IDF V5.1.4 fork with codec support and example |
| [ESP32-A2DP-SINK-WITH-CODECS-UPDATED ](https://github.com/WillyBilly06/ESP32-A2DP-SINK-WITH-CODECS-UPDATED/tree/main) | main | cfint/WillyBilly06 | ESP-IDF V5.5.2 fork with codec support and internal-RAM operation and example. No PSRAM is required |
| [ESP32-A2DP-SINK-WITH-CODECS-UPDATED ](https://github.com/WillyBilly06/ESP32-A2DP-SINK-WITH-CODECS-UPDATED/tree/PSRAM-only) | PSRAM-only | cfint/WillyBilly06 | ESP-IDF V5.5.2 fork with codec support and PSRAM operation and example. PSRAM is required |
| [ESP32-S31-A2DP-Codecs](https://github.com/WillyBilly06/ESP32-S31-A2DP-Codecs) | main | WillyBilly06 | ESP-IDF V6.1.0 fork with codec support and example |

### Library with Codec Config and I2S Config

| Project | Tree | Author | Description |
|---------|------|--------|-------------|
| [ESP32-A2DP](https://github.com/cfint/ESP32-A2DP/tree/v5.1-a2dp_codecs) | v5.1-a2dp_codecs | cfint/pschatzmann | A2DP library with codec config |
| [arduino-audio-tools](https://github.com/cfint/arduino-audio-tools/tree/v5.1-a2dp_codecs) | v5.1-a2dp_codecs | cfint/pschatzmann | Audio Processing with I2S config |

### A2DP Audio Codecs

| Project | Tree | Author | Description | Usage Status |
|---------|------|--------|-------------|--------------|
| [opus](https://github.com/xiph/opus) | main | xiph | Opus Decoder | Used |
| [liblc3](https://github.com/cfint/liblc3) | esp32 | cfint | LC3 Decoder (LE Audio)| Used |
| [libfreeaptx](https://github.com/cfint/libfreeaptx-esp) | master | cfint | aptX decoder for ESP32 | Used |
| [arduino-fdk-aac](https://github.com/cfint/arduino-fdk-aac) | idf_component | cfint | AAC decoder | Used |
| [libldacdec](https://github.com/anonymix007/libldacdec) | master | anonymix007 | LDAC Decoder, not very well | Unused |
| [libldac-dec](https://github.com/cfint/libldac-dec) | esp32 | O2C14/cfint | LDAC Decoder, works well | Used |
| [liblhdcv5dec](https://github.com/sprlightning/liblhdcv5dec) | main | sprlightning | LHDC V5 Decoder, no decoder core | Unused |
| [LHDC-V5-Decoder](https://github.com/WillyBilly06/LHDC-V5-Decoder) | main | WillyBilly06 | LHDC V5 Decoder, works well | Used |
