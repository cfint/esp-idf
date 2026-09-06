# v5.1.4 适配：ringbuf 在 esp_ringbuf 组件（v6.1.0 在 freertos），I2S 在 driver 组件
idf_component_register(SRCS "bt_app_core_utils.c"
                    PRIV_REQUIRES bt esp_ringbuf driver
                    INCLUDE_DIRS ".")
