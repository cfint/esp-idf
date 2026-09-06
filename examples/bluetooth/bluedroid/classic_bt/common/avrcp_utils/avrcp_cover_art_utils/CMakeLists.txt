# v5.1.4 适配：esp_driver_i2s 等为 v6.1.0 组件拆分，v5.1.4 的 SPI 在 driver 组件
idf_component_register(SRCS "avrcp_cover_art_utils.c"
                            "avrcp_cover_art_service.c"
                    PRIV_REQUIRES bt esp_lcd driver avrcp_common_utils
                    INCLUDE_DIRS "." "../include")
