idf_component_register(SRCS "bt_app_av.c"
                            "bt_app_core.c"
                            "main.c"
                            "codec_config/codec_config.c"
                    INCLUDE_DIRS "." "codec_config"
                    PRIV_REQUIRES bt driver esp_ringbuf nvs_flash)
