# v5.1.4 适配：A2DP 音频流使用 v5.1.4 原始 a2dp_sink 实现（bt_app_av.c 内），
# 不依赖 v6.1.0 的 a2dp_sink_int/ext_codec_utils 组件。
idf_component_register(SRCS "bt_app_av.c"
                            "main.c"
                    PRIV_REQUIRES bt bt_app_core_utils bredr_app_common_utils driver
                    PRIV_REQUIRES avrcp_common_utils avrcp_metadata_utils avrcp_cover_art_utils
                    INCLUDE_DIRS ".")
