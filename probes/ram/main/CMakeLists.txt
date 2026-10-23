idf_component_register(SRCS "ram_probe.c" INCLUDE_DIRS "." REQUIRES swid esp_timer)
target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
