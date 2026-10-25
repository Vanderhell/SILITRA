idf_component_register(SRCS "silitra_ram_probe.c" INCLUDE_DIRS "." REQUIRES silitra esp_timer)
target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
