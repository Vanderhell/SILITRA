idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES esp_driver_uart esp_driver_usb_serial_jtag esp_system freertos swid)

target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)

if(SWID_FP1_UART_TRANSPORT)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE SWID_FP1_UART_TRANSPORT=1)
endif()
