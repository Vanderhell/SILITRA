idf_component_register(
    SRCS "../../src/swid_core.c" "../../ports/esp_idf/swid_esp_idf.c"
    INCLUDE_DIRS "../../include" "../../ports"
    REQUIRES esp_system esp_hw_support esp_rom efuse spi_flash esp_psram
)

set(SWID_PROFILE "FULL" CACHE STRING "SWID build profile: MINIMAL, STANDARD, or FULL")
string(TOUPPER "${SWID_PROFILE}" SWID_PROFILE_UPPER)
if(SWID_PROFILE_UPPER STREQUAL "MINIMAL")
    target_compile_definitions(${COMPONENT_LIB} PUBLIC SWID_PROFILE_MINIMAL=1)
elseif(SWID_PROFILE_UPPER STREQUAL "STANDARD")
    target_compile_definitions(${COMPONENT_LIB} PUBLIC SWID_PROFILE_STANDARD=1)
else()
    target_compile_definitions(${COMPONENT_LIB} PUBLIC SWID_PROFILE_FULL=1)
endif()
