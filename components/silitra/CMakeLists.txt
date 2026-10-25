idf_component_register(
    SRCS "../../src/silitra_core.c" "../../ports/esp_idf/silitra_esp_idf.c"
    INCLUDE_DIRS "../../include" "../../ports"
    REQUIRES esp_system esp_hw_support esp_rom efuse spi_flash esp_psram
)

if(DEFINED SWID_PROFILE AND NOT DEFINED SILITRA_PROFILE)
    set(SILITRA_PROFILE "${SWID_PROFILE}" CACHE STRING "SILITRA build profile: MINIMAL, STANDARD, or FULL")
else()
    set(SILITRA_PROFILE "FULL" CACHE STRING "SILITRA build profile: MINIMAL, STANDARD, or FULL")
endif()
string(TOUPPER "${SILITRA_PROFILE}" SILITRA_PROFILE_UPPER)
if(SILITRA_PROFILE_UPPER STREQUAL "MINIMAL")
    target_compile_definitions(${COMPONENT_LIB} PUBLIC SILITRA_PROFILE_MINIMAL=1)
elseif(SILITRA_PROFILE_UPPER STREQUAL "STANDARD")
    target_compile_definitions(${COMPONENT_LIB} PUBLIC SILITRA_PROFILE_STANDARD=1)
else()
    target_compile_definitions(${COMPONENT_LIB} PUBLIC SILITRA_PROFILE_FULL=1)
endif()
