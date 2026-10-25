cmake_minimum_required(VERSION 3.16)

option(SILITRA_HOST_TESTS "Build the portable SILITRA core unit test" OFF)
option(SWID_HOST_TESTS "Deprecated alias for SILITRA_HOST_TESTS" OFF)
if(SWID_HOST_TESTS)
    set(SILITRA_HOST_TESTS ON)
endif()
if(SILITRA_HOST_TESTS)
    project(silitra_host_tests VERSION 2.0.0 LANGUAGES C)
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_C_STANDARD_REQUIRED ON)
    set(CMAKE_C_EXTENSIONS OFF)
    enable_testing()
    add_executable(silitra_core_test
        src/silitra_core.c
        ports/host/silitra_host_mock.c
        tests/unit/silitra_core_test.c)
    target_include_directories(silitra_core_test PRIVATE include ports)
    add_test(NAME silitra_core_test COMMAND silitra_core_test)
    return()
endif()

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/firmware/main"
    "${CMAKE_CURRENT_LIST_DIR}/components/silitra")
set(COMPONENTS main silitra)
set(PROJECT_VER "2.0.0")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(silitra)
