cmake_minimum_required(VERSION 3.16)

option(SWID_HOST_TESTS "Build the portable SWID core unit test" OFF)
if(SWID_HOST_TESTS)
    project(swid_host_tests C)
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_C_STANDARD_REQUIRED ON)
    set(CMAKE_C_EXTENSIONS OFF)
    enable_testing()
    add_executable(swid_core_test
        src/swid_core.c
        ports/host/swid_host_mock.c
        tests/unit/swid_core_test.c)
    target_include_directories(swid_core_test PRIVATE include ports)
    add_test(NAME swid_core_test COMMAND swid_core_test)
    return()
endif()

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/firmware/main"
    "${CMAKE_CURRENT_LIST_DIR}/components/swid")
set(COMPONENTS main swid)
set(PROJECT_VER "0.1.0")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(swid)
