cmake_minimum_required(VERSION 3.16)

project(windbg_coreclr_dac_bridge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED DBGENG_PACKAGE_DIR)
    set(DBGENG_PACKAGE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../target/nuget/Microsoft.Debugging.Platform.DbgEng.20260319.1511.0")
endif()

set(DBGENG_INCLUDE_DIR "${DBGENG_PACKAGE_DIR}/build/native/inc")
if(NOT EXISTS "${DBGENG_INCLUDE_DIR}/dbgeng.h")
    message(FATAL_ERROR "DbgEng headers were not found under ${DBGENG_INCLUDE_DIR}")
endif()

add_library(windbg_coreclr_dac_bridge SHARED windbg_coreclr_dac_bridge.cpp)

target_compile_definitions(windbg_coreclr_dac_bridge
    PRIVATE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
)

target_include_directories(windbg_coreclr_dac_bridge
    PRIVATE
        "${DBGENG_INCLUDE_DIR}"
)

target_link_libraries(windbg_coreclr_dac_bridge
    PRIVATE
        version
)

set_target_properties(windbg_coreclr_dac_bridge PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)
