cmake_minimum_required(VERSION 3.20)
project(PhantomScopeNative VERSION 1.0.0 LANGUAGES CXX ASM_NASM)

# ============================================================================
# PhantomScope CMake Build Configuration
# Builds: NASM assembly → shared library → C++ N-API addon
#
# Usage:
#   Windows: cmake -G "Visual Studio 17 2022" -A x64 ..
#   Linux:   cmake -DCMAKE_BUILD_TYPE=Release ..
#   Both:    cmake --build . --config Release
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- Platform detection ----
if(WIN32)
    message(STATUS "PhantomScope: Building for Windows x64")
    add_compile_definitions(PHANTOMSCOPE_WINDOWS=1 _WIN32_WINNT=0x0A00)
elseif(UNIX AND NOT APPLE)
    message(STATUS "PhantomScope: Building for Linux x64")
    add_compile_definitions(PHANTOMSCOPE_LINUX=1)
else()
    message(FATAL_ERROR "PhantomScope: Unsupported platform (Windows and Linux only)")
endif()

# ---- NASM configuration ----
enable_language(ASM_NASM)

if(WIN32)
    set(CMAKE_ASM_NASM_FLAGS "-f win64")
    set(ASM_FORMAT "win64")
elseif(UNIX)
    set(CMAKE_ASM_NASM_FLAGS "-f elf64 -DLINUX")
    set(ASM_FORMAT "elf64")
endif()

# Debug vs Release NASM flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -g -F dwarf")
else()
    set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -O2")
endif()

# ---- Assembly sources ----
set(ASM_SOURCES_WIN
    ${CMAKE_SOURCE_DIR}/asm/process_enum.asm
    ${CMAKE_SOURCE_DIR}/asm/syscall_wrapper.asm
    ${CMAKE_SOURCE_DIR}/asm/md5_engine.asm
    ${CMAKE_SOURCE_DIR}/asm/entropy_calc.asm
)

set(ASM_SOURCES_LIN
    ${CMAKE_SOURCE_DIR}/asm/linux_proc.asm
    ${CMAKE_SOURCE_DIR}/asm/md5_engine.asm
    ${CMAKE_SOURCE_DIR}/asm/entropy_calc.asm
)

if(WIN32)
    set(ASM_SOURCES ${ASM_SOURCES_WIN})
else()
    set(ASM_SOURCES ${ASM_SOURCES_LIN})
endif()

# ---- C++ Bridge sources ----
set(CPP_SOURCES
    ${CMAKE_SOURCE_DIR}/src/bridge/asm_bridge.cpp
    ${CMAKE_SOURCE_DIR}/src/bridge/process_diff.cpp
    ${CMAKE_SOURCE_DIR}/src/bridge/vt_client.cpp
    ${CMAKE_SOURCE_DIR}/src/bridge/file_scanner.cpp
    ${CMAKE_SOURCE_DIR}/src/bridge/graph_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/bridge/pe_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/bridge/elf_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/bridge/napi_bindings.cpp
)

# ---- Node.js N-API headers ----
# node-gyp sets these; for standalone CMake builds, find them manually
if(DEFINED ENV{npm_config_node_include})
    set(NODE_INCLUDE_DIR $ENV{npm_config_node_include})
else()
    # Try to find Node.js headers via node --print
    execute_process(
        COMMAND node -p "require('path').dirname(process.execPath)"
        OUTPUT_VARIABLE NODE_BIN_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    find_path(NODE_INCLUDE_DIR
        NAMES node_api.h
        HINTS
            "${NODE_BIN_DIR}/../include/node"
            "/usr/include/node"
            "/usr/local/include/node"
        DOC "Node.js include directory"
    )
endif()

if(NOT NODE_INCLUDE_DIR)
    message(WARNING "Node.js headers not found — N-API bindings will be skipped")
    set(BUILD_NAPI OFF)
else()
    message(STATUS "Node.js headers: ${NODE_INCLUDE_DIR}")
    set(BUILD_NAPI ON)
endif()

# ---- Build the ASM static library ----
add_library(phantomscope_asm STATIC ${ASM_SOURCES})
set_target_properties(phantomscope_asm PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

# ---- Build the C++ bridge shared library ----
add_library(phantomscope_bridge SHARED ${CPP_SOURCES})

target_include_directories(phantomscope_bridge
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/bridge
        ${CMAKE_SOURCE_DIR}/src/bridge/include
)

target_link_libraries(phantomscope_bridge
    PRIVATE
        phantomscope_asm
)

if(WIN32)
    target_link_libraries(phantomscope_bridge PRIVATE
        ntdll.lib
        kernel32.lib
        advapi32.lib     # Service Control Manager
        wintrust.lib     # Digital signature verification
        crypt32.lib
    )
    # Generate import library
    set_target_properties(phantomscope_bridge PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS OFF   # Use explicit __declspec(dllexport)
    )
elseif(UNIX)
    target_link_libraries(phantomscope_bridge PRIVATE
        dl          # dlopen for dynamic loading
        pthread
    )
    set_target_properties(phantomscope_bridge PROPERTIES
        SOVERSION 1
    )
endif()

# Compiler flags
target_compile_options(phantomscope_bridge PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /O2 /LTCG>
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -O3 -march=native>
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -O3 -march=native>
)

# ---- Build N-API native addon (if Node.js headers found) ----
if(BUILD_NAPI)
    add_library(phantomscope_addon MODULE ${CPP_SOURCES})

    target_include_directories(phantomscope_addon
        PRIVATE
            ${NODE_INCLUDE_DIR}
            ${CMAKE_SOURCE_DIR}/src/bridge
            ${CMAKE_SOURCE_DIR}/src/bridge/include
    )

    target_compile_definitions(phantomscope_addon PRIVATE
        NAPI_VERSION=8
        NODE_ADDON_API_DISABLE_DEPRECATED
        BUILDING_NODE_EXTENSION
    )

    target_link_libraries(phantomscope_addon
        PRIVATE
            phantomscope_asm
    )

    # Node.js addon must have .node extension
    set_target_properties(phantomscope_addon PROPERTIES
        PREFIX ""
        SUFFIX ".node"
        OUTPUT_NAME "phantomscope"
    )

    if(WIN32)
        target_link_libraries(phantomscope_addon PRIVATE
            ntdll.lib kernel32.lib advapi32.lib wintrust.lib crypt32.lib
        )
    else()
        target_link_options(phantomscope_addon PRIVATE
            -undefined dynamic_lookup    # Don't link node symbols at build time
        )
    endif()

    # Install .node addon to the expected location
    install(TARGETS phantomscope_addon
        LIBRARY DESTINATION ${CMAKE_SOURCE_DIR}/build/Release
    )
endif()

# ---- Unit test target ----
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    enable_testing()
    add_executable(phantomscope_tests
        ${CMAKE_SOURCE_DIR}/tests/unit/test_md5.cpp
        ${CMAKE_SOURCE_DIR}/tests/unit/test_entropy.cpp
        ${CMAKE_SOURCE_DIR}/tests/unit/test_process_diff.cpp
        ${CMAKE_SOURCE_DIR}/tests/unit/test_pe_parser.cpp
    )
    target_link_libraries(phantomscope_tests
        PRIVATE phantomscope_bridge phantomscope_asm
    )
    add_test(NAME UnitTests COMMAND phantomscope_tests)
endif()

# ---- Build info summary ----
message(STATUS "=== PhantomScope Build Configuration ===")
message(STATUS "Platform:        ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Build type:      ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard:    C++${CMAKE_CXX_STANDARD}")
message(STATUS "NASM format:     ${ASM_FORMAT}")
message(STATUS "N-API bindings:  ${BUILD_NAPI}")
message(STATUS "ASM sources:     ${ASM_SOURCES}")
message(STATUS "=========================================")
