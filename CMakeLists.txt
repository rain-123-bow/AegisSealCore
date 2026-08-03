cmake_minimum_required(VERSION 3.28)

project(AegisSealCore VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "ASC-1 v1 supports only Windows with MSVC")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

enable_testing()

add_library(aegis_seal_cng STATIC
    src/cng_hash.cpp
)

target_include_directories(aegis_seal_cng PRIVATE src)
target_compile_options(aegis_seal_cng PRIVATE
    /W4 /WX /permissive- /utf-8
    $<$<CONFIG:Release>:/O2>
    $<$<CONFIG:Release>:/GL>
)
target_link_libraries(aegis_seal_cng PRIVATE bcrypt)

add_library(aegis_seal_core STATIC
    src/core.cpp
    src/pepper.cpp
)

target_include_directories(aegis_seal_core
    PUBLIC include
    PRIVATE src
)
target_compile_options(aegis_seal_core PRIVATE
    /W4 /WX /permissive- /utf-8
    $<$<CONFIG:Release>:/O2>
    $<$<CONFIG:Release>:/GL>
)
target_link_libraries(aegis_seal_core PRIVATE aegis_seal_cng)

add_library(aegis_seal_manifest STATIC
    src/manifest.cpp
)

target_include_directories(aegis_seal_manifest
    PUBLIC include
    PRIVATE src
)
target_compile_options(aegis_seal_manifest PRIVATE
    /W4 /WX /permissive- /utf-8
    $<$<CONFIG:Release>:/O2>
    $<$<CONFIG:Release>:/GL>
)

add_executable(aegis_seal
    src/main.cpp
)

target_include_directories(aegis_seal PRIVATE include src)
target_compile_options(aegis_seal PRIVATE
    /W4 /WX /permissive- /utf-8
    $<$<CONFIG:Release>:/O2>
    $<$<CONFIG:Release>:/GL>
)
target_link_libraries(aegis_seal PRIVATE aegis_seal_core aegis_seal_manifest)
target_link_options(aegis_seal PRIVATE
    $<$<CONFIG:Release>:/LTCG>
    $<$<CONFIG:Release>:/OPT:REF>
    $<$<CONFIG:Release>:/OPT:ICF>
)
set_target_properties(aegis_seal PROPERTIES OUTPUT_NAME "aegis-seal")

add_executable(aegis_seal_tests
    tests/core_tests.cpp
)

target_include_directories(aegis_seal_tests PRIVATE include)
target_compile_options(aegis_seal_tests PRIVATE /W4 /WX /permissive- /utf-8)
target_link_libraries(aegis_seal_tests PRIVATE aegis_seal_core)
target_link_options(aegis_seal_tests PRIVATE $<$<CONFIG:Release>:/LTCG>)

add_test(NAME aegis_seal_core COMMAND aegis_seal_tests)

add_executable(aegis_seal_cng_tests
    tests/cng_hash_tests.cpp
)

target_include_directories(aegis_seal_cng_tests PRIVATE src)
target_compile_options(aegis_seal_cng_tests PRIVATE /W4 /WX /permissive- /utf-8)
target_link_libraries(aegis_seal_cng_tests PRIVATE aegis_seal_cng)
target_link_options(aegis_seal_cng_tests PRIVATE $<$<CONFIG:Release>:/LTCG>)

add_test(NAME aegis_seal_cng COMMAND aegis_seal_cng_tests)

add_executable(aegis_seal_manifest_tests
    tests/manifest_tests.cpp
)

target_include_directories(aegis_seal_manifest_tests PRIVATE include src)
target_compile_options(aegis_seal_manifest_tests PRIVATE /W4 /WX /permissive- /utf-8)
target_link_libraries(aegis_seal_manifest_tests PRIVATE aegis_seal_manifest)
target_link_options(aegis_seal_manifest_tests PRIVATE $<$<CONFIG:Release>:/LTCG>)

add_test(NAME aegis_seal_manifest COMMAND aegis_seal_manifest_tests)

find_program(POWERSHELL_EXECUTABLE NAMES pwsh REQUIRED)
add_test(
    NAME aegis_seal_cli
    COMMAND "${POWERSHELL_EXECUTABLE}" -NoProfile -File
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_integration.ps1"
        -ExePath "$<TARGET_FILE:aegis_seal>"
        -WorkDir "${CMAKE_CURRENT_BINARY_DIR}/cli-test"
)

install(TARGETS aegis_seal RUNTIME DESTINATION bin)
