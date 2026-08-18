cmake_minimum_required(VERSION 3.20)

project(NetAssess LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "NetAssess supports x64 builds only.")
endif()

if(CMAKE_GENERATOR_PLATFORM)
    string(TOLOWER "${CMAKE_GENERATOR_PLATFORM}" netassess_generator_platform)
    if(NOT netassess_generator_platform STREQUAL "x64")
        message(FATAL_ERROR "NetAssess supports the x64 generator platform only.")
    endif()
endif()

add_library(NetAssessCore STATIC src/protocol_classifier.cpp src/traffic_aggregator.cpp src/formatting.cpp
                                  src/process_info.cpp src/etw_decoder.cpp src/etw_monitor.cpp
                                  src/main_window.cpp)
target_include_directories(NetAssessCore PUBLIC src)
target_compile_definitions(NetAssessCore PUBLIC _WIN32_WINNT=0x0A00 UNICODE _UNICODE)
target_compile_options(NetAssessCore PRIVATE /utf-8)
target_link_libraries(NetAssessCore PRIVATE tdh advapi32 ole32 comctl32 user32 gdi32)

add_executable(NetAssess WIN32 src/main.cpp resources/app.manifest)
target_link_libraries(NetAssess PRIVATE NetAssessCore)
target_compile_options(NetAssess PRIVATE /utf-8)
target_link_options(NetAssess PRIVATE /MANIFESTUAC:NO)

add_executable(NetAssessTests tests/unit_tests.cpp)
target_link_libraries(NetAssessTests PRIVATE NetAssessCore)
target_compile_options(NetAssessTests PRIVATE /utf-8)

include(CTest)
if(BUILD_TESTING)
    add_test(NAME NetAssessTests COMMAND NetAssessTests)
endif()
