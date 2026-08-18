cmake_minimum_required(VERSION 3.20)

project(NetAssess LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(NetAssessCore STATIC src/protocol_classifier.cpp)
target_include_directories(NetAssessCore PUBLIC src)
target_compile_options(NetAssessCore PRIVATE /utf-8)

add_executable(NetAssessTests tests/unit_tests.cpp)
target_link_libraries(NetAssessTests PRIVATE NetAssessCore)
target_compile_options(NetAssessTests PRIVATE /utf-8)

include(CTest)
if(BUILD_TESTING)
    add_test(NAME NetAssessTests COMMAND NetAssessTests)
endif()
