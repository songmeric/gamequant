cmake_minimum_required(VERSION 3.25)
project(pme
    VERSION 1.0.0
    DESCRIPTION "Packet Matching Engine"
    LANGUAGES CXX
)

# Linux build environment check
if(CMAKE_SYSTEM_NAME AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(WARNING "This project is designed for Linux systems. Build may fail on ${CMAKE_SYSTEM_NAME}.")
endif()

# 
# Build Configuration
#

list(APPEND CMAKE_MODULE_PATH /opt/sp/cmake/2.25/modules/)
# Note: The Functions module is part of SP framework - required for sp_find_package
include(Functions)
add_compile_options(-Wall -Wno-interference-size)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_BUILD_TYPE Debug)

#if(NOT CMAKE_BUILD_TYPE)
#    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
#endif()

#
# Dependencies
#

# --- System Prerequisites for Linux
# libpcap is required: apt install libpcap-dev (Debian/Ubuntu) or yum install libpcap-devel (RHEL/CentOS)
# PcapPlusPlus will find it automatically during build

# --- PcapPlusPlus (fetch from source)
include(FetchContent)

FetchContent_Declare(
    PcapPlusPlus
    GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
    GIT_TAG v23.09  # Latest stable release
)

# Set PcapPlusPlus build options
set(PCAPPP_BUILD_EXAMPLES OFF CACHE BOOL "Build PcapPlusPlus examples")
set(PCAPPP_BUILD_TESTS OFF CACHE BOOL "Build PcapPlusPlus tests")
set(PCAPPP_BUILD_UTILS OFF CACHE BOOL "Build PcapPlusPlus utilities")
set(PCAPPP_INSTALL OFF CACHE BOOL "Install PcapPlusPlus")
set(PCAPPP_USE_DPDK OFF CACHE BOOL "Use DPDK")
set(PCAPPP_USE_PF_RING OFF CACHE BOOL "Use PF_RING")

FetchContent_MakeAvailable(PcapPlusPlus)

# yaml-cpp

FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG master # Can be a tag (yaml-cpp-x.x.x), a commit hash, or a branch name (master)
)
FetchContent_MakeAvailable(yaml-cpp)

# Boost
set(BOOST_VERSION 1.60.0)
sp_find_package(Boost ${BOOST_VERSION})

# SP Application Framework
set(SPAPP_VERSION 31)
include(/opt/sp/spapp/${SPAPP_VERSION}/cmake/init.cmake)
set(RAZEAPI_VERSION 3.24.2)
set(MD_API_VERSION 1.606)
sp_find_package(razeapi ${RAZEAPI_VERSION} NODEPEND)
sp_find_package(md_api ${MD_API_VERSION} USEDEFAULTDEPENDCOMPONENTS)

# --- GoogleTest (for tests)
find_package(GTest REQUIRED)


#
# Source Files
#

# Core library sources (reusable components)
set(PME_CORE_SOURCES
    src/Config.cpp
    src/DropcopyHandler.cpp
    src/Engine.cpp
    src/PacketProcessor.cpp
    src/FlowClassifier.cpp
    src/ProtocolHandlerFactory.cpp
    src/SpcastV3Handler.cpp
    src/RazeHandler.cpp
    util/Log.cpp
)

set(PME_CORE_HEADERS
    src/Config.h
    src/DropcopyHandler.h
    src/Engine.h
    src/OutputFileWriter.h
    src/PacketProcessor.h
    src/FlowClassifier.h
    src/RuntimeContext.h
    src/IProtocolHandler.h
    src/Protocols.h
    src/SpcastV3Handler.h
    src/RazeHandler.h
    src/Hash.h
    src/Types.h
    src/RingBuffer.h
    util/Log.h
)

# Application-specific sources
set(PME_APP_SOURCES
    src/main.cpp
)

set(PME_APP_HEADERS
    src/Cli.h
)

# Test sources
set(PME_TEST_SOURCES
    tests/DropcopyHandler_test.cpp
    tests/SpcastV3Handler_test.cpp
    tests/RazeHandler_test.cpp
    tests/RingBuffer_test.cpp
    tests/FlowClassifier_test.cpp
    tests/Config_test.cpp
    tests/Hash_test.cpp
    tests/Protocols_test.cpp
    tests/OutputFileWriter_test.cpp
)

#
# Interface Library for Common Dependencies
#

add_library(pme_deps INTERFACE)
target_link_libraries(pme_deps INTERFACE
    Pcap++
    Common++
    Packet++
    spapp_logging
    spapp_app
    boost_program_options-mt
    yaml-cpp
)
# No need to manually add include directories - FetchContent handles this
target_compile_features(pme_deps INTERFACE cxx_std_20)

#
# Core Library Target
#

add_library(pme_core ${PME_CORE_SOURCES} ${PME_CORE_HEADERS})
target_include_directories(pme_core PUBLIC
    src
    util
)
target_link_libraries(pme_core PUBLIC pme_deps)

# Make headers available for IDE
set_target_properties(pme_core PROPERTIES
    PUBLIC_HEADER "${PME_CORE_HEADERS}"
)

#
# Main Executable Target
#

add_executable(pme ${PME_APP_SOURCES} ${PME_APP_HEADERS})
target_include_directories(pme PRIVATE src util)
target_link_libraries(pme PRIVATE
    pme_core
    pme_deps
    spapp_app_cmdlne
)

#
# Tests (Optional)
#

option(PME_ENABLE_TESTS "Build unit tests" ON)

if(PME_ENABLE_TESTS)
    enable_testing()

    add_executable(pme_tests ${PME_TEST_SOURCES})
    target_include_directories(pme_tests PRIVATE src util)
    target_link_libraries(pme_tests PRIVATE
        pme_core
        pme_deps
        spapp_app_cmdlne
        GTest::gmock
        GTest::gtest
        GTest::gmock_main
    )

    # Register test with CTest
    include(GoogleTest)
    gtest_discover_tests(pme_tests)

    # Also add a simple test command for convenience
    add_test(NAME all_tests COMMAND pme_tests)
endif()
