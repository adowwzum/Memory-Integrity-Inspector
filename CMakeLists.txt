cmake_minimum_required(VERSION 3.20)
project(MemoryIntegrityInspector VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Memory Integrity Inspector requires Windows 10/11 x64.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Select an x64 toolchain, for example with -A x64.")
endif()

add_executable(Memory-Integrity-Inspector main.cpp memory_scanner.cpp memory_scanner.h)
target_compile_features(Memory-Integrity-Inspector PRIVATE cxx_std_17)
set_target_properties(Memory-Integrity-Inspector PROPERTIES CXX_EXTENSIONS OFF)
target_compile_definitions(Memory-Integrity-Inspector PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX WINVER=0x0A00 _WIN32_WINNT=0x0A00)

if(MSVC)
    target_compile_options(Memory-Integrity-Inspector PRIVATE /W4 /permissive- /EHsc /utf-8)
    set_property(TARGET Memory-Integrity-Inspector PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    target_compile_options(Memory-Integrity-Inspector PRIVATE -Wall -Wextra -Wpedantic)
endif()
