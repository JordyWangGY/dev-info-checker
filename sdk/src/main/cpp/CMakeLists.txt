cmake_minimum_required(VERSION 3.22.1)
project("devcheck")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(devcheck SHARED devcheck.cpp)

# 体积/隐藏符号优化
target_compile_options(devcheck PRIVATE -O2 -fvisibility=hidden -ffunction-sections -fdata-sections)
target_link_options(devcheck PRIVATE -Wl,--gc-sections -Wl,--strip-all)
