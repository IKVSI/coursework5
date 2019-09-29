cmake_minimum_required(VERSION 3.14)
project(AES)

set(CMAKE_CXX_STANDARD 17)
link_libraries("-static")
add_executable(AES main.cpp lib/AES.h lib/AES.cpp lib/GF256.cpp lib/GF256.h)