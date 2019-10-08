cmake_minimum_required(VERSION 3.14)
project(AESSecretSharing)

set(CMAKE_CXX_STANDARD 17)
link_libraries("-static")
add_executable(AESSecretSharing main.cpp lib/SSS.cpp lib/SSS.h ../AES/lib/GF256.h ../AES/lib/GF256.cpp)