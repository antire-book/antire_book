project(encryptSections CXX)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -g -std=c++11")

add_executable(${PROJECT_NAME}
                src/main.cpp
                ../common/crypto/crc32.c
                ../common/crypto/rc4.c)

set_source_files_properties(../common/crypto/crc32.c PROPERTIES LANGUAGE CXX)
set_source_files_properties(../common/crypto/rc4.c PROPERTIES LANGUAGE CXX)
