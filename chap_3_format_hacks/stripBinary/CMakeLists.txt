project(stripBinary CXX)
cmake_minimum_required(VERSION 3.0)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wshadow -g")
add_executable(${PROJECT_NAME} ./src/stripBinary.cpp)
