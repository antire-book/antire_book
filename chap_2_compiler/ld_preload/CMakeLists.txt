project(catch_memcmp.so C)
cmake_minimum_required(VERSION 3.0)

set(CMAKE_C_FLAGS "-Wall -Wextra -Wshadow -fPIC -shared -std=gnu11")
add_executable(${PROJECT_NAME} src/catch_memcmp.c)
target_link_libraries(${PROJECT_NAME} dl)

