project(woodenhouse C)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_C_FLAGS "-nostdlib -s -pie -Wall -Wextra -std=gnu11")

add_executable(${PROJECT_NAME}
                src/main.c)

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND strip -R .interp -R .comment ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../stripBinary/stripBinary ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../convertToFile/convertToFile ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME} > ../../trouble/src/generated/the_binary.h)
