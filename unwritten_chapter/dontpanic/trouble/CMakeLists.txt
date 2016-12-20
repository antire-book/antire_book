project(trouble C)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_C_FLAGS "-static -Wall -Wextra -Winline -Wshadow -O2 -s -std=gnu11")

add_executable(${PROJECT_NAME}
                src/main.c
                src/ptrace_funcs.c
                src/maps_parsing.c
                src/load_binary.c
                ../common/crypto/crc32.c
                ../common/crypto/rc4.c)

add_custom_target(addLDS
                  COMMAND sed -i -e 's,-o,${CMAKE_CURRENT_SOURCE_DIR}/elf_layout.lds -o,g' ./CMakeFiles/trouble.dir/link.txt)

add_dependencies(${PROJECT_NAME} addLDS)

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND strip -R .comment ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../computeChecksums/computeChecksums ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../encryptSections/encryptSections ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../stripBinary/stripBinary ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../cryptor/cryptor ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND echo 'Ag==' | base64 -d | dd conv=notrunc of=${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME} bs=1 seek=5 )
