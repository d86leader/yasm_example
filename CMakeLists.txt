cmake_minimum_required(VERSION 3.17)
project(yamsex)
set(CMAKE_CXX_STANDARD 17)

include_directories(${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/../yasm/
    )

add_executable(${PROJECT_NAME}
    main.cpp
    )

target_compile_options(${PROJECT_NAME} PUBLIC -Wall -Wextra -Wpedantic)

target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/../yasm/libyasm.a)
