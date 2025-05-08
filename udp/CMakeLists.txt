cmake_minimum_required(VERSION 3.20)

project(udp_file_transfer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

include_directories(${PROJECT_SOURCE_DIR}/include)

add_library(common STATIC src/crc32.cpp)

add_executable(server server.cpp)
target_link_libraries(server PRIVATE common)

add_executable(client client.cpp)
target_link_libraries(client PRIVATE common)