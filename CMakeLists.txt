cmake_minimum_required(VERSION 2.8)
project(net_io_top)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "${CMKAE_CXX_FLAGS} -g")

include_directories(
    src/
)

file(GLOB_RECURSE SRCS src/*.cpp)

add_executable(net_io_top ${SRCS})

target_link_libraries(net_io_top
    pcap
    pthread
)
