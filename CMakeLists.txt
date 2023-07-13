cmake_minimum_required(VERSION 3.25.0)
project(net_io_top)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "${CMKAE_CXX_FLAGS} -g -Wall -Werror -Wextra -fPIC -Wno-error=unused-parameter -fno-omit-frame-pointer -Wl,--as-needed")

include_directories(
    src
)

file(GLOB_RECURSE SRCS src/*.cpp)

add_executable(net_io_top ${SRCS})

target_link_libraries(net_io_top
    pcap
    pthread
)
