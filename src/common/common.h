/**
 * @file common.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-29
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

#include <sys/types.h>
#include <stdint.h>

namespace net_io_top {


#define POL_TO_MS 10

#define SNAPLEN 100

#define SYN_SYNACK_WAIT 30
#define FIN_FINACK_WAIT 60

/**
 * @brief 数据报文
 * 
 */
struct PacketData {
    // 这个指针指向 malloc 出来的内存块，不要忘记释放
    u_char* p_data;
    uint64_t len;
    struct timeval ts;
};

}  // namespace net_io_top

#endif  // SRC_COMMON_H_
