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

struct IpPacketWrap {
    // 这个指针指向 malloc 出来的内存块，不要忘记释放
    // 这个指针从 IP 报头开始
    u_char* ip_data;
    uint64_t ip_data_len;
    struct timeval ts;
};

enum TransportLayerProtocol {
    TRANSPORT_LAYER_PROTOCOL_TCP = 0,
    TRANSPORT_LAYER_PROTOCOL_UDP
};

}  // namespace net_io_top

#endif  // SRC_COMMON_H_
