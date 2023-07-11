/**
 * @file udp_packet.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-10
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TRANSPORT_LAYER_UDP_PACKET_H_
#define SRC_TRANSPORT_LAYER_UDP_PACKET_H_

#include <netinet/in.h>
#include <stdint.h>
#include "transport_layer/udp_header.h"
#include "transport_layer/transport_packet.h"

namespace net_io_top {

class UdpPacket {
public:
    UdpPacket(
        const IPAddress& src_addr, const IPAddress& dst_addr,
        const u_char* udp_data, uint32_t udp_data_len)
        : udp_header_(udp_data, udp_data_len) {
        ip_src_addr_ = src_addr.clone();
        ip_dst_addr_ = dst_addr.clone();
    }
    ~UdpPacket() {
        delete ip_src_addr_;
        delete ip_dst_addr_;
    }

public:
    inline const IPAddress& get_src_addr() const { return *ip_src_addr_; }
    inline const IPAddress& get_dst_addr() const { return *ip_dst_addr_; }
    inline uint16_t get_src_port() const { return udp_header_.get_src_port(); }
    inline uint16_t get_dst_port() const { return udp_header_.get_dst_port(); }
    inline const UdpHeader& get_udp_header() const { return udp_header_; }

private:
    // IP 源地址
    IPAddress* ip_src_addr_{nullptr};
    // IP 目的地址
    IPAddress* ip_dst_addr_{nullptr};
    // TCP 头部
    UdpHeader udp_header_;
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_UDP_PACKET_H_
