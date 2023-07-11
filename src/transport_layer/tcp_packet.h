/**
 * @file tcp_packet.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-30
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TRANSPORT_LAYER_TCP_PACKET_H_
#define SRC_TRANSPORT_LAYER_TCP_PACKET_H_

#include <stdint.h>
#include "transport_layer/tcp_header.h"
#include "network_layer/ip_address.h"
#include "network_layer/ipv4_address.h"
#include "transport_layer/socket_pair.h"

namespace net_io_top {

/**
 * @brief TCP 报文主体
 * 
 */
class TcpPacket {
public:
    TcpPacket(
        const IPAddress& src_addr, const IPAddress& dst_addr,
        const u_char* tcp_data, uint32_t tcp_data_len)
        : tcp_header_(tcp_data, tcp_data_len) {
        ip_src_addr_ = src_addr.clone();
        ip_dst_addr_ = dst_addr.clone();
    }
    ~TcpPacket() {
        delete ip_src_addr_;
        delete ip_dst_addr_;
    }
    TcpPacket(const TcpPacket&) = delete;
    TcpPacket& operator=(const TcpPacket&) = delete;
    TcpPacket(TcpPacket&&) = delete;
    TcpPacket& operator=(TcpPacket&&) = delete;

public:
    inline const IPAddress& get_src_addr() const { return *ip_src_addr_; }
    inline const IPAddress& get_dst_addr() const { return *ip_dst_addr_; }
    inline uint16_t get_src_port() const { return tcp_header_.get_src_port(); }
    inline uint16_t get_dst_port() const { return tcp_header_.get_dst_port(); }
    inline const TcpHeader& get_tcp_header() const { return tcp_header_; }

private:
    // IP 源地址
    IPAddress* ip_src_addr_{nullptr};
    // IP 目的地址
    IPAddress* ip_dst_addr_{nullptr};
    // TCP 头部
    TcpHeader tcp_header_;
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_TCP_PACKET_H_
