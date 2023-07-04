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

#ifndef SRC_TCP_PACKET_H_
#define SRC_TCP_PACKET_H_

#include <stdint.h>
#include "tcp_header.h"
#include "ip_address.h"
#include "ipv4_address.h"
#include "socket_pair.h"

namespace net_io_top {

class TcpPacket {
public:
    TcpPacket(const u_char* data, uint32_t data_len) {
        // 先解 IP 报头
        struct sniff_ip* ip = (struct sniff_ip*)data;
        if (ip->ip_v == 4) {
            total_len_ = ntohs(ip->ip_len);
            src_ = new IPv4Address(ip->ip_src);
            dst_ = new IPv4Address(ip->ip_dst);
            header_len_ = ip->ip_hl * 4;
        }
        tcp_header_ = new TCPHeader(data+header_len_, data_len-header_len_);
        socket_pair_ = new SocketPair(*src_, tcp_header_->get_src_port(), *dst_, tcp_header_->get_dst_port());
    }

    TcpPacket(const TcpPacket& other) {}
    ~TcpPacket() {}

public:
    uint32_t get_total_len() const {}
    uint64_t get_len() const { return total_len_; }
    uint32_t get_payload_len() const {  }
    IPAddress& get_src_addr() const { }
    IPAddress& get_dst_addr() const {}
    TCPHeader& get_tcp_header() const { return *tcp_header_; }
    SocketPair& get_socket_pair() const { return *socket_pair_; }

private:
    uint64_t total_len_;
    uint16_t header_len_;
    IPAddress* src_;
    IPAddress* dst_;
    TCPHeader* tcp_header_;
    SocketPair* socket_pair_;
};

}  // namespace net_io_top

#endif  // SRC_TCP_PACKET_H_
