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
        // 只处理 IPv4 报文
        if (ip->ip_v == 4) {
            total_len_ = ntohs(ip->ip_len);
            src_ = new IPv4Address(ip->ip_src);
            dst_ = new IPv4Address(ip->ip_dst);
            header_len_ = ip->ip_hl * 4;
        }
        // TODO(noahyzhang): 还未处理 IPv6 报文
        tcp_header_ = new TcpHeader(data+header_len_, data_len-header_len_);
        socket_pair_ = new SocketPair(*src_, tcp_header_->get_src_port(), *dst_, tcp_header_->get_dst_port());
    }

    TcpPacket(const TcpPacket& other) {
        src_ = other.get_src_addr().clone();
        dst_ = other.get_dst_addr().clone();
        total_len_ = other.total_len_;
        header_len_ = other.header_len_;
        tcp_header_ = new TcpHeader(*other.tcp_header_);
        socket_pair_ = new SocketPair(*other.socket_pair_);
    }

    ~TcpPacket() {
        delete src_;
        delete dst_;
        delete tcp_header_;
        delete socket_pair_;
    }

public:
    uint64_t get_total_len() const { return total_len_; }
    uint32_t get_payload_len() const { return total_len_ - header_len_; }
    const IPAddress& get_src_addr() const { return *src_; }
    const IPAddress& get_dst_addr() const { return *dst_; }
    const TcpHeader& get_tcp_header() const { return *tcp_header_; }
    const SocketPair& get_socket_pair() const { return *socket_pair_; }

public:
    static TcpPacket* new_tcp_packet(const u_char* data, uint64_t data_len) {
        struct sniff_ip* ip = (struct sniff_ip*)data;
        // 校验 IPv4 报头
        if (ip->ip_v == 4 && ip->ip_p != IPPROTO_TCP) {
            return nullptr;
        }
        // TODO(noahyzhang): 暂未校验 IPv6 报文
        return new TcpPacket(data, data_len);
    }

private:
    uint64_t total_len_{0};
    uint16_t header_len_{0};
    IPAddress* src_{nullptr};
    IPAddress* dst_{nullptr};
    TcpHeader* tcp_header_{nullptr};
    SocketPair* socket_pair_{nullptr};
};

}  // namespace net_io_top

#endif  // SRC_TCP_PACKET_H_
