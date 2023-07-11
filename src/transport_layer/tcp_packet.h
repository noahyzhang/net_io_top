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
        // // 先解 IP 报头
        // struct sniff_ip* ip = (struct sniff_ip*)data;
        // // 只处理 IPv4 报文
        // if (ip->ip_v == 4) {
        //     total_len_ = ntohs(ip->ip_len);
        //     ip_src_addr_ = new IPv4Address(ip->ip_src);
        //     ip_dst_addr_ = new IPv4Address(ip->ip_dst);
        //     ip_header_len_ = ip->ip_hl * 4;
        // }
        // // TODO(noahyzhang): 暂未处理 IPv6 报文
        // tcp_header_ = new TcpHeader(data+ip_header_len_, data_len - ip_header_len_);
        // socket_pair_ = new SocketPair(
        //     *ip_src_addr_, tcp_header_->get_src_port(),
        //     *ip_dst_addr_, tcp_header_->get_dst_port());
    }

    ~TcpPacket() {
        delete ip_src_addr_;
        delete ip_dst_addr_;
    }

    // TcpPacket(const TcpPacket& other) {
    //     total_len_ = other.total_len_;
    //     ip_header_len_ = other.ip_header_len_;
    //     ip_src_addr_ = other.get_src_addr().clone();
    //     ip_dst_addr_ = other.get_dst_addr().clone();
    //     tcp_header_ = new TcpHeader(*other.tcp_header_);
    //     socket_pair_ = new SocketPair(*other.socket_pair_);
    // }

    // TcpPacket& operator=(const TcpPacket& other) {
    //     total_len_ = other.total_len_;
    //     ip_header_len_ = other.ip_header_len_;
    //     ip_src_addr_ = other.get_src_addr().clone();
    //     ip_dst_addr_ = other.get_dst_addr().clone();
    //     tcp_header_ = new TcpHeader(*other.tcp_header_);
    //     socket_pair_ = new SocketPair(*other.socket_pair_);
    //     return *this;
    // }

    // TcpPacket(TcpPacket&& other) {
    //     total_len_ = other.total_len_;
    //     ip_header_len_ = other.ip_header_len_;
    //     other.total_len_ = other.ip_header_len_ = 0;
    //     ip_src_addr_ = other.ip_src_addr_;
    //     ip_dst_addr_ = other.ip_dst_addr_;
    //     tcp_header_ = other.tcp_header_;
    //     socket_pair_ = other.socket_pair_;
    //     ip_src_addr_ = ip_dst_addr_ = nullptr;
    //     tcp_header_ = nullptr;
    //     socket_pair_ = nullptr;
    // }

    // TcpPacket& operator=(TcpPacket&& other) {
    //     total_len_ = other.total_len_;
    //     ip_header_len_ = other.ip_header_len_;
    //     other.total_len_ = other.ip_header_len_ = 0;
    //     ip_src_addr_ = other.ip_src_addr_;
    //     ip_dst_addr_ = other.ip_dst_addr_;
    //     tcp_header_ = other.tcp_header_;
    //     socket_pair_ = other.socket_pair_;
    //     ip_src_addr_ = ip_dst_addr_ = nullptr;
    //     tcp_header_ = nullptr;
    //     socket_pair_ = nullptr;
    //     return *this;
    // }

public:
    /**
     * @brief 返回报文总长度(从 IP 报头算起)
     * 
     * @return uint64_t 
     */
    // uint64_t get_total_len() const { return total_len_; }

    /**
     * @brief 返回报文主体长度（从 TCP 报头算起）
     * 
     * @return uint32_t 
     */
    // uint32_t get_payload_len() const { return total_len_ - ip_header_len_; }

    inline const IPAddress& get_src_addr() const { return *ip_src_addr_; }
    inline const IPAddress& get_dst_addr() const { return *ip_dst_addr_; }
    inline uint16_t get_src_port() const { return tcp_header_.get_src_port(); }
    inline uint16_t get_dst_port() const { return tcp_header_.get_dst_port(); }
    inline const TcpHeader& get_tcp_header() const { return tcp_header_; }
    // const SocketPair& get_socket_pair() const  { return *socket_pair_; }

private:
    // 报文总长度（从 IP 头算起）
    // uint64_t total_len_{0};
    // IP 报文头部长度
    // uint16_t ip_header_len_{0};
    // IP 源地址
    IPAddress* ip_src_addr_{nullptr};
    // IP 目的地址
    IPAddress* ip_dst_addr_{nullptr};
    // TCP 头部
    TcpHeader tcp_header_;
    // socket 连接对
    // SocketPair* socket_pair_{nullptr};
};

}  // namespace net_io_top

#endif  // SRC_TCP_PACKET_H_
