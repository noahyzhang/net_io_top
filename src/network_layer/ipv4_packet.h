/**
 * @file ip_packet.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-10
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_NETWORK_LAYER_IPV4_PACKET_H_
#define SRC_NETWORK_LAYER_IPV4_PACKET_H_

#include <stdint.h>
#include <netinet/in.h>
#include "common/headers.h"
#include "network_layer/ipv4_address.h"
#include "common/log.h"

namespace net_io_top {

/**
 * @brief IP 数据报文
 * 
 */
class IPv4Packet {
public:
    IPv4Packet() = default;
    ~IPv4Packet() {
        if (ip_src_addr_ != nullptr) {
            delete ip_src_addr_;
        }
        if (ip_dst_addr_ != nullptr) {
            delete ip_dst_addr_;
        }
    }
    IPv4Packet(const IPv4Packet&) = delete;
    IPv4Packet& operator=(const IPv4Packet&) = delete;
    IPv4Packet(IPv4Packet&&) = delete;
    IPv4Packet& operator=(IPv4Packet&&) = delete;

public:
    int init(u_char* ip_data, uint32_t real_ip_data_len, uint32_t expected_ip_data_len) {
        (void)expected_ip_data_len;
        if (sizeof(struct sniff_ip) > real_ip_data_len) {
            LOG(ERROR) << "IPv4Packet data length exceeds real data length!";
            return -1;
        }
        struct sniff_ip* ip = (struct sniff_ip*)(ip_data);
        if (ip->ip_v != 4) {
            LOG(ERROR) << "IPv4Packet init failed, just support IPv4, cur protocol: " << ip->ip_v;
            return -2;
        }
        ip_src_addr_ = new IPv4Address(ip->ip_src);
        ip_dst_addr_ = new IPv4Address(ip->ip_dst);
        ip_header_len_ = ip->ip_hl * 4;
        ip_protocol_ = ip->ip_p;
        if (ip_header_len_ > real_ip_data_len) {
            LOG(ERROR) << "IPv4Packet data length too small, Not enough space for the IP header";
            return -3;
        }
        ip_body_ = ip_data + ip_header_len_;
        // 注意大小端，网络字节序转换为主机字节序
        ip_body_len_ = ntohs(ip->ip_len) - ip_header_len_;
        real_ip_body_len_ = real_ip_data_len - ip_header_len_;
        return 0;
    }

    inline u_char get_ip_protocol() const { return ip_protocol_; }
    inline uint16_t get_ip_header_len() const { return ip_header_len_; }
    inline const IPv4Address& get_ip_src_addr() const { return *ip_src_addr_; }
    inline const IPv4Address& get_ip_dst_addr() const { return *ip_dst_addr_; }
    inline const u_char* get_ip_body() const { return ip_body_; }
    inline uint32_t get_ip_body_len() const { return ip_body_len_; }
    inline uint32_t get_real_ip_body_len() const { return real_ip_body_len_; }

private:
    IPv4Address* ip_src_addr_{nullptr};
    IPv4Address* ip_dst_addr_{nullptr};
    uint16_t ip_header_len_{0};
    u_char ip_protocol_{0};
    u_char* ip_body_{nullptr};
    uint32_t ip_body_len_{0};
    uint32_t real_ip_body_len_{0};
};

}  // namespace net_io_top

#endif  // SRC_NETWORK_LAYER_IPV4_PACKET_H_
