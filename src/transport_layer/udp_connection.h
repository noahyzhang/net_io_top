/**
 * @file udp_connection.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-10
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TRANSPORT_LAYER_UDP_CONNECTION_H_
#define SRC_TRANSPORT_LAYER_UDP_CONNECTION_H_

#include <stdint.h>
#include "transport_layer/udp_packet.h"
#include "transport_layer/connection.h"

namespace net_io_top {

class UdpConnection : public Connection {
public:
    explicit UdpConnection(const UdpPacket& udp_packet) {
        src_addr_ = udp_packet.get_src_addr().clone();
        dst_addr_ = udp_packet.get_dst_addr().clone();
        src_port_ = udp_packet.get_src_port();
        dst_port_ = udp_packet.get_dst_port();
        all_packet_count_ = 1;
        all_packet_bytes_ = udp_packet.get_udp_header().get_udp_packet_len();
        forward_packet_count_ = 1;
        forward_packet_bytes_ = udp_packet.get_udp_header().get_udp_packet_len();
        last_period_packet_tm_s_ = time(NULL);
    }
    ~UdpConnection() {
        delete src_addr_;
        delete dst_addr_;
    }

public:
    inline TransportLayerProtocol get_protocol() const override {
        return TransportLayerProtocol::TRANSPORT_LAYER_PROTOCOL_UDP; 
    }
    inline const IPAddress& get_src_addr() const override { return *src_addr_; }
    inline const IPAddress& get_dst_addr() const override { return *dst_addr_; }
    inline uint16_t get_src_port() const override { return src_port_; }
    inline uint16_t get_dst_port() const override { return dst_port_; }

    inline uint64_t get_all_packet_count() const override { return all_packet_count_; }
    inline uint64_t get_all_packet_bytes() const override { return all_packet_bytes_; }

    inline uint64_t get_forward_packet_count() const override { return forward_packet_count_; }
    inline uint64_t get_forward_packet_bytes() const override { return forward_packet_bytes_; }
    inline uint64_t get_backward_packet_count() const override { return backward_packet_count_; }
    inline uint64_t get_backward_packet_bytes() const override { return backward_packet_bytes_; }

    inline uint64_t get_cur_period_forward_packet_count() const override { return cur_period_forward_packet_count_; }
    inline uint64_t get_cur_period_forward_packet_bytes() const override { return cur_period_forward_packet_bytes_; }
    inline uint64_t get_cur_period_backward_packet_count() const override { return cur_period_backward_packet_count_; }
    inline uint64_t get_cur_period_backward_packet_bytes() const override { return cur_period_backward_packet_bytes_; }

    inline uint64_t exchange_cur_period_forward_packet_count(uint64_t val) override {
        std::swap(cur_period_forward_packet_count_, val);
        return val;
    }
    inline uint64_t exchange_cur_period_forward_packet_bytes(uint64_t val) override {
        std::swap(cur_period_forward_packet_bytes_, val);
        return val;
    }
    inline uint64_t exchange_cur_period_backward_packet_count(uint64_t val) override {
        std::swap(cur_period_backward_packet_count_, val);
        return val;
    }
    inline uint64_t exchange_cur_period_backward_packet_bytes(uint64_t val) override {
        std::swap(cur_period_backward_packet_bytes_, val);
        return val;
    }

    time_t get_idle_time_s() const override { return time(NULL) - last_period_packet_tm_s_; }

public:
    int accept_packet(const UdpPacket& udp_packet) {
        if ((udp_packet.get_src_addr() == *src_addr_ && udp_packet.get_src_port() == src_port_)
            && (udp_packet.get_dst_addr() == *dst_addr_ && udp_packet.get_dst_port() == dst_port_)) {
            forward_packet_count_ += 1;
            forward_packet_bytes_ += udp_packet.get_udp_header().get_udp_packet_len();
            cur_period_forward_packet_count_ += 1;
            cur_period_forward_packet_bytes_ += udp_packet.get_udp_header().get_udp_packet_len();

        } else if ((udp_packet.get_src_addr() == *dst_addr_ && udp_packet.get_src_port() == dst_port_)
            && (udp_packet.get_dst_addr() == *src_addr_ && udp_packet.get_dst_port() == src_port_)) {
            backward_packet_count_ += 1;
            backward_packet_bytes_ += udp_packet.get_udp_header().get_udp_packet_len();
            cur_period_backward_packet_count_ += 1;
            cur_period_backward_packet_bytes_ += udp_packet.get_udp_header().get_udp_packet_len();
        } else {
            return -1;
        }
        all_packet_count_ += 1;
        all_packet_bytes_ += udp_packet.get_udp_header().get_udp_packet_len();
        last_period_packet_tm_s_ = time(NULL);
        return 0;
    }

private:
    IPAddress* src_addr_{nullptr};
    IPAddress* dst_addr_{nullptr};
    uint16_t src_port_{0};
    uint16_t dst_port_{0};

    uint64_t all_packet_count_{0};
    uint64_t all_packet_bytes_{0};

    uint64_t forward_packet_count_{0};
    uint64_t forward_packet_bytes_{0};
    uint64_t cur_period_forward_packet_count_{0};
    uint64_t cur_period_forward_packet_bytes_{0};

    uint64_t backward_packet_count_{0};
    uint64_t backward_packet_bytes_{0};
    uint64_t cur_period_backward_packet_count_{0};
    uint64_t cur_period_backward_packet_bytes_{0};

    time_t last_period_packet_tm_s_{0};
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_UDP_CONNECTION_H_
