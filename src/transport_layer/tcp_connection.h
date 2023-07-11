/**
 * @file tcp_connection.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-04
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TRANSPORT_LAYER_TCP_CONNECTION_H_
#define SRC_TRANSPORT_LAYER_TCP_CONNECTION_H_

#include <list>
#include <utility>
#include "transport_layer/connection.h"
#include "transport_layer/tcp_packet.h"

namespace net_io_top {

/**
 * @brief TCP 的连接
 * 
 */
class TcpConnection : public Connection {
public:
    explicit TcpConnection(const TcpPacket& tcp_packet) {
        src_addr_ = tcp_packet.get_src_addr().clone();
        dst_addr_ = tcp_packet.get_dst_addr().clone();
        src_port_ = tcp_packet.get_src_port();
        dst_port_ = tcp_packet.get_dst_port();
        all_packet_count_ = 1;
        all_packet_bytes_ = tcp_packet.get_tcp_header().get_tcp_packet_len();
        forward_packet_count_ = 1;
        forward_packet_bytes_ = tcp_packet.get_tcp_header().get_tcp_packet_len();
        last_period_packet_tm_s_ = time(NULL);
    }
    ~TcpConnection() {
        delete src_addr_;
        delete dst_addr_;
    }
    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;
    TcpConnection(TcpConnection&&) = delete;
    TcpConnection& operator=(TcpConnection&&) = delete;

public:
    inline TransportLayerProtocol get_protocol() const override {
        return TransportLayerProtocol::TRANSPORT_LAYER_PROTOCOL_TCP;
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

    inline time_t get_idle_time_s() const override { return time(NULL) - last_period_packet_tm_s_; }

public:
    int accept_packet(const TcpPacket& tcp_packet) {
        if ((tcp_packet.get_src_addr() == *src_addr_ && tcp_packet.get_src_port() == src_port_)
            && (tcp_packet.get_dst_addr() == *dst_addr_ && tcp_packet.get_dst_port() == dst_port_)) {
            forward_packet_count_ += 1;
            forward_packet_bytes_ += tcp_packet.get_tcp_header().get_tcp_packet_len();
            cur_period_forward_packet_count_ += 1;
            cur_period_forward_packet_bytes_ += tcp_packet.get_tcp_header().get_tcp_packet_len();

        } else if ((tcp_packet.get_src_addr() == *dst_addr_ && tcp_packet.get_src_port() == dst_port_)
            && (tcp_packet.get_dst_addr() == *src_addr_ && tcp_packet.get_dst_port() == src_port_)) {
            backward_packet_count_ += 1;
            backward_packet_bytes_ += tcp_packet.get_tcp_header().get_tcp_packet_len();
            cur_period_backward_packet_count_ += 1;
            cur_period_backward_packet_bytes_ += tcp_packet.get_tcp_header().get_tcp_packet_len();
        } else {
            return -1;
        }
        all_packet_count_ += 1;
        all_packet_bytes_ += tcp_packet.get_tcp_header().get_tcp_packet_len();
        last_period_packet_tm_s_ = time(NULL);
        return 0;
    }

private:
    // 源 IP 地址和目的 IP 地址
    IPAddress* src_addr_{nullptr};
    IPAddress* dst_addr_{nullptr};
    // 源端口和目的端口
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

    uint64_t last_period_packet_tm_s_{0};
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_TCP_CONNECTION_H_
