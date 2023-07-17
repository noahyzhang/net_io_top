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
#include "common/log.h"

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
        all_packet_bytes_ = tcp_packet.get_tcp_header().get_tcp_packet_len()
            + DLT_EN10MB_HEADER_LEN + IP_HEADER_LEN;
        last_period_forward_packet_count_ = 1;
        last_period_forward_packet_bytes_ = tcp_packet.get_tcp_header().get_tcp_packet_len()
            + DLT_EN10MB_HEADER_LEN + IP_HEADER_LEN;
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

    inline uint64_t get_forward_packet_count() const override { return last_period_forward_packet_count_; }
    inline uint64_t get_forward_packet_bytes() const override { return last_period_forward_packet_bytes_; }
    inline uint64_t get_backward_packet_count() const override { return last_period_backward_packet_count_; }
    inline uint64_t get_backward_packet_bytes() const override { return last_period_backward_packet_bytes_; }

    inline time_t get_idle_time_s() const override { return time(NULL) - last_period_packet_tm_s_; }

    void re_calc_period_value() override {
        last_period_backward_packet_count_ = cur_period_backward_packet_count_;
        last_period_backward_packet_bytes_ = cur_period_backward_packet_bytes_;
        last_period_forward_packet_count_ = cur_period_forward_packet_count_;
        last_period_forward_packet_bytes_ = cur_period_forward_packet_bytes_;
        cur_period_backward_packet_count_ = cur_period_backward_packet_bytes_ = 0;
        cur_period_forward_packet_count_ = cur_period_forward_packet_bytes_ = 0;
    }

public:
    int accept_packet(const TcpPacket& tcp_packet) {
        if ((tcp_packet.get_src_addr() == *src_addr_ && tcp_packet.get_src_port() == src_port_)
            && (tcp_packet.get_dst_addr() == *dst_addr_ && tcp_packet.get_dst_port() == dst_port_)) {
            cur_period_forward_packet_count_ += 1;
            // 在这里直接加上链路层和网络层的头部大小，不优雅的实现，后续需要改进
            cur_period_forward_packet_bytes_ += tcp_packet.get_tcp_header().get_tcp_packet_len()
                + DLT_EN10MB_HEADER_LEN + IP_HEADER_LEN;
            // LOG(DEBUG) << "accept forward tcp packet, src: " << src_addr_->ptr() << ":" << src_port_
            //     << ", dst: " << dst_addr_->ptr() << ":" << dst_port_
            //     << ", count: " << cur_period_forward_packet_count_
            //     << ", bytes: " << tcp_packet.get_tcp_header().get_tcp_packet_len()
            //         + DLT_EN10MB_HEADER_LEN + IP_HEADER_LEN;

        } else if ((tcp_packet.get_src_addr() == *dst_addr_ && tcp_packet.get_src_port() == dst_port_)
            && (tcp_packet.get_dst_addr() == *src_addr_ && tcp_packet.get_dst_port() == src_port_)) {
            cur_period_backward_packet_count_ += 1;
            // 在这里直接加上链路层和网络层的头部大小，不优雅的实现，后续需要改进
            cur_period_backward_packet_bytes_ += tcp_packet.get_tcp_header().get_tcp_packet_len()
                + DLT_EN10MB_HEADER_LEN + IP_HEADER_LEN;
            // LOG(DEBUG) << "accept backward tcp packet, src: " << src_addr_->ptr() << ":" << src_port_
            //     << ", dst: " << dst_addr_->ptr() << ":" << dst_port_
            //     << ", count: " << cur_period_backward_packet_count_
            //     << ", bytes: " << tcp_packet.get_tcp_header().get_tcp_packet_len()
            //         + DLT_EN10MB_HEADER_LEN + IP_HEADER_LEN;
        } else {
            LOG(ERROR) << "packet not belong to same ip or port";
            return -1;
        }
        all_packet_count_ += 1;
        all_packet_bytes_ += tcp_packet.get_tcp_header().get_tcp_packet_len() + DLT_EN10MB_HEADER_LEN + IP_HEADER_LEN;
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

    uint64_t last_period_forward_packet_count_{0};
    uint64_t last_period_forward_packet_bytes_{0};
    uint64_t last_period_backward_packet_count_{0};
    uint64_t last_period_backward_packet_bytes_{0};

    uint64_t cur_period_forward_packet_count_{0};
    uint64_t cur_period_forward_packet_bytes_{0};
    uint64_t cur_period_backward_packet_count_{0};
    uint64_t cur_period_backward_packet_bytes_{0};

    uint64_t last_period_packet_tm_s_{0};
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_TCP_CONNECTION_H_
