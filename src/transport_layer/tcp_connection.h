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

#ifndef SRC_TCP_CONNECTION_H_
#define SRC_TCP_CONNECTION_H_

#include <list>
#include "transport_layer/tcp_capture.h"

namespace net_io_top {

enum TCP_STATE_TYPE {
    // 三次握手的状态
    // 初始化状态，发送了 SYN 包，等待 SYN&ACK 包
    TCP_STATE_SYN_SYNACK = 1,
    // 已经收到 SYN&ACK 包，等待 ACK 包
    TCP_STATE_SYNACK_ACK = 2,
    // 已经发送 ACK 包，连接已经建立
    TCP_STATE_UP = 3,
    // 四次挥手的状态
    // 发送了 FIN 包，等待 FIN&ACK 包
    TCP_STATE_FIN_FINACK = 4,
    // 进入了 CLOSED 状态
    TCP_STATE_CLOSED = 5,
    // 进入了 RESET 状态
    TCP_STATE_RESET = 6
};

struct avg_stat {
    struct timeval ts;
    uint32_t size;
};

/**
 * @brief TCP 的连接
 * 
 */
class TcpConnection {
public:
    explicit TcpConnection(const TcpCapture& p);
    ~TcpConnection();
    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;
    TcpConnection(TcpConnection&&) = delete;
    TcpConnection& operator=(TcpConnection&&) = delete;

public:
    IPAddress& get_src_addr() const { return *src_addr_; }
    uint16_t get_src_port() { return src_port_; }
    IPAddress& get_dst_addr() { return *dst_addr_;}
    uint16_t get_dst_port() { return dst_port_; }

    int get_packet_count() { return packet_count_; }
    int64_t get_all_tcp_payload_bytes() { return all_tcp_payload_bytes_; }
    TCP_STATE_TYPE get_state() { return state_; }

    uint32_t get_cur_period_tcp_payload_bytes() { return cur_period_tcp_payload_bytes_; }
    int get_cur_period_all_bytes() { return cur_period_all_bytes_; }

    time_t get_cur_pkt_timestamp() { return cur_pkt_ts_; }
    time_t get_idle_seconds() { return time(NULL) - get_cur_pkt_timestamp(); }

    uint64_t get_last_period_packet_count() { return last_period_packet_count_; }
    uint64_t get_last_period_tcp_payload_bytes() { return last_period_tcp_payload_bytes_; }
    uint64_t get_last_period_all_bytes() { return last_period_all_bytes_; }

    bool is_finished() {
        if (state_ == TCP_STATE_CLOSED || state_ == TCP_STATE_RESET) {
            return true;
        }
        return false;
    }

public:
    bool match(const IPAddress& sa, const IPAddress& da, uint16_t sp, uint16_t dp) const;

    /**
     * @brief 处理 TCP 数据包
     * 
     * @param cap 
     * @return true 
     * @return false 
     */
    bool accept_packet(const TcpCapture& cap);
    void re_calc_avg();

private:
    void update_counter_for_packet(const TcpCapture& p);

private:
    // 来自于目的端的 FIN&ACK 的报文序号
    uint64_t fin_ack_from_dst_{0};
    // 来自于源端的 FIN&ACK 的报文序号
    uint64_t fin_ack_from_src_{0};
    // 接收到来自于源端的 FIN&ACK 报文
    bool recvd_fin_ack_from_src_{false};
    // 接收到来自于目的端的 FIN&ACK 报文
    bool recvd_fin_ack_from_dst_{false};


    // 源端口和目的端口
    uint16_t src_port_{0};
    uint16_t dst_port_{0};
    // 源 IP 地址和目的 IP 地址
    IPAddress* src_addr_{nullptr};
    IPAddress* dst_addr_{nullptr};

    // 当前报文 TCP 的状态
    TCP_STATE_TYPE state_;

    // 当前报文的时间戳
    time_t cur_pkt_ts_{0};
    // 此条 TCP 连接的报文数量
    uint64_t packet_count_{0};

    // 此连接的 TCP 报文(不包括 TCP 头)总字节数
    uint64_t all_tcp_payload_bytes_{0};

    // 当前周期的时间节点（周期 = 1秒）
    time_t cur_period_tm_s_{0};
    // 当前周期的数据包数量
    uint64_t cur_period_packet_count_{0};
    // 当前周期的 TCP 报文总字节数(不包括 TCP 头)
    uint64_t cur_period_tcp_payload_bytes_{0};
    // 当前周期的数据包总字节数(从 IP 头算起)
    uint64_t cur_period_all_bytes_{0};
    // 上一周期的数据包数量
    uint64_t last_period_packet_count_{0};
    // 上一周期的 TCP 报文总字节数(不包括 TCP 头)
    uint64_t last_period_tcp_payload_bytes_{0};
    // 上一周期的数据包总字节数(从 IP 头算起)
    uint64_t last_period_all_bytes_{0};
};

}  // namespace net_io_top

#endif  // SRC_TCP_CONNECTION_H_
