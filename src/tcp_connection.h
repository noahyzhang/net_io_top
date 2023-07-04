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
#include "tcp_capture.h"

namespace net_io_top {

enum TCP_STATE_TYPE {
    TCP_STATE_SYN_SYNACK = 1,
    TCP_STATE_SYNACK_ACK = 2,
    TCP_STATE_UP = 3,
    TCP_STATE_FIN_FINACK = 4,
    TCP_STATE_CLOSED = 5,
    TCP_STATE_RESET = 6
};

struct avg_stat {
    struct timeval ts;
    uint32_t size;
};

class TcpConnection {
public:
    explicit TcpConnection(const TcpCapture& p);
    ~TcpConnection();

public:
    IPAddress& get_src_addr() { return *src_addr_; }
    uint16_t get_src_port() { return src_port_; }
    IPAddress& get_dst_addr() { return *dst_addr_;}
    uint16_t get_dst_port() { return dst_port_; }

    int get_packet_count() { return packet_count_; }
    int64_t get_payload_byte_count() { return payload_byte_count_; }
    TCP_STATE_TYPE get_state() { return state_; }
    SocketPair& get_end_points() { return *end_ptrs_; }

    time_t get_last_pkt_timestamp() { return last_pkt_ts_; }
    time_t get_idle_seconds() { return time(NULL) - get_last_pkt_timestamp(); }

    bool is_finished() {
        if (state_ == TCP_STATE_CLOSED || state_ == TCP_STATE_RESET) {
            return true;
        }
        return false;
    }

    bool match(const IPAddress& sa, const IPAddress& da, uint16_t sp, uint16_t dp) const;
    bool accept_packet(const TcpCapture& cap);

    void re_calc_avg();

    bool is_activity_toggle();

    int get_packets_per_second() {

    }
    uint32_t get_payload_bytes_per_second();
    int get_all_bytes_per_second();

private:
    uint64_t fin_ack_from_dst_;
    uint64_t fin_ack_from_src_;
    bool recvd_fin_ack_from_src_;
    bool recvd_fin_ack_from_dst_;

    SocketPair* end_ptrs_;
    uint16_t src_port_;
    uint16_t dst_port_;
    IPAddress* src_addr_;
    IPAddress* dst_addr_;

    TCP_STATE_TYPE state_;
    time_t last_pkt_ts_;
    int packet_count_;

    int64_t payload_byte_count_;
    bool activity_toggle_;
    std::list<struct avg_stat> avg_stack_;
    uint32_t fm_bps_;
    uint32_t fm_pps_;

    time_t this_second_;
    uint32_t packets_this_second_;
    uint32_t payload_bytes_this_second_;
    uint32_t all_bytes_this_second_;
    uint32_t packets_last_second_;
    uint32_t payload_bytes_last_second_;
    uint32_t all_bytes_last_second_;
};

}  // namespace net_io_top

#endif  // SRC_TCP_CONNECTION_H_
