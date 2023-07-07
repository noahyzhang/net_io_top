#include <time.h>
#include "tcp_connection.h"

namespace net_io_top {

TcpConnection::TcpConnection(const TcpCapture& p) {
    src_addr_ = p.get_packet().get_src_addr().clone();
    dst_addr_ = p.get_packet().get_dst_addr().clone();
    src_port_ = p.get_packet().get_tcp_header().get_src_port();
    dst_port_ = p.get_packet().get_tcp_header().get_dst_port();
    if (p.get_packet().get_tcp_header().is_SYN()) {
        // 如果是 SYN 请求，等待 SYN&ACK 包
        state_ = TCP_STATE_SYN_SYNACK;
    } else {
        // 否则认为连接已经建立
        state_ = TCP_STATE_UP;
    }
    packet_count_ = 1;
    cur_period_tm_s_ = time(nullptr);
    cur_period_packet_count_ = 1;
    cur_period_tcp_payload_bytes_ = p.get_packet().get_payload_len() - p.get_packet().get_tcp_header().get_header_len();
    cur_period_all_bytes_ = p.get_packet().get_total_len();
    all_tcp_payload_bytes_ = p.get_packet().get_payload_len() - p.get_packet().get_tcp_header().get_header_len();

    last_pkt_ts_ = time(nullptr);

    fm_bps_ = 0;
    fin_ack_from_dst_ = 0;
    fin_ack_from_src_ = 0;
    recvd_fin_ack_from_src_ = false;
    recvd_fin_ack_from_dst_ = false;
}

TcpConnection::~TcpConnection() {
    delete src_addr_;
    delete dst_addr_;
}

bool TcpConnection::match(const IPAddress& sa, const IPAddress& da, uint16_t sp, uint16_t dp) const {
    if ((!(*src_addr_ == sa)) || (!(*dst_addr_ == da))) {
        return false;
    }
    if (dp != dst_port_ || sp != src_port_) {
        return false;
    }
    return true;
}

bool TcpConnection::accept_packet(const TcpCapture& t_cap) {
    // 如果是关闭 TCP 连接的报文，不处理
    if (state_ == TCP_STATE_CLOSED) {
        return false;
    }
    const TcpPacket& t_packet = t_cap.get_packet();
    // 获取到 tcp 报文的主体长度
    uint32_t tcp_payload_len = t_packet.get_payload_len() - t_packet.get_tcp_header().get_header_len();
    // 匹配是否是此条 tcp 连接
    if (match(t_packet.get_src_addr(), t_packet.get_dst_addr(),
        t_packet.get_tcp_header().get_src_port(), t_packet.get_tcp_header().get_dst_port())
        || match(t_packet.get_dst_addr(), t_packet.get_src_addr(),
        t_packet.get_tcp_header().get_dst_port(), t_packet.get_tcp_header().get_src_port())) {
        ++packet_count_;
        update_counter_for_packet(t_cap);
        // 此报文是 FIN 报文
        if (t_packet.get_tcp_header().is_FIN()) {
            // 确定是源报文还是目的报文
            if (t_packet.get_src_addr() == *src_addr_) {
                if (tcp_payload_len == 0) {
                    fin_ack_from_dst_ = t_packet.get_tcp_header().get_seq() + 1;
                } else {
                    fin_ack_from_dst_ = t_packet.get_tcp_header().get_seq() + tcp_payload_len + 1;
                }
                recvd_fin_ack_from_dst_ = false;
            } else if (t_packet.get_src_addr() == *dst_addr_) {
                if (tcp_payload_len == 0) {
                    fin_ack_from_src_ = t_packet.get_tcp_header().get_seq() + 1;
                } else {
                    fin_ack_from_src_ = t_packet.get_tcp_header().get_seq() + tcp_payload_len + 1;
                }
                recvd_fin_ack_from_src_ = false;
            }
        }
        // 根据报文的类型，确定连接的下一个状态
        if (state_ == TCP_STATE_SYNACK_ACK) {
            // 发送了 SYN&ACK 包，等待 ACK 包 ===> 连接已经建立
            if (t_packet.get_tcp_header().is_ACK()) {
                state_ = TCP_STATE_UP;
            }
        } else if (state_ == TCP_STATE_SYN_SYNACK) {
            // 发送了 SYN 包，等待 SYN&ACK 包 ===> 收到了 SYN&ACK 包，等待 ACK 包
            if (t_packet.get_tcp_header().is_SYN() && t_packet.get_tcp_header().is_ACK()) {
                state_ = TCP_STATE_SYNACK_ACK;
            }
        } else if (state_ == TCP_STATE_UP) {
            // 连接建立状态 ===> 发送了 FIN 包，等待 FIN&ACK 包
            if (t_packet.get_tcp_header().is_FIN()) {
                state_ = TCP_STATE_FIN_FINACK;
            }
        } else if (state_ == TCP_STATE_FIN_FINACK) {
            // 发送了 FIN 包，等待 FIN&ACK 包 ===> 收到了 ACK 包
            if (t_packet.get_tcp_header().is_ACK()) {
                if (t_packet.get_src_addr() == *src_addr_) {
                    if (t_packet.get_tcp_header().get_ack() == fin_ack_from_src_) {
                        recvd_fin_ack_from_src_ = true;
                    }
                } else if (t_packet.get_src_addr() == *dst_addr_) {
                    if (t_packet.get_tcp_header().get_ack() == fin_ack_from_dst_) {
                        recvd_fin_ack_from_dst_ = true;
                    }
                }
                if (recvd_fin_ack_from_src_ && recvd_fin_ack_from_dst_) {
                    state_ = TCP_STATE_CLOSED;
                }
            }
        }
        // 如果此报文要求重置
        if (t_packet.get_tcp_header().is_RST()) {
            state_ = TCP_STATE_RESET;
        }
        last_pkt_ts_ = time(nullptr);
        return true;
    }
    return false;
}

void TcpConnection::re_calc_avg() {
    if (cur_period_tm_s_ != time(0)) {
        last_period_packet_count_ = cur_period_packet_count_;
        last_period_tcp_payload_bytes_ = cur_period_tcp_payload_bytes_;
        last_period_all_bytes_ = cur_period_all_bytes_;

        cur_period_tm_s_ = time(0);
        cur_period_packet_count_ = 0;
        cur_period_tcp_payload_bytes_ = 0;
        cur_period_all_bytes_ = 0;
    }
}

void TcpConnection::update_counter_for_packet(const TcpCapture& t_cap) {
    time_t cur_time = time(nullptr);
    // 判断此数据包是否在当前周期（1秒）
    if (cur_period_tm_s_ != cur_time) {
        // 更新上一周期
        last_period_packet_count_ = cur_period_packet_count_;
        last_period_tcp_payload_bytes_ = cur_period_tcp_payload_bytes_;
        last_period_all_bytes_ = cur_period_all_bytes_;
        // 当前周期
        cur_period_tm_s_ = cur_time;
        cur_period_packet_count_ = 1;
        cur_period_tcp_payload_bytes_ =
            t_cap.get_packet().get_payload_len() - t_cap.get_packet().get_tcp_header().get_header_len();
        cur_period_all_bytes_ = t_cap.get_packet().get_total_len();
    } else {
        cur_period_packet_count_++;
        cur_period_tcp_payload_bytes_ +=
            t_cap.get_packet().get_payload_len() - t_cap.get_packet().get_tcp_header().get_header_len();
        cur_period_all_bytes_ += t_cap.get_packet().get_total_len();
    }
    all_tcp_payload_bytes_ +=
        t_cap.get_packet().get_payload_len() - t_cap.get_packet().get_tcp_header().get_header_len();
}

}  // namespace net_io_top
