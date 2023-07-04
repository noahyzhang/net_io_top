#include <time.h>
#include "tcp_connection.h"

namespace net_io_top {

TcpConnection::TcpConnection(const TcpCapture& p) {
    src_addr_ = p.get_packet().get_src_addr().clone();
    dst_addr_ = p.get_packet().get_dst_addr().clone();
    src_port_ = p.get_packet().get_tcp_header().get_src_port();
    dst_port_ = p.get_packet().get_tcp_header().get_dst_port();
    packet_count_ = 1;
    if (p.get_packet().get_tcp_header().is_SYN()) {
        state_ = TCP_STATE_SYN_SYNACK;
    } else {
        state_ = TCP_STATE_UP;
    }
    this_second_ = time(0);
    packets_this_second_ = 1;

    payload_bytes_this_second_ = p.get_packet().get_payload_len() - p.get_packet().get_tcp_header().get_header_len();
    all_bytes_this_second_ = p.get_packet().get_total_len();
    payload_bytes_last_second_ = 0;
    all_bytes_last_second_ = 0;

    payload_byte_count_ = p.get_packet().get_payload_len() - p.get_packet().get_tcp_header().get_header_len();

    last_pkt_ts_ = time(NULL);
    activity_toggle_ = false;

    fm_bps_ = 0;
    fin_ack_from_dst_ = 0;
    fin_ack_from_src_ = 0;
    recvd_fin_ack_from_src_ = false;
    recvd_fin_ack_from_dst_ = false;

    end_ptrs_ = new SocketPair(*src_addr_, src_port_, *dst_addr_, dst_port_);
}

TcpConnection::~TcpConnection() {
    delete src_addr_;
    delete dst_addr_;
    delete end_ptrs_;
}

bool TcpConnection::match(const IPAddress& sa, const IPAddress& da, uint16_t sp, uint16_t dp) const {
    if (!(*src_addr_ == sa)) {
        return false;
    }
    if (!(*dst_addr_ == da)) {
        return false;
    }
    if (dp != dst_port_ || sp != src_port_) {
        return false;
    }
    return true;
}

bool TcpConnection::accept_packet(const TcpCapture& cap) {
    TcpPacket* p = &(cap.get_packet());
    uint32_t payload_len = p->get_payload_len() - p->get_tcp_header().get_header_len();
    if (state_ == TCP_STATE_CLOSED) {
        return false;
    }
    if (match(p->get_src_addr(), p->get_dst_addr(),
        p->get_tcp_header().get_src_port(), p->get_tcp_header().get_dst_port())
        || match(p->get_dst_addr(), p->get_src_addr(),
        p->get_tcp_header().get_dst_port(), p->get_tcp_header().get_src_port())) {
        ++packet_count_;
        activity_toggle_ = true;
        update_counter_for_packet(cap);
        if (p->get_tcp_header().is_FIN()) {
            if (p->get_src_addr() == *src_addr_) {
                if (payload_len == 0) {
                    fin_ack_from_dst_ = p->get_tcp_header().get_seq() + 1;
                } else {
                    fin_ack_from_dst_ = p->get_tcp_header().get_seq() + payload_len + 1;
                }
                recvd_fin_ack_from_dst_ = false;
            }
            if (p->get_src_addr() == *dst_addr_) {
                if (payload_len == 0) {
                    fin_ack_from_src_ = p->get_tcp_header().get_seq() + 1;
                } else {
                    fin_ack_from_src_ = p->get_tcp_header().get_seq() + payload_len + 1;
                }
                recvd_fin_ack_from_src_ = false;
            }
        }
        if (state_ == TCP_STATE_SYNACK_ACK) {
            if (p->get_tcp_header().is_ACK()) {
                state_ = TCP_STATE_UP;
            }
        } else if (state_ == TCP_STATE_SYN_SYNACK) {
            if (p->get_tcp_header().is_SYN() && p->get_tcp_header().is_ACK()) {
                state_ = TCP_STATE_SYNACK_ACK;
            }
        } else if (state_ == TCP_STATE_UP) {
            if (p->get_tcp_header().is_FIN()) {
                state_ = TCP_STATE_FIN_FINACK;
            }
        } else if (state_ == TCP_STATE_FIN_FINACK) {
            if (p->get_tcp_header().is_ACK()) {
                if (p->get_src_addr() == *src_addr_) {
                    if (p->get_tcp_header().get_ack() == fin_ack_from_src_) {
                        recvd_fin_ack_from_src_ = true;
                    }
                } else if (p->get_src_addr() == *dst_addr_) {
                    if (p->get_tcp_header().get_ack() == fin_ack_from_dst_) {
                        recvd_fin_ack_from_dst_ = true;
                    }
                }
                if (recvd_fin_ack_from_src_ && recvd_fin_ack_from_dst_) {
                    state_ = TCP_STATE_CLOSED;
                }
            }
        }
        if (p->get_tcp_header().is_RST()) {
            state_ = TCP_STATE_RESET;
        }
        last_pkt_ts_ = time(nullptr);
        return true;
    }
    return false;
}

void TcpConnection::re_calc_avg() {
    if (this_second_ != time(0)) {
        packets_last_second_ = packets_this_second_;
        payload_bytes_last_second_ = payload_bytes_this_second_;
        all_bytes_last_second_ = all_bytes_this_second_;

        this_second_ = time(0);
        packets_this_second_ = 0;
        payload_bytes_this_second_ = 0;
        all_bytes_this_second_ = 0;
    }
}

void TcpConnection::update_counter_for_packet(const TcpCapture& p) {
    if (this_second_ != time(0)) {
        packets_last_second_ = packets_this_second_;
        payload_bytes_last_second_ = payload_bytes_this_second_;
        all_bytes_last_second_ = all_bytes_this_second_;

        this_second_ = time(0);
        packets_this_second_ = 1;
        payload_bytes_this_second_ =
            p.get_packet().get_payload_len() - p.get_packet().get_tcp_header().get_header_len();
        all_bytes_this_second_ = p.get_packet().get_total_len();
    } else {
        packets_this_second_++;
        payload_bytes_this_second_ +=
            p.get_packet().get_payload_len() - p.get_packet().get_tcp_header().get_header_len();
        all_bytes_this_second_ += p.get_packet().get_total_len();
    }
    payload_byte_count_ += p.get_packet().get_payload_len() - p.get_packet().get_tcp_header().get_header_len();
}

}  // namespace net_io_top
