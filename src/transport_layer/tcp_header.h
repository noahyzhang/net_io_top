/**
 * @file tcp_header.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-30
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TCP_HEADER_H_
#define SRC_TCP_HEADER_H_

#include <stdint.h>
#include <netinet/in.h>
#include "common/headers.h"

namespace net_io_top {

const uint8_t FIN = 0x01;  // 该报文段的发送方已经结束向对方发送数据
const uint8_t SYN = 0x02;  // 用于初始化一个连接的同步序列号
const uint8_t RST = 0x04;  // 重置连接（连接取消，经常时因为错误）
const uint8_t PSH = 0x08;  // 推送（接收方应尽快给应用程序传送这个数据，该字段没被可靠地实现或用到）
const uint8_t ACK = 0x10;  // 确认（ACK Number 字段有效，连接建立以后一般都是启用状态）
const uint8_t URG = 0x20;  // 紧急（紧急指针字段有效，很少被使用）
const uint8_t ECE = 0x40;  // ECN 回显（发送方接收到了一个更早的拥塞通告）
const uint8_t CWR = 0x80;  // 拥塞窗口减少（发送方降低它的发送速率）

/**
 * @brief TCP 的头部
 * 
 */
class TcpHeader {
public:
    TcpHeader(const u_char* data, uint32_t data_len) {
        // 先保留
        (void)(data_len);
        struct sniff_tcp* tcp = (struct sniff_tcp*)data;
        // tcp header 至少 20 字节
        // 构造函数中暂不做判断，假定此 tcp 报文没有问题
        // tcp->th_off >= 5;
        src_port_ = ntohs(tcp->th_sport);
        dst_port_ = ntohs(tcp->th_dport);
        seq_num_ = ntohl(tcp->th_seq);
        ack_num_ = ntohl(tcp->th_ack);
        flags_ = tcp->th_flags;
        header_len_ = tcp->th_off * 4;
    }
    ~TcpHeader() = default;
    TcpHeader(const TcpHeader&) = default;
    TcpHeader& operator=(const TcpHeader&) = default;
    TcpHeader(TcpHeader&&) = delete;
    TcpHeader& operator=(TcpHeader&&) = delete;

public:
    bool is_FIN() const { return flags_ & FIN; }
    bool is_SYN() const { return flags_ & SYN; }
    bool is_RST() const { return flags_ & RST; }
    bool is_PSH() const { return flags_ & PSH; }
    bool is_ACK() const { return flags_ & ACK; }
    bool is_URG() const { return flags_ & URG; }
    bool is_ECE() const { return flags_ & ECE; }
    bool is_CWR() const { return flags_ & CWR; }

    uint32_t get_seq() const { return seq_num_; }
    uint32_t get_ack() const { return ack_num_; }
    uint16_t get_src_port() const { return src_port_; }
    uint16_t get_dst_port() const { return dst_port_; }
    uint16_t get_header_len() const { return header_len_; }

private:
    // tcp 报头顺序号
    uint32_t seq_num_{0};
    // tcp 报头确认号
    uint32_t ack_num_{0};
    // tcp 报头源端口号
    uint16_t src_port_{0};
    // tcp 报头目的端口号
    uint16_t dst_port_{0};
    // tcp 报头的标志位
    char flags_{0};
    // tcp 报头的长度（数据偏移*4）
    uint16_t header_len_{0};
};

}  // namespace net_io_top

#endif  // SRC_TCP_HEADER_H_
