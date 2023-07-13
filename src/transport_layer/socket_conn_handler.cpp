#include <string.h>
#include <error.h>
#include <utility>
#include <algorithm>
#include "common/common.h"
#include "common/config.h"
#include "network_layer/ipv4_packet.h"
#include "common/log.h"
#include "transport_layer/socket_conn_handler.h"

namespace net_io_top {

SocketConnHandler::SocketConnHandler() {
    pthread_mutex_init(&conn_hash_lock_, nullptr);
}

SocketConnHandler::~SocketConnHandler() {
    for (auto it = conn_hash_.begin(); it != conn_hash_.end(); ++it) {
        Connection* rm = (*it).second;
        delete rm;
    }
    conn_hash_.clear();
}

int SocketConnHandler::process_packet(const IPv4Packet& ip_packet) {
    if (ip_packet.get_ip_protocol() == IPPROTO_TCP) {
        TcpPacket tcp_packet(
            ip_packet.get_ip_src_addr(), ip_packet.get_ip_dst_addr(),
            ip_packet.get_ip_body(), ip_packet.get_ip_body_len());
        return process_tcp_packet(tcp_packet);
    } else if (ip_packet.get_ip_protocol() == IPPROTO_UDP) {
        UdpPacket udp_packet(
            ip_packet.get_ip_src_addr(), ip_packet.get_ip_dst_addr(),
            ip_packet.get_ip_body(), ip_packet.get_ip_body_len());
        return process_udp_packet(udp_packet);
    } else {
        LOG(ERROR) << "just support TCP/UDP protocol";
        return -1;
    }
    return 0;
}

int SocketConnHandler::process_tcp_packet(const TcpPacket& tcp_packet) {
    bool found = false;
    SocketPair sp(
        TransportLayerProtocol::TRANSPORT_LAYER_PROTOCOL_TCP,
        tcp_packet.get_src_addr(),
        tcp_packet.get_src_port(),
        tcp_packet.get_dst_addr(),
        tcp_packet.get_dst_port());
    pthread_mutex_lock(&conn_hash_lock_);
    // 判断这个包是不是已有连接
    auto iter = conn_hash_.find(sp);
    if (iter != conn_hash_.end()) {
        Connection* conn = iter->second;
        if (conn->get_protocol() == TransportLayerProtocol::TRANSPORT_LAYER_PROTOCOL_TCP) {
            if ((reinterpret_cast<TcpConnection*>(conn))->accept_packet(tcp_packet) == 0) {
                found = true;
            }
        }
    }
    // 如果是一个新连接
    // 这里不应该去判断这个包的状态，因为可能不能监控到一条连接的全程，也许是是连接开始后才去监控的
    // if (found == false
    //     && (tcp_packet.get_tcp_header().is_SYN())
    //     && !(tcp_packet.get_tcp_header().is_ACK())) {
    if (found == false) {
        TcpConnection* new_conn = new TcpConnection(tcp_packet);
        conn_hash_.emplace(sp, new_conn);
        LOG(DEBUG) << "receive new tcp connection, src: "
            << new_conn->get_src_addr().ptr() << ":" << new_conn->get_src_port()
            << ", dst: " << new_conn->get_dst_addr().ptr() << ":" << new_conn->get_dst_port();
    }
    // 走到这里，说明之前没有拿到这个连接，先丢弃吧
    pthread_mutex_unlock(&conn_hash_lock_);
    return 0;
}

int SocketConnHandler::process_udp_packet(const UdpPacket& udp_packet) {
    bool found = false;
    SocketPair sp(
        TransportLayerProtocol::TRANSPORT_LAYER_PROTOCOL_UDP,
        udp_packet.get_src_addr(),
        udp_packet.get_src_port(),
        udp_packet.get_dst_addr(),
        udp_packet.get_dst_port());
    pthread_mutex_lock(&conn_hash_lock_);
    // 判断这个包是不是已有连接
    auto iter = conn_hash_.find(sp);
    if (iter != conn_hash_.end()) {
        Connection* conn = iter->second;
        if (conn->get_protocol() == TransportLayerProtocol::TRANSPORT_LAYER_PROTOCOL_UDP) {
            if ((reinterpret_cast<UdpConnection*>(conn))->accept_packet(udp_packet) == 0) {
                found = true;
            }
        }
    }
    // 如果是一个新连接
    if (found == false) {
        UdpConnection* new_conn = new UdpConnection(udp_packet);
        conn_hash_.emplace(sp, new_conn);
        LOG(DEBUG) << "receive new udp connection, src: "
            << new_conn->get_src_addr().ptr() << ":" << new_conn->get_src_port()
            << ", dst: " << new_conn->get_dst_addr().ptr() << ":" << new_conn->get_dst_port();
    }
    pthread_mutex_unlock(&conn_hash_lock_);
    return 0;
}

std::vector<Connection*> SocketConnHandler::get_sorted_conns() {
    std::vector<Connection*> sorted_conns;
    // 在锁内，先移除过期的连接，然后放入数组容器中
    pthread_mutex_lock(&conn_hash_lock_);
    remove_overdue_conn();
    for (auto it = conn_hash_.begin(); it != conn_hash_.end(); ++it) {
        it->second->re_calc_period_value();
        sorted_conns.emplace_back(it->second);
    }
    pthread_mutex_unlock(&conn_hash_lock_);
    // 排序
    std::sort(sorted_conns.begin(), sorted_conns.end(),
        [](Connection* c1, Connection* c2) ->bool {
        if ((c1->get_backward_packet_bytes() + c1->get_forward_packet_bytes())
            > (c2->get_backward_packet_bytes() + c2->get_forward_packet_bytes())) {
            return false;
        } else {
            return true;
        }
    });
    return sorted_conns;
}

void SocketConnHandler::remove_overdue_conn() {
    // 目前对于已经关闭的、过期的连接，仅仅使用这条连接上的空闲时间来判断
    // 暂时没有做比如对于 TCP 的状态检测，因此连接超级多的时候，可能存储连接的哈希表会大一点，占用内存多一点
    for (auto it = conn_hash_.begin(); it != conn_hash_.end();) {
        Connection* conn = (*it).second;
        // 删除已经关闭的、或过期的连接
        if (static_cast<uint64_t>(conn->get_idle_time_s())
            > Config::get_instance().get_conn_closed_timeout_s()) {
            delete conn;
            it = conn_hash_.erase(it);
        } else {
            it++;
        }
    }
}

}  // namespace net_io_top
