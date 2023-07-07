#include <string.h>
#include <error.h>
#include <utility>
#include <algorithm>
#include "config.h"
#include "common.h"
#include "log.h"
#include "socket_conn_handler.h"

namespace net_io_top {

SocketConnHandler::SocketConnHandler() {
    pthread_mutex_init(&conn_hash_lock_, nullptr);
}

SocketConnHandler::~SocketConnHandler() {
    for (auto it = conn_hash_.begin(); it != conn_hash_.end(); ++it) {
        TcpConnection* rm = (*it).second;
        delete rm;
    }
    conn_hash_.clear();
}

int SocketConnHandler::process_packet(const TcpCapture& t_cap) {
    bool found = false;
    SocketPair sp(t_cap.get_packet().get_src_addr(),
        t_cap.get_packet().get_tcp_header().get_src_port(),
        t_cap.get_packet().get_dst_addr(),
        t_cap.get_packet().get_tcp_header().get_dst_port());
    pthread_mutex_lock(&conn_hash_lock_);
    // 判断这个包是不是已有连接
    auto iter = conn_hash_.find(sp);
    if (iter != conn_hash_.end()) {
        LOG(DEBUG) << "capture packet, src: " << t_cap.get_packet().get_src_addr().ptr()
            << ", dst:" << t_cap.get_packet().get_dst_addr().ptr();
        if (iter->second->accept_packet(t_cap)) {
            found = true;
        }
    }
    // 如果是一个新连接
    if (found == false
        && (t_cap.get_packet().get_tcp_header().is_SYN())
        && !(t_cap.get_packet().get_tcp_header().is_ACK())) {
        TcpConnection* new_conn = new TcpConnection(t_cap);
        conn_hash_.emplace(sp, new_conn);
        LOG(DEBUG) << "receive new connection, src: "
            << new_conn->get_src_addr().ptr() << ":" << new_conn->get_src_port()
            << ", dst: " << new_conn->get_dst_addr().ptr() << ":" << new_conn->get_dst_port();
    }
    // TODO(noahyzhang): 走到这里，这是一个什么包？
    pthread_mutex_unlock(&conn_hash_lock_);
    return 0;
}

std::vector<TcpConnection*> SocketConnHandler::get_sorted_conns() {
    std::vector<TcpConnection*> sorted_conns(conn_hash_.size(), nullptr);
    // 在锁内，先移除过期的连接，然后放入数组容器中
    pthread_mutex_lock(&conn_hash_lock_);
    remove_overdue_conn();
    for (auto it = conn_hash_.begin(); it != conn_hash_.end(); ++it) {
        sorted_conns.push_back(it->second);
    }
    pthread_mutex_unlock(&conn_hash_lock_);
    // 排序
    std::sort(sorted_conns.begin(), sorted_conns.end(),
        [](TcpConnection* c1, TcpConnection* c2) ->bool {
        if (c1->get_payload_bytes_per_second() > c2->get_payload_bytes_per_second()) {
            return false;
        } else {
            return true;
        }
    });
    return sorted_conns;
}

void SocketConnHandler::remove_overdue_conn() {
    for (auto it = conn_hash_.begin(); it != conn_hash_.end();) {
        TcpConnection* t_conn = (*it).second;
        t_conn->re_calc_avg();
        // 删除已经关闭的、或过期的连接
        if ((t_conn->is_finished()
            && t_conn->get_idle_seconds() > Config::get_instance().get_conn_closed_timeout_s())
            || (t_conn->get_state() == TCP_STATE_SYN_SYNACK && t_conn->get_idle_seconds() > SYN_SYNACK_WAIT)
            || (t_conn->get_state() == TCP_STATE_FIN_FINACK && t_conn->get_idle_seconds() > FIN_FINACK_WAIT)) {
            delete t_conn;
            it = conn_hash_.erase(it);
        } else {
            it++;
        }
    }
}

}  // namespace net_io_top
