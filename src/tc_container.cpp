#include <string.h>
#include <error.h>
#include <utility>
#include "common.h"
#include "log.h"
#include "tc_container.h"

namespace net_io_top {

TCContainer::~TCContainer() {
    stop();
    for (tcc_map::iterator it = conn_hash_.begin(); it != conn_hash_.end();) {
        TcpConnection* rm = (*it).second;
        tcc_map::iterator tmp = it;
        it++;
        conn_hash_.erase(tmp);
        delete rm;
    }
}

void TCContainer::stop() {
    pthread_mutex_lock(&state_mutex_);
    if (state_ != THREAD_STATE_RUNNING) {
        pthread_mutex_unlock(&state_mutex_);
        return;
    }
    state_ = THREAD_STATE_STOPPING;
    pthread_mutex_unlock(&state_mutex_);
    if (maint_thread_tid_ != 0) {
        pthread_join(maint_thread_tid_, nullptr);
    }
    state_ = THREAD_STATE_DONE;
}

int TCContainer::init() {
    state_ = THREAD_STATE_IDLE;
    pthread_mutex_init(&con_list_lock_, nullptr);
    pthread_mutex_init(&state_mutex_, nullptr);
    if (pthread_create(&maint_thread_tid_, nullptr, maint_thread_func, this) != 0) {
        LOG(ERROR) << "TCContainer::init failed, pthread_create err: " << strerror(errno);
        return -1;
    }
    state_ = THREAD_STATE_RUNNING;
    purge_flag_ = true;
    is_init_ = true;
    return 0;
}

int TCContainer::process_packet(const TcpCapture& p) {
    bool found = false;
    SocketPair sp(p.get_packet().get_src_addr(),
        p.get_packet().get_tcp_header().get_src_port(),
        p.get_packet().get_dst_addr(),
        p.get_packet().get_tcp_header().get_dst_port());
    pthread_mutex_lock(&con_list_lock_);
    // 判断这个包是不是已有连接
    std::pair<tcc_map::const_iterator, tcc_map::const_iterator> pr = conn_hash_.equal_range(sp);
    for (tcc_map::const_iterator it = pr.first; it != pr.second; it++) {
        TcpConnection* ic = (*it).second;
        if (ic->accept_packet(p)) {
            found = true;
        }
    }
    // 如果是一个新连接
    if (found == false
        && (p.get_packet().get_tcp_header().is_SYN())
        && !(p.get_packet().get_tcp_header().is_ACK())) {
        TcpConnection* new_conn = new TcpConnection(p);
        found = true;
        conn_hash_.insert(tcc_map::value_type(sp, new_conn));
    }
    // TODO(noahyzhang): 这是一个什么包
    pthread_mutex_unlock(&con_list_lock_);
    return found;
}

void TCContainer::maint_thread_run() {
    while (state_ == THREAD_STATE_RUNNING || state_ == THREAD_STATE_IDLE) {
        // 一秒运行一次
        struct timespec ts;
        ts.tv_sec = 1;
        ts.tv_nsec = 0;
        nanosleep(&ts, nullptr);
        pthread_mutex_lock(&con_list_lock_);
        for (tcc_map::iterator it = conn_hash_.begin(); it != conn_hash_.end();) {
            TcpConnection* ic = (*it).second;
            ic->re_calc_avg();
            // 删除已经关闭的、或过期的连接
            if (purge_flag_ == true) {
                if ((ic->is_finished() && ic->get_idle_seconds() > app->remto)
                    || (ic->get_state() == TCP_STATE_SYN_SYNACK && ic->get_idle_seconds() > SYN_SYNACK_WAIT)
                    || (ic->get_state() == TCP_STATE_FIN_FINACK && ic->get_idle_seconds() > FIN_FINACK_WAIT)) {
                    TcpConnection* rm = ic;
                    tcc_map::iterator tmp = it;
                    it++;
                    conn_hash_.erase(tmp);
                    delete rm;
                } else {
                    it++;
                }
            } else {
                it++;
            }
        }
        pthread_mutex_unlock(&con_list_lock_);
    }
}

void* TCContainer::maint_thread_func(void* arg) {
    TCContainer* tc = reinterpret_cast<TCContainer*>(arg);
    tc->maint_thread_run();
    return nullptr;
}

}  // namespace net_io_top
