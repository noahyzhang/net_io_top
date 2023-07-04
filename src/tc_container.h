/**
 * @file tc_container.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-30
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TC_CONTAINER_H_
#define SRC_TC_CONTAINER_H_

#include <functional>
#include <hash_map>
#include "tcp_connection.h"
#include "tcp_capture.h"

namespace net_io_top {

enum thread_state_type {
    THREAD_STATE_IDLE = 1,
    THREAD_STATE_RUNNING = 2,
    THREAD_STATE_STOPPING = 3,
    THREAD_STATE_DONE = 4
};

class TCCEqFunc : public std::unary_function<SocketPair, bool> {
public:
    bool operator()(const SocketPair& sp1, const SocketPair& sp2) {
        if (sp1 == sp2) {
            return true;
        } else {
            return false;
        }
    }
};

class TCCHashFunc : public std::unary_function<SocketPair, uint32_t> {
public:
    uint32_t operator()(const SocketPair& sp) const {
        return sp.hash();
    }
};

typedef __gnu_cxx::hash_map<SocketPair, TcpConnection*, TCCHashFunc, TCCEqFunc> tcc_map;

class TCContainer {
public:
    TCContainer() = default;
    ~TCContainer();

public:
    int init();
    int process_packet(const TcpCapture& p);
    uint32_t get_connection_num();
    void maint_thread_run();
    void purge(bool purge_flag);

private:
    void stop();

private:
    static void* maint_thread_func(void* arg);

private:
    tcc_map conn_hash_;
    pthread_mutex_t con_list_lock_;

    pthread_t maint_thread_tid_{0};
    bool run_maint_thread_{false};

    thread_state_type state_{THREAD_STATE_IDLE};
    pthread_mutex_t state_mutex_;
    bool purge_flag_{false};
    bool is_init_{false};
};

}  // namespace net_io_top

#endif  // SRC_TC_CONTAINER_H_
