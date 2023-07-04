/**
 * @file packet_buffer.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-29
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_PACKET_BUFFER_H_
#define SRC_PACKET_BUFFER_H_

#include <pthread.h>
#include <queue>
#include "utils.h"
#include "tc_container.h"

namespace net_io_top {

class PacketBuffer {
public:
    PacketBuffer();
    ~PacketBuffer();

public:
    int init();
    void push_packet(struct nlp*);
    void maint_thread_run();

public:
    static void* pb_maint_thread_func(void*);

private:
    pthread_t maint_thread_tid_{0};
    bool pthread_initted_{false};

    pthread_mutex_t inq_lock_;
    pthread_cond_t inq_flag_;
    std::queue<struct nlp*> queue1_;
    std::queue<struct nlp*> queue2_;
    std::queue<struct nlp*>* in_queue_{nullptr};
    std::queue<struct nlp*>* out_queue_{nullptr};

    TCContainer* container_;
    pthread_mutex_t container_lock_;
};

}  // namespace net_io_top

#endif  // SRC_PACKET_BUFFER_H_
