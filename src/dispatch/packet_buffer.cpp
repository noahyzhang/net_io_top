#include <errno.h>
#include <string.h>
#include "common/log.h"
#include "common/common.h"
#include "dispatch/packet_buffer.h"

namespace net_io_top {

// 超过队列中存储超过 100 个包时进行处理
#define PACKET_MAX_COUNT_FOR_HANDLE 100
// 超过 1 秒即去处理队列中的包
#define PACKET_TIMEOUT_S_FOR_HANDLE 1

PacketBuffer::PacketBuffer() {
    in_queue_ = &queue1_;
    out_queue_ = &queue2_;
    pthread_mutex_init(&inq_lock_, nullptr);
    pthread_cond_init(&inq_flag_, nullptr);
}

PacketBuffer::~PacketBuffer() {
    if (pthread_initted_) {
        if (pthread_cancel(maint_thread_tid_) == 0) {
            pthread_join(maint_thread_tid_, nullptr);
        }
    }
}

int PacketBuffer::init(SocketConnHandler* container) {
    conn_handler_ = container;
    if (pthread_create(&maint_thread_tid_, nullptr, pb_maint_thread_func, this) != 0) {
        LOG(ERROR) << "pthread_create maint_thread_tid_ failed, errno: " << errno << ", err: " << strerror(errno);
        return -1;
    }
    pthread_setname_np(maint_thread_tid_, "net_io_pb");
    pthread_initted_ = true;
    return 0;
}

void PacketBuffer::push_packet(struct PacketData* packet) {
    if (packet == nullptr) {
        return;
    }
    pthread_mutex_lock(&inq_lock_);
    in_queue_->push(packet);
    if (++packet_count_ > PACKET_MAX_COUNT_FOR_HANDLE) {
        packet_count_ = 0;
        pthread_cond_signal(&inq_flag_);
    }
    pthread_mutex_unlock(&inq_lock_);
    return;
}

void PacketBuffer::maint_thread_run() {
    struct PacketData* packet = nullptr;
    struct timespec ts{PACKET_TIMEOUT_S_FOR_HANDLE, 0};
    for (;;) {
        pthread_mutex_lock(&inq_lock_);
        while (in_queue_->empty()) {
            pthread_cond_timedwait(&inq_flag_, &inq_lock_, &ts);
        }
        if (in_queue_ == &queue1_) {
            in_queue_ = &queue2_;
            out_queue_ = &queue1_;
        } else {
            in_queue_ = &queue1_;
            out_queue_ = &queue2_;
        }
        pthread_mutex_unlock(&inq_lock_);

        for (; !out_queue_->empty();) {
            packet = nullptr;
            packet = out_queue_->front();
            out_queue_->pop();
            if (conn_handler_ != nullptr) {
                TcpPacket* tcp_packet = TcpPacket::new_tcp_packet(packet->p_data, packet->len);
                TcpCapture cap(tcp_packet, packet->ts);
                conn_handler_->process_packet(cap);
            }
            free(packet->p_data);
            free(packet);
        }
    }
}

void* PacketBuffer::pb_maint_thread_func(void* arg) {
    PacketBuffer* pb_obj = reinterpret_cast<PacketBuffer*>(arg);
    pb_obj->maint_thread_run();
    return nullptr;
}

}  // namespace net_io_top
