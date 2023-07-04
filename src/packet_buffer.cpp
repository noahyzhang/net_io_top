#include <errno.h>
#include <string.h>
#include "log.h"
#include "packet_buffer.h"

namespace net_io_top {

PacketBuffer::PacketBuffer() {

}

PacketBuffer::~PacketBuffer() {
    if (pthread_initted_) {
        if (pthread_cancel(maint_thread_tid_) == 0) {
            pthread_join(maint_thread_tid_, nullptr);
        }
    }
}

int PacketBuffer::init() {
    if (pthread_create(&maint_thread_tid_, nullptr, pb_maint_thread_func, this) != 0) {
        LOG(ERROR) << "pthread_create maint_thread_tid_ failed, errno: " << errno << ", err: " << strerror(errno);
        return -1;
    }
    pthread_initted_ = true;
    return 0;
}

void PacketBuffer::push_packet(struct nlp* nlp) {
    if (nlp == nullptr) {
        return;
    }
    pthread_mutex_lock(&inq_lock_);
    in_queue_->push(nlp);
    pthread_cond_signal(&inq_flag_);
    pthread_mutex_unlock(&inq_lock_);
    return;
}

void PacketBuffer::maint_thread_run() {
    struct nlp* nlp;
    for (;;) {
        pthread_mutex_lock(&inq_lock_);
        if (in_queue_->empty()) {
            pthread_cond_wait(&inq_flag_, &inq_lock_);
        }
        if (in_queue_ == &queue1_) {
            in_queue_ = &queue2_;
            out_queue_ = &queue1_;
        } else {
            in_queue_ = &queue1_;
            out_queue_ = &queue2_;
        }
        pthread_mutex_unlock(&inq_lock_);

        nlp = nullptr;
        for (; !out_queue_->empty();) {
            nlp = nullptr;
            nlp = out_queue_->front();
            pthread_mutex_lock(&container_lock_);
            if (container_ != nullptr) {
                TcpPacket* tcp_packet = TcpPacket::new_tcp_packet(nlp->p, nlp->len);
                TcpCapture cap(tcp_packet, nlp->ts);
                container_->process_packet(cap);
            }
            pthread_mutex_unlock(&container_lock_);
            free(nlp->p);
            free(nlp);
            out_queue_->pop();
        }
    }
}

void* PacketBuffer::pb_maint_thread_func(void* arg) {
    PacketBuffer* pb_obj = reinterpret_cast<PacketBuffer*>(arg);
    pb_obj->maint_thread_run();
    return nullptr;
}

}  // namespace net_io_top
