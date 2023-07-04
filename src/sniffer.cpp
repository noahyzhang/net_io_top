#include <string.h>
#include <errno.h>
#include "common.h"
#include "log.h"
#include "utils.h"
#include "sniffer.h"

namespace net_io_top {

Sniffer::Sniffer() {
    pthread_mutex_init(&pb_mutex_, NULL);
}

Sniffer::~Sniffer() {
    if (pthread_initted_) {
        if (pthread_cancel(sniffer_tid_) == 0) {
            pthread_join(sniffer_tid_, NULL);
        }
    }
    if (pcap_initted_) {
        pcap_close(pcap_handler_);
    }
}

int Sniffer::init(const std::string& interface, const std::string& exp) {
    // 已经被初始化
    if (pcap_initted_ == true || pthread_initted_ == true) {
        return;
    }
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_handler_ = pcap_open_live(interface.c_str(), SNAPLEN, 0, POL_TO_MS, err_buf);
    if (pcap_handler_ == NULL) {
        LOG(ERROR) << "pcap_open_live failed, err: " << err_buf;
        return -1;
    }
    dlt_ = pcap_datalink(pcap_handler_);
    if (dlt_ == DLT_EN10MB && dlt_ != DLT_LINUX_SLL && dlt_ != DLT_RAW && dlt_ != DLT_NULL) {
        LOG(ERROR) << "pcap_datalink get dlt is: " << dlt_ << ", not support this interface";
        return -2;
    }
    struct bpf_program prog_filter;
    bpf_u_int32 mask = 0;
    bpf_u_int32 net = 0;
    if (pcap_lookupnet(interface.c_str(), &net, &mask, err_buf) == -1) {
        net = 0;
        mask = 0;
    }
    if (pcap_compile(pcap_handler_, &prog_filter, exp.c_str(), 0, net) == -1) {
        pcap_close(pcap_handler_);
        LOG(ERROR) << "pcap_compile failed, err: " << err_buf;
        return -3;
    }
    if (pcap_setfilter(pcap_handler_, &prog_filter) == -1) {
        pcap_freecode(&prog_filter);
        pcap_close(pcap_handler_);
        LOG(ERROR) << "pcap_setfilter failed, err: " << err_buf;
        return -4;
    }
    // 在 pcap_setfilter 之后 prog_filter 就不需要了，需要释放
    pcap_freecode(&prog_filter);
    pcap_initted_ = true;
    if (pthread_create(&sniffer_tid_, nullptr, sniffer_thread_func, this) != 0) {
        LOG(ERROR) << "pthread_create failed, errno: " << errno << ", err: " << strerror(errno);
        return -5;
    }
    pthread_initted_ = true;
    return 0;
}

void Sniffer::run() {
    u_char* other = reinterpret_cast<u_char*>(this);
    if (pcap_loop(pcap_handler_, -1, handle_packet, other) == -1) {
        LOG(ERROR) << "pcap_loop failed, err: " << pcap_geterr(pcap_handler_);
    }
    return;
}

void Sniffer::process_packet(const pcap_pkthdr* header, const u_char* packet) {
    if (pb_ == nullptr) {
        LOG(ERROR) << "process_packet of pb_ is nullptr";
        return;
    }
    pthread_mutex_lock(&pb_mutex_);
    struct nlp* nlp = get_nlp(packet, dlt_, header);
    if (nlp == nullptr) {
        pthread_mutex_unlock(&pb_mutex_);
        return;
    }
    if (!check_nlp(nlp)) {
        if (nlp->p != nullptr) {
            free(nlp->p);
        }
        free(nlp);
        pthread_mutex_unlock(&pb_mutex_);
        return;
    }
    pb_->push_packet(nlp);
    pthread_mutex_unlock(&pb_mutex_);
    return;
}

void handle_packet(u_char* other, const pcap_pkthdr* header, const u_char* packet) {
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(other);
    sniffer->process_packet(header, packet);
    return;
}

void* sniffer_thread_func(void* arg) {
    Sniffer* sniffer = static_cast<Sniffer*>(arg);
    try {
        sniffer->run();
    } catch (...) {
        LOG(ERROR) << "Sniffer thread exception caught.";
    }
    return nullptr;
}

}  // namespace net_io_top
