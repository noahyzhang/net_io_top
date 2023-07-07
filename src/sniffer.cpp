#include <string.h>
#include <errno.h>
#include "common.h"
#include "log.h"
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
    pthread_mutex_destroy(&pb_mutex_);
}

int Sniffer::init(PacketBuffer* packet_buffer, const std::string& interface, const std::string& exp) {
    // 已经被初始化
    if (pcap_initted_ == true || pthread_initted_ == true) {
        return 0;
    }
    // 给 PacketBuffer 赋值
    packet_buffer_ = packet_buffer;
    // 初始化 pcap 库
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_handler_ = pcap_open_live(interface.c_str(), SNAPLEN, 0, POL_TO_MS, err_buf);
    if (pcap_handler_ == NULL) {
        LOG(ERROR) << "pcap_open_live failed, err: " << err_buf;
        return -1;
    }
    pcap_dlt_ = pcap_datalink(pcap_handler_);
    if (pcap_dlt_ != DLT_EN10MB && pcap_dlt_ != DLT_LINUX_SLL && pcap_dlt_ != DLT_RAW && pcap_dlt_ != DLT_NULL) {
        LOG(ERROR) << "pcap_datalink get dlt is: " << pcap_dlt_ << ", not support this interface";
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
    // 创建线程，用于循环收集数据包
    if (pthread_create(&sniffer_tid_, nullptr, sniffer_thread_func, this) != 0) {
        LOG(ERROR) << "pthread_create failed, errno: " << errno << ", err: " << strerror(errno);
        return -5;
    }
    pthread_setname_np(sniffer_tid_, "net_io_sniffer");
    pthread_initted_ = true;
    return 0;
}

void Sniffer::collect_packet() {
    u_char* other = reinterpret_cast<u_char*>(this);
    if (pcap_loop(pcap_handler_, -1, handle_packet, other) == -1) {
        LOG(ERROR) << "pcap_loop failed, err: " << pcap_geterr(pcap_handler_);
    }
    return;
}

void Sniffer::process_packet(const pcap_pkthdr* header, const u_char* orig_packet) {
    // LOG(DEBUG) << "pcap get packet, header len: " << header->len;
    if (packet_buffer_ == nullptr) {
        LOG(ERROR) << "process_packet of packet_buffer_ is nullptr";
        return;
    }
    // pthread_mutex_lock(&pb_mutex_);
    struct PacketData* res_packet = get_packet_data(orig_packet, pcap_dlt_, header);
    if (res_packet == nullptr) {
        // pthread_mutex_unlock(&pb_mutex_);
        return;
    }
    if (!check_packet_data(res_packet)) {
        if (res_packet->p_data != nullptr) {
            free(res_packet->p_data);
        }
        free(res_packet);
        // pthread_mutex_unlock(&pb_mutex_);
        LOG(WARN) << "check packet data is invalid";
        return;
    }
    packet_buffer_->push_packet(res_packet);
    // pthread_mutex_unlock(&pb_mutex_);
    return;
}

void Sniffer::handle_packet(u_char* other, const pcap_pkthdr* header, const u_char* packet) {
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(other);
    sniffer->process_packet(header, packet);
    return;
}

void* Sniffer::sniffer_thread_func(void* arg) {
    Sniffer* sniffer = static_cast<Sniffer*>(arg);
    try {
        sniffer->collect_packet();
    } catch (...) {
        LOG(ERROR) << "Sniffer thread exception caught.";
    }
    return nullptr;
}

PacketData* Sniffer::get_packet_data(const u_char* p, int dlt, const pcap_pkthdr* pcap) {
    struct PacketData* res_packet = reinterpret_cast<PacketData*>(malloc(sizeof(struct PacketData)));
    res_packet->p_data = nullptr;
    res_packet->ts = pcap->ts;
    res_packet->len = 0;
    // 解析链路层，DLT_EN10MB 为以太网协议
    if (dlt == DLT_EN10MB) {
        // 这个报文的长度至少要大于 链路层头部+网络层头部 的长度
        if (pcap->caplen < DLT_EN10MB_HEADER_LEN + IP_HEADER_LEN) {
            free(res_packet);
            return nullptr;
        }
        const struct sniff_ethernet* ethernet = (struct sniff_ethernet*)(p);
        // 判断是否为局域网
        bool vlan_frame = (ntohs(ethernet->ether_type) == ETHERTYPE_VLAN);
        uint16_t ether_type;
        if (vlan_frame) {
            // 需要处理链路层头部可选项 8021Q 标识的 4 字节
            ether_type = ntohs(*((uint16_t*)(p + DLT_EN10MB_HEADER_LEN + VLAN_HEADER_LEN - 2)));
        } else {
            ether_type = ntohs(ethernet->ether_type);
        }
        if (ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6) {
            res_packet->len = pcap->caplen - DLT_EN10MB_HEADER_LEN - (vlan_frame ? VLAN_HEADER_LEN : 0);
            res_packet->p_data = reinterpret_cast<u_char*>(malloc(sizeof(u_char) * res_packet->len));
            memcpy(reinterpret_cast<void*>(res_packet->p_data),
                (void*)(p + DLT_EN10MB_HEADER_LEN + (vlan_frame ? VLAN_HEADER_LEN : 0)),
                res_packet->len);
        } else {
            free(res_packet);
            return nullptr;
        }
    } else if (dlt == DLT_LINUX_SLL) {  // Linux socket 类型
        if (pcap->caplen < DLT_LINUX_SLL_HEADER_LEN + IP_HEADER_LEN) {
            free(res_packet);
            return nullptr;
        }
        res_packet->len = pcap->caplen - DLT_LINUX_SLL_HEADER_LEN;
        res_packet->p_data = reinterpret_cast<u_char*>(malloc(sizeof(u_char)*res_packet->len));
        memcpy(reinterpret_cast<void*>(res_packet->p_data),
            (void*)(p + DLT_LINUX_SLL_HEADER_LEN), res_packet->len);
    } else if (dlt == DLT_RAW || dlt == DLT_NULL) {
        // DLT_RAW 是一种简单的数据链路类型，它表示数据包的头部没有任何特定的格式或协议结构。
        // 在 DLT_RAW 中，数据包头部直接包含了网络层及以上协议的数据。
        // 这种类型的数据链路通常用于原始数据包捕获或发送，允许以原始的、未经修改的形式处理数据包。
        // DLT_NULL 它表示数据包没有数据链路层头部，仅包含网络层及以上的数据
        // 这种类型的数据链路通常用于本地通信、回环接口（loopback interface）或隧道协议，其中链路层头部是不必要的
        if (pcap->caplen < IP_HEADER_LEN) {
            free(res_packet);
            return nullptr;
        }
        res_packet->len = pcap->caplen;
        res_packet->p_data = reinterpret_cast<u_char*>(malloc(sizeof(u_char)*res_packet->len));
        memcpy(reinterpret_cast<void*>(res_packet->p_data), (void*)(p), res_packet->len);
    }
    return res_packet;
}

bool Sniffer::check_packet_data(struct PacketData* packet) {
    struct sniff_ip* ip = reinterpret_cast<struct sniff_ip*>(packet->p_data);
    // 暂不支持 IPv6
    if (ip->ip_v == 6) {
        return false;
    }
    unsigned int ip_header_len = ip->ip_hl * 4;
    if (packet->len < ip_header_len + TCP_HEADER_LEN) {
        return false;
    }
    if (ip->ip_v != 4) {
        return false;
    }
    if (ntohs(ip->ip_len) < ip_header_len + TCP_HEADER_LEN) {
        return false;
    }
    if (ip->ip_hl < 5) {
        return false;
    }
    if (ip->ip_p != IPPROTO_TCP) {
        return false;
    }
    struct sniff_tcp* tcp = (struct sniff_tcp*)(packet->p_data + ip_header_len);
    if (tcp->th_off < 5) {
        return false;
    }
    if (tcp->th_sport == 0) {
        return false;
    }
    if (tcp->th_dport == 0) {
        return false;
    }
    return true;
}

}  // namespace net_io_top
