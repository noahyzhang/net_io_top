/**
 * @file utils.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-29
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_UTILS_H_
#define SRC_UTILS_H_

#include <stdint.h>
#include "pcap/pcap.h"

namespace net_io_top {

struct nlp {
    u_char* p;
    uint64_t len;
    struct timeval ts;
};

struct nlp* get_nlp(const u_char* p, int dlt, const pcap_pkthdr* pcap);
bool check_nlp(struct nlp* nlp);

}  // namespace net_io_top

#endif  // SRC_UTILS_H_
