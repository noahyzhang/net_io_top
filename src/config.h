/**
 * @file config.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-04
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdint.h>

namespace net_io_top {

class Config {
public:

public:
    uint64_t get_conn_closed_timeout_s() { return conn_closed_timeout_s_; }

private:
    // 移除已关闭连接的超时时间（单位为秒）
    uint64_t conn_closed_timeout_s_;
};

}  // namespace net_io_top

#endif  // SRC_CONFIG_H_
