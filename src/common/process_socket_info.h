/**
 * @file process_info.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-17
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_COMMON_PROCESS_SOCKET_INFO_H_
#define SRC_COMMON_PROCESS_SOCKET_INFO_H_

#include <errno.h>
#include <string.h>
#include <string>
#include <unordered_map>
#include <utility>
#include "common/common.h"

namespace net_io_top {

#define PATH_PROC_NET_TCP "/proc/net/tcp"
#define PATH_PROC_NET_UDP "/proc/net/udp"
#define PRG_SOCKET_PFX "socket:["
#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))

/**
 * @brief 进程的连接信息
 * 
 */
class ProcessSocketInfo {
public:
    ProcessSocketInfo() = default;
    ~ProcessSocketInfo() = default;
    ProcessSocketInfo(const ProcessSocketInfo&) = delete;
    ProcessSocketInfo& operator=(const ProcessSocketInfo&) = delete;
    ProcessSocketInfo(ProcessSocketInfo&&) = delete;
    ProcessSocketInfo& operator=(ProcessSocketInfo&&) = delete;

public:
    /**
     * @brief 刷新进程与连接的对应信息
     * 
     * @return int 
     */
    int refresh_process_socket_info();

    /**
     * @brief 获取此连接对应的进程
     * 
     * @param socket 
     * @return int 
     */
    int get_pid_from_socket(const SocketAddrInfo& socket);

private:
    /**
     * @brief 设置 TCP 连接与 inode 之间的对应关系
     * 
     * @return int 
     */
    int set_tcp_inode_socket_info();

    /**
     * @brief 设置 UDP 连接与 inode 之间的对应关系
     * 
     * @return int 
     */
    int set_udp_inode_socket_info();

    /**
     * @brief 遍历所有进程的信息
     * 
     * @return int 
     */
    int traverse_process_info();

    /**
     * @brief 通过 fd 获取到进程的所有 inode 信息
     * 
     * @param fd_path 
     * @param pid 
     * @return int 
     */
    int get_process_inode_from_fd(const std::string& fd_path, uint64_t pid);

    /**
     * @brief 通过 fd 的软连接提取到 inode
     * 
     * @param name 
     * @param inode_p 
     * @return int 
     */
    int extract_socket_inode(const char name[], uint64_t* inode_p);

private:
    /**
     * @brief IP 地址从十六进制转换为十进制
     * 
     * @param hex 
     * @param dec 
     * @param len 
     */
    static void ip_hex_to_dec(const char* hex, char* dec, int len);

private:
    // inode 与 pid 之间的对应关系
    // key: inode, value: pid
    std::unordered_map<uint64_t, uint64_t> inode_process_mp_;
    // inode 与 socket 连接之间的对应关系
    // key 为 inode
    std::unordered_map<uint64_t, SocketAddrInfo> inode_socket_info_mp_;
};

}  // namespace net_io_top

#endif  // SRC_COMMON_PROCESS_SOCKET_INFO_H_
