#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common/log.h"
#include "common/process_socket_info.h"

namespace net_io_top {

int ProcessSocketInfo::refresh_process_socket_info() {
    if (set_tcp_inode_socket_info() < 0) {
        return -1;
    }
    if (set_udp_inode_socket_info() < 0) {
        return -2;
    }
    if (traverse_process_info() < 0) {
        return -3;
    }
    return 0;
}

int ProcessSocketInfo::get_pid_from_socket(const SocketAddrInfo& socket) {
    int inode = -1;
    for (const auto& x : inode_socket_info_mp_) {
        if (x.second.protocol != socket.protocol) {
            continue;
        }
        if ((x.second.src_addr == socket.src_addr && x.second.dst_addr == socket.dst_addr)
            && (x.second.src_port == socket.src_port && x.second.dst_port == socket.dst_port)) {
            inode = x.first;
            break;
        }
        if ((x.second.src_addr == socket.dst_addr && x.second.dst_addr == socket.src_addr)
            && (x.second.src_port == socket.dst_port && x.second.dst_port == socket.src_port)) {
            inode = x.first;
            break;
        }
    }
    if (inode == -1) {
        return -1;
    }
    auto iter = inode_process_mp_.find(inode);
    if (iter != inode_process_mp_.end()) {
        return iter->second;
    }
    return -2;
}

int ProcessSocketInfo::traverse_process_info() {
    DIR* proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        LOG(ERROR) << "Failed to open /proc directory, err: " << strerror(errno);
        return -1;
    }
    struct dirent* dp;
    while ((dp = readdir(proc_dir)) != NULL) {
        // 跳过非数字的目录项
        if (dp->d_type != DT_DIR || !isdigit(dp->d_name[0])) {
            continue;
        }
        uint64_t pid = std::atoll(dp->d_name);
        std::string fd_path = "/proc/" + std::to_string(pid) + "/fd";
        // char fd_path[266] = {0};
        // snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", dp->d_name);
        get_process_inode_from_fd(fd_path, pid);
    }
    closedir(proc_dir);
    return 0;
}

int ProcessSocketInfo::get_process_inode_from_fd(const std::string& fd_path, uint64_t pid) {
    DIR* dir = opendir(fd_path.c_str());
    if (dir == nullptr) {
        LOG(ERROR) << "Failed to open directory: " << fd_path << ", err: " << strerror(errno);
        return -1;
    }
    struct dirent* dp;
    // char file_path[257] = {0};
    // struct stat file_stat;
    while ((dp = readdir(dir)) != nullptr) {
        // std::cout << "pid: " << pid << ", d_type: " << (int)(dp->d_type) << std::endl;
        // 文件系统无法识别 DT_SOCK，会识别成 DT_LNK 类型
        if (dp->d_type == DT_SOCK || dp->d_type == DT_LNK) {
            std::string socket_path = fd_path + "/" + dp->d_name;
            // 读取符号链接的目标文件信息
            char target_path[256];
            ssize_t len = readlink(socket_path.c_str(), target_path, sizeof(target_path)-1);
            if (len == -1) {
                LOG(ERROR) << "Failed to read link: " << socket_path << ", err: " << strerror(errno);
                continue;
            }
            target_path[len] = '\0';
            uint64_t inode = 0;
            if (extract_socket_inode(target_path, &inode) < 0) {
                continue;
            }
            // LOG(DEBUG) << "pid: " << pid << " socket inode: " << inode;
            inode_process_mp_[inode] = pid;
        }

        // // 跳过 . 和 .. 目录
        // if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
        //     continue;
        // }
        // // 构建完整的文件路径
        // snprintf(file_path, sizeof(file_path), "%s/%s", fd_path, dp->d_name);
        // // 获取文件信息
        // if (lstat(file_path, &file_stat) == -1) {
        //     LOG(ERROR) << "Failed to get file info: " << file_path << ", err: " << strerror(errno);
        //     continue;
        // }
        // // 判断是否为符号链接
        // if (S_ISLNK(file_stat.st_mode)) {
        //     // 读取符号链接的目标文件信息
        //     char target_path[256];
        //     ssize_t len = readlink(file_path, target_path, sizeof(target_path)-1);
        //     if (len == -1) {
        //         LOG(ERROR) << "Failed to read link: " << file_path << ", err: " << strerror(errno);
        //         continue;
        //     }
        //     target_path[len] = '\0';
        //     uint64_t inode = 0;
        //     if (extract_socket_inode(target_path, &inode) < 0) {
        //         continue;
        //     }
        //     // LOG(DEBUG) << "pid: " << pid << " socket inode: " << inode;
        //     inode_process_mp_[inode] = pid;
        // }
    }
    closedir(dir);
    return 0;
}

int ProcessSocketInfo::set_tcp_inode_socket_info() {
    FILE* tcp_file = fopen(PATH_PROC_NET_TCP, "r");
    if (tcp_file == NULL) {
        LOG(ERROR) << "Failed to open " << PATH_PROC_NET_TCP << ", err: " << strerror(errno);
        return -1;
    }
    char line[256];
    // 忽略文件的头部
    if (fgets(line, sizeof(line), tcp_file) == nullptr) {
        LOG(ERROR) << "Failed to fgets line from " << PATH_PROC_NET_TCP << ", err: " << strerror(errno);
        return -2;
    }
    // 遍历文件的每一行
    while (fgets(line, sizeof(line), tcp_file) != NULL) {
        uint64_t rxq, txq, time_len, retr, inode;
        int local_port, remote_port, d, state, uid, timer_run, timeout;
        char hex_local_addr[128], hex_remote_addr[128];
        int num = sscanf(line,
            "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
            &d, hex_local_addr, &local_port, hex_remote_addr, &remote_port, &state,
            &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);
        if (num < 11) {
            LOG(ERROR) << "Failed to parse line: " << line << ", err: " << strerror(errno);
            continue;
        }
        // 将十六进制地址转换为十进制
        char local_address[32], remote_address[32];
        ip_hex_to_dec(hex_local_addr, local_address, sizeof(local_address)-1);
        ip_hex_to_dec(hex_remote_addr, remote_address, sizeof(remote_address)-1);

        // LOG(DEBUG) << "get TCP local_addr: " << local_address << ":" << local_port
        //     << ", remote_addr: " << remote_address << ":" << remote_port;
        inode_socket_info_mp_[inode] = SocketAddrInfo{
            TransportLayerProtocol::TRANSPORT_LAYER_PROTOCOL_TCP,
            local_address, remote_address,
            static_cast<uint16_t>(local_port), static_cast<uint16_t>(remote_port)};
    }
    fclose(tcp_file);
    return 0;
}

int ProcessSocketInfo::set_udp_inode_socket_info() {
    FILE* udp_file = fopen(PATH_PROC_NET_UDP, "r");
    if (udp_file == NULL) {
        LOG(ERROR) << "Failed to open " << PATH_PROC_NET_UDP << ", err: " << strerror(errno);
        return -1;
    }
    char line[256];
    if (fgets(line, sizeof(line), udp_file) == nullptr) {
        LOG(ERROR) << "Failed to fgets line from " << PATH_PROC_NET_UDP << ", err: " << strerror(errno);
        return -2;
    }
    while (fgets(line, sizeof(line), udp_file) != NULL) {
        uint64_t rxq, txq, time_len, retr, inode;
        int local_port, remote_port, d, state, uid, timer_run, timeout;
        char hex_local_addr[128], hex_remote_addr[128];
        int num = sscanf(line,
            "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
            &d, hex_local_addr, &local_port,
            hex_remote_addr, &remote_port, &state,
            &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);
        if (num < 11) {
            LOG(ERROR) << "Failed to parse line: " << line << ", err: " << strerror(errno);
            continue;
        }
        // 将十六进制地址转换为十进制
        char local_address[32], remote_address[32];
        ip_hex_to_dec(hex_local_addr, local_address, sizeof(local_address)-1);
        ip_hex_to_dec(hex_remote_addr, remote_address, sizeof(remote_address)-1);

        // LOG(DEBUG) << "get UDP local_addr: " << local_address << ":" << local_port
        //     << ", remote_addr: " << remote_address << ":" << remote_port;
        inode_socket_info_mp_[inode] = SocketAddrInfo{
            TransportLayerProtocol::TRANSPORT_LAYER_PROTOCOL_UDP,
            local_address, remote_address,
            static_cast<uint16_t>(local_port), static_cast<uint16_t>(remote_port)};
    }
    fclose(udp_file);
    return 0;
}

void ProcessSocketInfo::ip_hex_to_dec(const char* hex, char* dec, int len) {
    uint32_t decNum;
    sscanf(hex, "%x", &decNum);
    snprintf(dec, len, "%u.%u.%u.%u",
        (decNum & 0xFF), ((decNum >> 8) & 0xFF), ((decNum >> 16) & 0xFF),
        ((decNum >> 24) & 0xFF));
}

int ProcessSocketInfo::extract_socket_inode(const char name[], uint64_t* inode_p) {
    if (strlen(name) < PRG_SOCKET_PFXl+3) {
        // LOG(ERROR) << "invalid socket name, len too small, name: " << name;
        return -1;
    }
    if (memcmp(name, PRG_SOCKET_PFX, PRG_SOCKET_PFXl)) {
        // LOG(ERROR) << "invalid socket name, name: " << name;
        return -2;
    }
    if (name[strlen(name)-1] != ']') {
        LOG(ERROR) << "invalid socket name, name: " << name;
        return -3;
    }
    char inode_str[strlen(name+1)] = {0};
    const int inode_str_len = strlen(name) - PRG_SOCKET_PFXl - 1;
    char* serr;
    strncpy(inode_str, name + PRG_SOCKET_PFXl, inode_str_len);
    inode_str[inode_str_len] = '\0';
    *inode_p = strtoul(inode_str, &serr, 0);
    if (!serr || *serr) {
        LOG(ERROR) << "convert socket inode error, name: " << name;
        return -4;
    }
    return 0;
}

}  // namespace net_io_top
