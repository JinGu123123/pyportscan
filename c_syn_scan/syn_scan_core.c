/*
 * SYN 半开扫描 - 核心版
 * 
 * 仅依赖原始套接字，在真实 Linux 环境下工作。
 * 在 WSL2 下受网络隔离限制，无法完整运行。
 *
 * 编译: gcc -o syn_scan_core syn_scan_core.c
 * 运行: sudo ./syn_scan_core <目标IP> <目标端口>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* 16 位校验和 */
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "用法: %s <目标IP> <目标端口>\n", argv[0]);
        return 1;
    }
    
    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    
    /* 1. 创建原始套接字 */
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket 失败（需要 root）");
        return 1;
    }
    
    /* 2. 构造 TCP 头部 */
    struct tcphdr tcp;
    memset(&tcp, 0, sizeof(tcp));
    tcp.source = htons(12345);
    tcp.dest = htons(target_port);
    tcp.seq = htonl(rand());
    tcp.doff = 5;
    tcp.syn = 1;
    tcp.window = htons(65535);
    
    /* 3. 构造 IP 头部 */
    struct iphdr ip;
    memset(&ip, 0, sizeof(ip));
    ip.version = 4;
    ip.ihl = 5;
    ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip.id = htons(rand() & 0xFFFF);
    ip.ttl = 64;
    ip.protocol = IPPROTO_TCP;
    ip.saddr = inet_addr("127.0.0.1");   /* 真实 Linux 上可改为本机 IP */
    ip.daddr = inet_addr(target_ip);
    ip.check = checksum((unsigned short *)&ip, sizeof(ip));
    
    /* 4. 组装包 */
    unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memcpy(packet, &ip, sizeof(ip));
    memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));
    
    /* 5. 发送 */
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip.daddr;
    
    if (sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto 失败");
        close(sock);
        return 1;
    }
    printf("[+] SYN 包已发送到 %s:%d\n", target_ip, target_port);
    
    /* 6. 接收响应 */
    struct timeval tv = { 3, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    unsigned char recvbuf[4096];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                     (struct sockaddr *)&from, &from_len);
    if (n < 0) {
        printf("[-] 3 秒无响应\n");
    } else {
        /* 解析响应（跳过第一个 IP 头——这是 raw socket 收到自己发的包） */
        struct iphdr *rip = (struct iphdr *)recvbuf;
        int ip_len = rip->ihl * 4;
        unsigned char *tcp_bytes = recvbuf + ip_len;
        unsigned char flags = tcp_bytes[13];
        
        int syn = (flags & 0x02) != 0;
        int ack = (flags & 0x10) != 0;
        int rst = (flags & 0x04) != 0;
        
        printf("[*] 收到响应: flags=0x%02x\n", flags);
        if (syn && ack) printf("[+] 端口 %d 开放！\n", target_port);
        else if (rst)  printf("[-] 端口 %d 关闭\n", target_port);
        else           printf("[?] 其他响应\n");
    }
    
    close(sock);
    return 0;
}
