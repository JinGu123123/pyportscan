#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>

volatile sig_atomic_t g_timeout = 0;
volatile sig_atomic_t g_got_response = 0;

void on_alarm(int sig) {
    (void)sig;
    g_timeout = 1;
}

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

unsigned int get_local_ip(const char *iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

void get_local_mac(const char *iface, unsigned char *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}

/* 获取"网关 IP"的 MAC 地址（通过 /proc/net/arp） */
int get_gateway_mac(const char *gateway_ip, unsigned char *mac) {
    FILE *fp = fopen("/proc/net/arp", "r");
    if (!fp) return -1;
    char line[256];
    fgets(line, sizeof(line), fp);  /* 跳过表头 */
    while (fgets(line, sizeof(line), fp)) {
        char ip[64], hw[64];
        sscanf(line, "%63s %*s %*s %63s", ip, hw);
        if (strcmp(ip, gateway_ip) == 0) {
            sscanf(hw, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "用法: %s <目标IP> <目标端口>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int is_loopback = (strcmp(target_ip, "127.0.0.1") == 0);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);

    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface = is_loopback ? "lo" : "eth0";
    pcap_t *handle = pcap_open_live(iface, 65535, 0, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live 失败: %s\n", errbuf);
        return 1;
    }
    printf("[*] 监听接口: %s\n", iface);

    struct bpf_program fp;
    char filter_exp[128];
    snprintf(filter_exp, sizeof(filter_exp),
             "tcp and src port %d and dst port 12345", target_port);
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "过滤规则设置失败\n");
        pcap_close(handle);
        return 1;
    }
    printf("[*] 过滤规则: %s\n", filter_exp);

    /* ---------- 构造 IP + TCP ---------- */
    struct tcphdr tcp;
    memset(&tcp, 0, sizeof(tcp));
    tcp.source = htons(12345);
    tcp.dest = htons(target_port);
    tcp.seq = htonl(rand());
    tcp.doff = 5;
    tcp.syn = 1;
    tcp.window = htons(65535);

    struct iphdr ip;
    memset(&ip, 0, sizeof(ip));
    ip.version = 4;
    ip.ihl = 5;
    ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip.id = htons(rand() & 0xFFFF);
    ip.ttl = 64;
    ip.protocol = IPPROTO_TCP;

    unsigned int src_ip;
    if (is_loopback) {
        src_ip = inet_addr("127.0.0.1");
    } else {
        src_ip = get_local_ip("eth0");
    }
    ip.saddr = src_ip;
    ip.daddr = inet_addr(target_ip);

    /* TCP 校验和（含伪头部） */
    struct {
        unsigned int src;
        unsigned int dst;
        unsigned char zero;
        unsigned char proto;
        unsigned short tcp_len;
    } __attribute__((packed)) pseudo;

    pseudo.src = ip.saddr;
    pseudo.dst = ip.daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.tcp_len = htons(sizeof(struct tcphdr));

    unsigned char tcp_buf[sizeof(pseudo) + sizeof(struct tcphdr)];
    memcpy(tcp_buf, &pseudo, sizeof(pseudo));
    memcpy(tcp_buf + sizeof(pseudo), &tcp, sizeof(tcp));
    tcp.check = checksum((unsigned short *)tcp_buf, sizeof(tcp_buf));

    ip.check = checksum((unsigned short *)&ip, sizeof(ip));

    /* ---------- 构造完整包：以太网头 + IP + TCP ---------- */
    unsigned char packet[14 + sizeof(struct iphdr) + sizeof(struct tcphdr)];
    unsigned char *eth = packet;
    unsigned char *ip_ptr = packet + 14;
    unsigned char *tcp_ptr = packet + 14 + sizeof(struct iphdr);

    /* 以太网头 */
    unsigned char src_mac[6], dst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    get_local_mac("eth0", src_mac);

    if (!is_loopback) {
        /* 找网关 IP 和 MAC */
        FILE *fp = popen("ip route | grep default | awk '{print $3}'", "r");
        char gw_ip[64] = {0};
        if (fp) { fgets(gw_ip, sizeof(gw_ip), fp); pclose(fp); }
        gw_ip[strcspn(gw_ip, "\n")] = 0;
        printf("[*] 网关 IP: %s\n", gw_ip);

        if (get_gateway_mac(gw_ip, dst_mac) != 0) {
            printf("[!] 无法获取网关 MAC，使用广播地址\n");
        } else {
            printf("[*] 网关 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
        }
    } else {
        memcpy(dst_mac, src_mac, 6);  /* loopback：自己发给自己 */
    }

    memcpy(eth, dst_mac, 6);
    memcpy(eth + 6, src_mac, 6);
    eth[12] = 0x08;
    eth[13] = 0x00;

    memcpy(ip_ptr, &ip, sizeof(ip));
    memcpy(tcp_ptr, &tcp, sizeof(tcp));

    /* ---------- 用 pcap_sendpacket 发送 ---------- */
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "pcap_sendpacket 失败: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    printf("[+] SYN 包已发送到 %s:%d\n", target_ip, target_port);
    printf("[*] 等待响应（3 秒）...\n");
    fflush(stdout);

    alarm(3);

    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    while (!g_timeout) {
        int result = pcap_next_ex(handle, &header, &pkt_data);
        if (result != 1) continue;

        /* 跳过以太网头（14 字节） */
        struct iphdr *rip = (struct iphdr *)(pkt_data + 14);
        int ip_hlen = rip->ihl * 4;
        unsigned char *tcp_bytes = (unsigned char *)rip + ip_hlen;
        unsigned char flags = tcp_bytes[13];

        int has_syn = (flags & 0x02) != 0;
        int has_ack = (flags & 0x10) != 0;
        int has_rst = (flags & 0x04) != 0;

        printf("[*] 收到响应：flags=0x%02x (syn=%d ack=%d rst=%d)\n",
               flags, has_syn, has_ack, has_rst);

        if (has_syn && has_ack) {
            printf("[+] 端口 %d 开放！(SYN+ACK)\n", target_port);
        } else if (has_rst) {
            printf("[-] 端口 %d 关闭 (RST)\n", target_port);
        } else {
            printf("[?] 其他响应\n");
        }

        g_got_response = 1;
        break;
    }

    alarm(0);

    if (!g_got_response) {
        printf("[-] 超时：3 秒内无响应\n");
    }

    pcap_close(handle);
    return 0;
}
