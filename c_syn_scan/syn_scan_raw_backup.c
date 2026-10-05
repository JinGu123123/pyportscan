#include<stdio.h>		// printf, fprintf
#include<stdlib.h>		// atoi, rand
#include<string.h>		// memset, memcpy
#include<unistd.h>		// close
#include<netinet/ip.h>		// struct iphdr（IP 头部结构）
#include<netinet/tcp.h>		// struct tcphdr（TCP 头部结构）
#include<arpa/inet.h>		// htons, htonl, inet_addr
#include<sys/socket.h>		// socket, sendto


unsigned short checksum(unsigned short *buf,int len){
	unsigned long sum = 0;
	while(len > 1){
		sum += *buf++;
		len -= 2;
	}
	if(len == 1){
		sum += *(unsigned char *)buf;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}


int main(int argc,char *argv[]){
	if (argc != 3){
		fprintf(stderr,"用法：%s<目标IP><目标端口>\n",argv[0]);
		return 1;
	}

	const char *target_ip = argv[1];
	int target_port = atoi(argv[2]);


	//1、创建原始套接字
	int sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	if(sock < 0){
	perror("socket创建失败（需要root权限）");
	return 1;
	}


	//2、构造TCP头部
	struct tcphdr tcp;
	memset(&tcp,0,sizeof(tcp));
	tcp.source = htons(12345);		//源端口
	tcp.dest = htons(target_port);		//目标端口
	tcp.seq = htonl(rand());		//序列号
	tcp.doff = 5;				//数据偏移：5 * 4 = 20字节
	tcp.syn = 1;				//SYN标志位
	tcp.window = htons(65535);		//窗口大小


	//3、构造IP头部
	struct iphdr ip;
	memset(&ip,0,sizeof(ip));
	ip.version = 4;								//IPv4
	ip.ihl = 5;								//头部长度：5 * 4 = 20字节
	ip.tos = 0;
	ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	ip.id = htons(rand() & 0xFFFF);
	ip.frag_off = 0;
	ip.ttl = 64;
	ip.protocol = IPPROTO_TCP;						//协议号 6 = TCP
	ip.saddr = inet_addr("127.0.0.1");					//源IP
	ip.daddr = inet_addr(target_ip);					//目标IP
	ip.check = checksum((unsigned short *)&ip,sizeof(ip));


	//4、构造完整的包（IP + TCP）
	unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
	memcpy(packet,&ip,sizeof(ip));
	memcpy(packet + sizeof(ip),&tcp,sizeof(tcp));


	//5、发送
	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = ip.daddr;


	int sent = sendto(sock,packet,sizeof(packet),0,
		(struct sockaddr *)&dest,sizeof(dest));
	if(sent < 0){
		perror("sendto失败");
		close(sock);
		return 1;
	}


	printf("SYN包%d字节已发送到%s:%d\n",sent,target_ip,target_port);

	/* ===== 新增：接收响应 ===== */
	struct timeval tv;
	tv.tv_sec = 3;              /* 3 秒超时 */
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	unsigned char recvbuf[4096];
	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);

	int recv_len = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
				(struct sockaddr *)&from, &from_len);

	if (recv_len < 0) {
		printf("→ 3 秒内无响应（端口开放或被过滤，无法确定）\n");
	} else {
		printf("→ 收到 %d 字节响应\n", recv_len);
		/* ===== 临时诊断：打印前 80 字节的十六进制 ===== */
		printf("原始数据: ");
		for (int i = 0; i < recv_len && i < 80; i++) {
		printf("%02x ", recvbuf[i]);
	}
		printf("\n");

		/* 解析 IP 头 */
		/* 注意：Linux raw socket 会收到"自己发的包"的回显
		 * 所以要先跳过第一个 IP 头，再解析"对端响应" */
		int first_ip_len = ((struct iphdr *)recvbuf)->ihl * 4;
		unsigned char *resp_start = recvbuf + first_ip_len;

		struct iphdr *resp_ip = (struct iphdr *)resp_start;
		int ip_header_len = resp_ip->ihl * 4;
		/* 解析 TCP 头（不用 struct tcphdr 的位域） */
		unsigned char *tcp_start = resp_start + ip_header_len;
		unsigned char flags_byte = tcp_start[13];   /* TCP 第 13 字节是标志位 */

		int has_syn = (flags_byte & 0x02) != 0;
		int has_ack = (flags_byte & 0x10) != 0;
		int has_rst = (flags_byte & 0x04) != 0;

		printf("   flags: 0x%02x (syn=%d ack=%d rst=%d)\n",
			flags_byte, has_syn, has_ack, has_rst);

		if (has_syn && has_ack) {
		printf("   SYN+ACK → 端口开放！\n");
		} else if (has_rst) {
		printf("   RST → 端口关闭\n");
		} else if (has_syn) {
		printf("   SYN → 意外响应\n");
		} else {
		printf("   其他响应\n");
		}
	}
	/* ===== 新增结束 ===== */

	close(sock);
	return 0;
}
