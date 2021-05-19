#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <linux/net.h>
#include <net/protocol.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>

#include <linux/ktime.h>
#include <linux/timekeeping.h>

#include "ip2str.h"
#include "eth_if.h"
#include "uc2str.h"
#include "uc2int.h"


//extern void uc2str(char* str, unsigned char uc);
//extern void eth_if(char* des, char* src, char* ip_type, unsigned char* eth_header);

struct file* file = NULL;
static char buf[20];
mm_segment_t fs;
loff_t pos;
unsigned char* data = NULL;
unsigned char* head = NULL;
unsigned char* head_1 = NULL;
unsigned char* head_2 = NULL;
struct iphdr* iph = NULL;

char mac_des[18],mac_src[18],ip_type[7];

char tmp[3];
char rev_time[33];
char ipaddr[20],ipaddr2[20];
int i,j;
char link_layer[15] = {"--Link Layer--"};
char internet_layer[19] = {"--Internet Layer--"};
char transport_layer[20] = {"--Transport Layer--"};
char destination[13] = {"Destination:"};
char source[8] = {"Source:"};
char ip_pro_type[9] = {"IP Type:"};
char sourceIP[11] = {"Source IP:"};
char destinationIP[16] = {"destination IP:"};
char pkt_type[13] = {"Packet Type:"};
char* space = " ";
char* table = "\t";
char* next_line = "\n";

char ip_version[12] = {"IP Version:"};
char ip_length[11] = {"IP Length:"};
char time_to_live[5] = {"TTL:"};

char icmp_type[6] = {"Type:"};
char icmp_code[6] = {"Code:"};
char icmp_seq_num[17] = {"Sequence Number:"};

char udp_src_port[13] = {"Source Port:"};
char udp_des_port[18] = {"Destination Port:"};
char udp_length[12] = {"UDP Length:"};

char tcp_src_port[13] = {"Source Port:"};
char tcp_des_port[18] = {"Destination Port:"};
char tcp_window_size[25] = {"Window Size(not scaled):"};

//ip
char ip_v_c[5] = {"Ipv4"};
int ip_len_i;
int ttl_i;
char ip_len_c[6];
char ttl_c[4];

//transport
int icmp_type_i;	
int icmp_code_i;
int icmp_seq_num_i;
char icmp_type_c[4];	
char icmp_code_c[4];
char icmp_seq_num_c[6];

int udp_src_i;
int udp_des_i;
int udp_len_i;
char udp_src_c[6];
char udp_des_c[6];
char udp_len_c[6];

int tcp_src_i;
int tcp_des_i;
int tcp_window_i;
char tcp_src_c[6];
char tcp_des_c[6];
char tcp_window_c[6];

char pkt_type_c[20] = {"Defult"};
char* pkt_icmp_c = "ICMP";
char* pkt_udp_c = "UDP";
char* pkt_tcp_c = "TCP";
char* pkt_http_c = "HTTP";
char* pkt_ftp_c = "FTP";
char* pkt_smtp_c = "SMTP";

unsigned int my_hook_fun(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	char dst_ipaddr[20];
	char *local_dst = "192.168.163.132";
	iph = ip_hdr(skb);
	ip2str(dst_ipaddr, sizeof(dst_ipaddr), ntohl(iph->daddr));
	strcpy(buf,dst_ipaddr);
	if(strcmp(buf,local_dst) != 0){
		
		return NF_ACCEPT;
	}	


	memset(ipaddr, 0, sizeof(ipaddr));
        ip2str(ipaddr, sizeof(ipaddr), ntohl(iph->saddr));
	strcpy(buf,ipaddr);

	memset(ipaddr2, 0, sizeof(ipaddr2));
        ip2str(ipaddr2, sizeof(ipaddr2), ntohl(iph->daddr));
	strcpy(buf,ipaddr2);
	
	struct rtc_time tm;
	struct timespec64 ts;
	ktime_get_real_ts64(&ts);
	ts.tv_sec = ts.tv_sec + 8*60*60;
	rtc_time_to_tm(ts.tv_sec,&tm);	
	sprintf(rev_time,"Recive time: %04d-%02d-%02d %02d:%02d:%02d", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	
	if( unlikely(!skb) ) {
		printk(KERN_ALERT "!skb\n");
                return NF_ACCEPT;
        }
        
        if( unlikely(!iph) ) {
		printk(KERN_ALERT "!iph\n");
                return NF_ACCEPT;
        }
 		
	// IP Layer:	
	head_1 = skb_network_header(skb);
	if(head_1[0] == 0x45){
	
		ip_len_i = uc2int(head_1,2,2);
		printk("%d",ip_len_i);
		snprintf(ip_len_c, 6, "%d", ip_len_i);
		printk("%d",strlen(ip_len_c));

		printk("%x",head_1[8]);
		ttl_i = uc2int(head_1,8,1);
		printk("%d",ttl_i);
		snprintf(ttl_c, 4, "%d", ttl_i);
		printk("%d",strlen(ttl_c));
	}
	
	//
	//transfer layer
	head_2 = skb_transport_header(skb);
	if(iph->protocol == IPPROTO_ICMP){
		icmp_type_i = uc2int(head_2, 0, 1);
		icmp_code_i = uc2int(head_2, 1, 1);
		icmp_seq_num_i = uc2int(head_2, 6, 2);
		snprintf(icmp_type_c, 4, "%d", icmp_type_i);
		snprintf(icmp_code_c, 4, "%d", icmp_code_i);
		snprintf(icmp_seq_num_c, 6, "%d", icmp_seq_num_i);

		snprintf(pkt_type_c, 20, "%s", pkt_icmp_c);		
	}
	else if(iph->protocol == IPPROTO_UDP){
		udp_src_i = uc2int(head_2, 0, 2);
		udp_des_i = uc2int(head_2, 2, 2);
		udp_len_i = uc2int(head_2, 4, 2);	
		snprintf(udp_src_c, 6, "%d", udp_src_i);
		snprintf(udp_des_c, 6, "%d", udp_des_i);
		snprintf(udp_len_c, 6, "%d", udp_len_i);

		snprintf(pkt_type_c, 20, "%s", pkt_udp_c);
	}
	else if(iph->protocol == IPPROTO_TCP){
		tcp_src_i = uc2int(head_2, 0, 2);
		tcp_des_i = uc2int(head_2, 2, 2);
		tcp_window_i = uc2int(head_2, 14, 2);
		snprintf(tcp_src_c, 6, "%d", tcp_src_i);
		snprintf(tcp_des_c, 6, "%d", tcp_des_i);
		snprintf(tcp_window_c, 6, "%d", tcp_window_i);
		
		if(tcp_src_i == 80 || tcp_des_i == 80){
			snprintf(pkt_type_c, 20, "%s,%s", pkt_tcp_c,pkt_http_c);
		}
		else if(tcp_src_i == 21 || tcp_des_i == 21){
			snprintf(pkt_type_c, 20, "%s,%s", pkt_tcp_c,pkt_ftp_c);
		}
		else if(tcp_src_i == 25 || tcp_des_i == 25){
			snprintf(pkt_type_c, 20, "%s,%s", pkt_tcp_c,pkt_smtp_c);
		}
		else{
			snprintf(pkt_type_c, 20, "%s", pkt_tcp_c);
		}
	}
	//
	head = skb_mac_header(skb);
	eth_if(mac_des, mac_src,ip_type,head);

        set_fs(KERNEL_DS);
	
	vfs_write(file, next_line,1, &pos);
	vfs_write(file, next_line,1, &pos);
	vfs_write(file, rev_time,sizeof(rev_time)-1, &pos);
	vfs_write(file, next_line,1, &pos);

	vfs_write(file, pkt_type,sizeof(pkt_type)-1, &pos);
	vfs_write(file, pkt_type_c,strlen(pkt_type_c), &pos);
	vfs_write(file, next_line,1, &pos);
		
	vfs_write(file, link_layer,sizeof(link_layer)-1, &pos);
	vfs_write(file, next_line,1, &pos);

	vfs_write(file, destination,sizeof(destination)-1, &pos);
	vfs_write(file, mac_des,sizeof(mac_des)-1, &pos);
	vfs_write(file, table,1, &pos);
	vfs_write(file, source,sizeof(source)-1, &pos);
	vfs_write(file, mac_src,sizeof(mac_src)-1, &pos);
	vfs_write(file, next_line,1, &pos);
	vfs_write(file, ip_pro_type,sizeof(ip_pro_type)-1, &pos);
	vfs_write(file, ip_type,sizeof(ip_type)-1, &pos);
	vfs_write(file, next_line,1, &pos);
	
	if(head_1[0] == 0x45){
		vfs_write(file, internet_layer,sizeof(internet_layer)-1, &pos);
		vfs_write(file, next_line,1, &pos);
		vfs_write(file, sourceIP,sizeof(sourceIP)-1, &pos);
		vfs_write(file, ipaddr,strlen(ipaddr), &pos);
		vfs_write(file, table,1, &pos);
		vfs_write(file, destinationIP,sizeof(destinationIP)-1, &pos);
		vfs_write(file, ipaddr2,strlen(ipaddr2), &pos);
		vfs_write(file, next_line,1, &pos);
		vfs_write(file, ip_version,sizeof(ip_version)-1, &pos);
		vfs_write(file, ip_v_c,sizeof(ip_v_c)-1, &pos);
		vfs_write(file, next_line,1, &pos);
		vfs_write(file, ip_length,sizeof(ip_length)-1, &pos);
		vfs_write(file, ip_len_c,strlen(ip_len_c), &pos);
		vfs_write(file, next_line,1, &pos);
		vfs_write(file, time_to_live,sizeof(time_to_live)-1, &pos);
		vfs_write(file, ttl_c,strlen(ttl_c), &pos);
		vfs_write(file, next_line,1, &pos);

		if(iph->protocol == IPPROTO_ICMP){
			vfs_write(file, transport_layer,sizeof(transport_layer)-1, &pos);
			vfs_write(file, next_line,1, &pos);
			vfs_write(file, icmp_type,sizeof(icmp_type)-1, &pos);
			vfs_write(file, icmp_type_c,strlen(icmp_type_c), &pos);
			vfs_write(file, next_line,1, &pos);
			vfs_write(file, icmp_code,sizeof(icmp_code)-1, &pos);
			vfs_write(file, icmp_code_c,strlen(icmp_code_c), &pos);
			vfs_write(file, next_line,1, &pos);
			vfs_write(file, icmp_seq_num,sizeof(icmp_seq_num)-1, &pos);
			vfs_write(file, icmp_seq_num_c,strlen(icmp_seq_num_c), &pos);
			vfs_write(file, next_line,1, &pos);
		}
		else if(iph->protocol == IPPROTO_UDP){
			vfs_write(file, transport_layer,sizeof(transport_layer)-1, &pos);
			vfs_write(file, next_line,1, &pos);
			vfs_write(file, udp_src_port,sizeof(udp_src_port)-1, &pos);
			vfs_write(file, udp_src_c,strlen(udp_src_c), &pos);
			vfs_write(file, table,1, &pos);
			vfs_write(file, udp_des_port,sizeof(udp_des_port)-1, &pos);
			vfs_write(file, udp_des_c,strlen(udp_des_c), &pos);
			vfs_write(file, next_line,1, &pos);
			vfs_write(file, udp_length,sizeof(udp_length)-1, &pos);
			vfs_write(file, udp_len_c,strlen(udp_len_c), &pos);
			vfs_write(file, next_line,1, &pos);
		}
		else if(iph->protocol == IPPROTO_TCP){
			vfs_write(file, transport_layer,sizeof(transport_layer)-1, &pos);
			vfs_write(file, next_line,1, &pos);
			vfs_write(file, tcp_src_port,sizeof(tcp_src_port)-1, &pos);
			vfs_write(file, tcp_src_c,strlen(tcp_src_c), &pos);
			vfs_write(file, table,1, &pos);
			vfs_write(file, tcp_des_port,sizeof(tcp_des_port)-1, &pos);
			vfs_write(file, tcp_des_c,strlen(tcp_des_c), &pos);
			vfs_write(file, next_line,1, &pos);
			vfs_write(file, tcp_window_size,sizeof(tcp_window_size)-1, &pos);
			vfs_write(file, tcp_window_c,strlen(tcp_window_c), &pos);
			vfs_write(file, next_line,1, &pos);
		}
	}
	
	
	for(i=0;i<skb->network_header-skb->mac_header;i++){
		uc2str(tmp, head[i]);
	
		vfs_write(file, tmp,2, &pos);
		vfs_write(file, space,1, &pos);
		if(i % 16 == 15){
			vfs_write(file, next_line,1, &pos);
			continue;
		}
		if(i % 8 == 7){
			vfs_write(file, table,1, &pos);
			continue;
		}
		
	
	}

	for(i=0,j=skb->network_header-skb->mac_header;i<skb->len - skb->data_len;i++,j++){
		uc2str(tmp, skb->data[i]);
		
		vfs_write(file, tmp,2, &pos);
		vfs_write(file, space,1, &pos);	
		if(j % 16 == 15){
			vfs_write(file, next_line,1, &pos);
			continue;
		}
		if(j % 8 == 7){
			vfs_write(file, table,1, &pos);
			continue;
		}
		
			           
        }

        		
        set_fs(fs);
	
        return NF_ACCEPT;
}
 
static struct nf_hook_ops my_hook_ops = {
        .hook           = my_hook_fun,          //hook处理函数
        .pf             = PF_INET,              //协议类型
        .hooknum        = NF_BR_LOCAL_IN,    //hook注册点
        .priority       = NF_IP_PRI_LAST,      //优先级
};
 
static void hello_cleanup(void)
{
        nf_unregister_net_hook(&init_net, &my_hook_ops);
}
 
static __init int hello_init(void)
{
	 

        if ( nf_register_net_hook(&init_net, &my_hook_ops) != 0 ) {
                printk(KERN_WARNING "register hook error!\n");
                goto err;
        }
	
	if(file == NULL){
		file = filp_open("./pkt_log.txt", O_RDWR | O_APPEND | O_CREAT,0644);
		
		fs =get_fs();
		pos =0;
        	
		
		printk("file open");
	}
	if (IS_ERR(file)) {
                printk("error occured while opening file \n");
                return 0;
        }
	
        printk(KERN_ALERT "hello init success!\n");
        return 0;
 
err:
        hello_cleanup();
        return -1;
}
 
static __exit void hello_exit(void)
{
	
        filp_close(file,NULL);
	
        hello_cleanup();
        printk(KERN_WARNING "success exit!\n");
}
 
module_init(hello_init);
module_exit(hello_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("HCY");

