#include <linux/time.h> 
#include <linux/init.h>  
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>  
#include <linux/netfilter_ipv4.h>
#include <linux/net.h>
#include <net/ip.h>
#include <linux/if_ether.h>
#include <net/protocol.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/if_vlan.h>

#define ICMP 1
#define ETH "ens33"
#define S_PORT 9988
#define D_PORT 8899

u_long S_IP = 0xAC0A0170;//172.10.1.112
u_long D_IP = 0xAC0A01BD;//172.10.1.189
u_long T_IP = 0xAC140188;//172.20.1.136 target ip
unsigned char S_MAC[ETH_ALEN]={0x00,0x0c,0x29,0x8b,0xb3,0x2e};/*vmware mac*/
unsigned char D_MAC[ETH_ALEN]={0x40,0xA5,0xEF,0x60,0x50,0xF2};/*openwrt mac*/
unsigned char T_MAC[ETH_ALEN]={0x30,0x9c,0x23,0x95,0x6c,0x77};/*win7 mac*/

static int construct_send(char *eth, u_char *smac, u_char *dmac,
            u_char *pkt, int pkt_len,u_long sip, u_long dip, u_short sport, u_short dport)
{
    int ret = -1;
    unsigned int pktSize;
    struct sk_buff *skb = NULL;
    struct net_device *dev = NULL;
    struct ethhdr *ethheader = NULL;
    struct iphdr *ipheader = NULL;
    struct udphdr *udpheader = NULL;
    u_char *pdata = NULL;

    /*参数合法性检查*/
    if(NULL == smac || NULL == dmac)
        goto out;

    /*通过出口接口名称获取接口设备信息*/
    dev = dev_get_by_name(&init_net, eth);
    if(NULL == dev)
    {
        printk(KERN_ERR "unknow device name:%s\n", eth);
        goto out;
    }

    /*计算报文长度*/
    pktSize = pkt_len + sizeof(struct iphdr) + sizeof(struct udphdr) + LL_RESERVED_SPACE(dev);
    skb = alloc_skb(pktSize, GFP_ATOMIC);
    if(NULL == skb)
    {
        printk(KERN_ERR "malloc skb fail\n");
        goto out;
    }
    
    /*在头部预留需要的空间*/
     skb_reserve (skb, pktSize);

    skb->dev = dev;
    skb->pkt_type = PACKET_OTHERHOST;
    skb->protocol = __constant_htons(ETH_P_IP);
    skb->ip_summed = CHECKSUM_NONE;//udp校验和初始化
    skb->priority = 0;

    pdata = skb_push(skb, pkt_len);
    if(NULL != pkt)
        memcpy(pdata, pkt, pkt_len);

    /*填充udp头部*/
    udpheader = (struct udphdr*)skb_push(skb, sizeof(struct udphdr));
    memset(udpheader, 0, sizeof(struct udphdr));
    udpheader->source = htons(sport);
    udpheader->dest = htons(dport);
    skb->csum = 0;
    udpheader->len = htons(sizeof(struct udphdr) + pkt_len);
    udpheader->check = 0;
    skb_reset_transport_header(skb);

    /*填充IP头*/
    ipheader = (struct iphdr*)skb_push(skb, sizeof(struct iphdr));
    ipheader->version = 4;
    ipheader->ihl = sizeof(struct iphdr) >> 2;//ip头部长度
    ipheader->frag_off = 0;
    ipheader->protocol = IPPROTO_UDP;
    ipheader->tos = 0;
    ipheader->saddr = htonl(sip);
    ipheader->daddr = htonl(dip);
    ipheader->ttl = 0x40;
    ipheader->tot_len = htons(pkt_len + sizeof(struct iphdr) + sizeof(struct udphdr));
    ipheader->check = 0;
    ipheader->check = ip_fast_csum((unsigned char *)ipheader, ipheader->ihl);
    skb_reset_network_header(skb);
    
    skb->csum = skb_checksum(skb, ipheader->ihl*4, skb->len-ipheader->ihl*4, 0);
    udpheader->check = csum_tcpudp_magic(sip, dip, skb->len-ipheader->ihl*4, IPPROTO_UDP, skb->csum);

    /*填充MAC*/
    ethheader = (struct ethhdr*)skb_push(skb, 14);
    memcpy(ethheader->h_dest, dmac, ETH_ALEN);
    memcpy(ethheader->h_source, smac, ETH_ALEN);
    ethheader->h_proto = __constant_htons(ETH_P_IP);
    skb_reset_mac_header(skb);
    
    /*send pkt
        dev_queue_xmit发送之后会释放相应的空间。
        因此注意不能做重复释放
    */
    if(0 > dev_queue_xmit(skb))
    {
        printk(KERN_ERR "send pkt error");
        goto out;
    }
    ret = 0;
    
    printk(KERN_INFO "send success\n");
out:
    if(ret != 0 && NULL != skb)
    {
        dev_put(dev);
        kfree_skb(skb);
    }
    return NF_ACCEPT;
}


static unsigned int forwarder(void *priv,
                   struct sk_buff *skb,
                   const struct nf_hook_state *state)
{
    
    const struct iphdr *iph = ip_hdr(skb);
    //filter icmp    
    //printk("%u\n",iph->saddr);
    if((iph->saddr == S_IP || iph->saddr == ntohs(S_IP))&& likely(iph->protocol==IPPROTO_UDP))
    {
        printk(KERN_INFO "received target message");
	int i;
	struct ethhdr *eth_hdr = (struct ethhdr *)skb_mac_header(skb);
	//iph->saddr = htonl(D_IP);
	//iph->daddr = htonl(T_IP);
	u_long t_ip = htonl(T_IP);
	/*memcpy(&(iph->saddr),&(iph->daddr),sizeof(u_long));
	memcpy(&(iph->daddr),&t_ip,sizeof(u_long));
	memcpy(eth_hdr->h_source,&eth_hdr->h_dest,ETH_ALEN);
	memcpy(eth_hdr->h_dest,&T_MAC,ETH_ALEN);
	//iph->check = 0;
	//iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
	memset(&(iph->check),0,sizeof(__be16));
	__be16 csum = ip_fast_csum((unsigned char *)iph, iph->ihl);
	memset(&(iph->check),csum,sizeof(__be16));*/
	
	struct udphdr *udph;
	udph=udp_hdr(skb);
        unsigned char *data=skb->data+iph->ihl*4+sizeof(struct udphdr);
	construct_send("eth1",D_MAC,T_MAC,data,ntohs(iph->tot_len)-iph->ihl*4-sizeof(struct udphdr),
	    D_IP,T_IP,8899,9988);
	
	
	/*if(0 > dev_queue_xmit(skb))
	{
	    printk(KERN_ERR "send pkt error\n");
	}
	else
	{
	    printk("send success\n");
	}*/
	return NF_DROP;
    }

    return NF_ACCEPT;
}

//挂载钩子
static struct nf_hook_ops nffwd = {
        .hook = forwarder,
        //.owner = THIS_MODULE,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
};

static int my_netfilter_init(void)
{
    printk(KERN_INFO "Forwarder, conponant 2. Loading\n");
    /*注册钩子*/
    nf_register_hook(&nffwd);

    return 0;
}

static void my_netfilter_exit(void)
{
    printk(KERN_INFO "Forwarder, conponant 2, Unloading\n");
    /*卸载钩子*/
    nf_unregister_hook(&nffwd);
}

module_init(my_netfilter_init);
module_exit(my_netfilter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wayne");

MODULE_DESCRIPTION("Forwarder, conponant 2");