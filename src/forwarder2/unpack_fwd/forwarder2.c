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
#define ETH "ens38"
#define S_PORT 9988
#define D_PORT 8899

u_long A_IP = 0x0A0A0A03;//10.10.10.3
u_long B1_IP = 0x0A0A0A02;//10.10.10.2
u_long B2_IP = 0xC0A80A02;//192.168.10.2
u_long C_IP = 0xC0A80A03;//192.168.10.3
unsigned char A_MAC[ETH_ALEN]={0x00,0x0c,0x29,0x8b,0xb3,0x38};
unsigned char B1_MAC[ETH_ALEN]={0x00,0x0c,0x29,0xf5,0xe5,0x21};
unsigned char B2_MAC[ETH_ALEN]={0x00,0x0c,0x29,0xf5,0xe5,0x2b};
unsigned char C_MAC[ETH_ALEN]={0x00,0x0c,0x29,0xf5,0x71,0xa3};

static bool isSendSensitive(struct sk_buff *skb)
{
    const struct iphdr *iph = ip_hdr(skb);
    if(iph->saddr == htonl(A_IP) && likely(iph->protocol==IPPROTO_UDP)){
	return true;
    }
    return false;
}

static bool isRecvSensitive(struct sk_buff *skb)
{
    if(iph->saddr == htonl(C_IP))
    {
	return true;
    }
    return false;
}

static unsigned int send(void *priv,
                   struct sk_buff *skb,
                   const struct nf_hook_state *state)
{
    
    const struct iphdr *iph = ip_hdr(skb);
    
    if(isSendSensitive(skb))
    {
	int i;
	struct ethhdr *eth_hdr = (struct ethhdr *)skb_mac_header(skb);
	u_long t_ip = htonl(C_IP);
	
	struct udphdr *udph;
	udph=udp_hdr(skb);
	int data_length=ntohs(iph->tot_len)-iph->ihl*4-sizeof(struct udphdr);
	memmove(skb->data+14,skb->data+28,data_length);
	eth_hdr = (struct ethhdr *)skb_mac_header(skb);
	memcpy(eth_hdr->h_source,B2_MAC,ETH_ALEN);
	memcpy(eth_hdr->h_dest,C_MAC,ETH_ALEN);
	eth_hdr->h_proto = __constant_htons(ETH_P_IP);
	memmove(skb->data,eth_hdr,14);
	skb->len -= 14;
	struct net_device *dev = dev_get_by_name(&init_net, "ens38");
	skb->dev = dev;
	
	iph = ip_hdr(skb);
	u_short ipcksum = 0;
	memmove(skb->data + 24,&ipcksum,2);
	u_long tmp = ntohl(B2_IP);
	memmove(skb->data+26,&tmp,4);
	ipcksum = ip_fast_csum((unsigned char *)(skb->data+14), 20);
	u_short cktmp = ipcksum + 0x9395;
	if(cktmp < ipcksum){
	  //ipcksum -= 0x10000;
	  ipcksum += 0x9396;
	}
	else{
	  ipcksum += 0x9395;
	}
	memmove(skb->data + 24,&ipcksum,2);	
	skb->csum = skb_checksum(skb, iph->ihl*4, skb->len-iph->ihl*4, 0);
	
	if(0 > dev_queue_xmit(skb))
	{
	    printk(KERN_ERR "send pkt error\n");
	}
	return NF_STOLEN;
    }

    return NF_ACCEPT;
}


static unsigned int recv(void *priv,
		    struct sk_buff *skb,
                   const struct nf_hook_state *state)
{
	const struct iphdr *iph = ip_hdr(skb);
	if(isRecvSensitive(skb)){
	
	//mod ip header
	u_short cksm = 0;
	u_long a_ip = htonl(A_IP);
	memmove(&(iph->daddr),&a_ip,sizeof(u_short));
	memmove(&(iph->check),&cksm,sizeof(u_short));
	cksm = ip_fast_csum((unsigned char *)iph, iph->ihl);
	memmove(&(iph->check),&cksm,sizeof(u_short));	
		
	//mod dev
	struct net_device *dev = dev_get_by_name(&init_net, "ens37");
	skb->dev = dev;
		
	//mod eth header
	struct ethhdr *eth_hdr = (struct ethhdr*)skb_push(skb, 14);
	memmove(eth_hdr->h_source,B1_MAC,ETH_ALEN);
	memmove(eth_hdr->h_dest,A_MAC,ETH_ALEN);
	eth_hdr->h_proto = __constant_htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	
	if(0 > dev_queue_xmit(skb))
	{
	    printk(KERN_ERR "send pkt error\n");
	}
	return NF_STOLEN;
    }
    return NF_ACCEPT;
}	

static struct nf_hook_ops fwder_send = {
        .hook = forwarder,
        //.owner = THIS_MODULE,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops fwder_recv = {
        .hook = rev_forwarder,
        //.owner = THIS_MODULE,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
};

static int fwder_init(void)
{
    printk(KERN_INFO "Forwarder, conponant 2. Loading\n");
    // load hooks
    nf_register_hook(&fwder_send);
    nf_register_hook(&fwder_recv);

    return 0;
}

static void fwder_exit(void)
{
    printk(KERN_INFO "Forwarder, conponant 2, Unloading\n");
    // unload hooks
    nf_unregister_hook(&fwder_send);
    nf_unregister_hook(&fwder_recv);
}

module_init(fwder_init);
module_exit(fwder_exit);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Wayne");

MODULE_DESCRIPTION("Forwarder, conponant 2");