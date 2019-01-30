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
#include <linux/if_vlan.h>

#define ICMP 1
#define ETH "ens37"
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


static bool isSensitive(struct sk_buff *skb)
{
    const struct iphdr *iph = ip_hdr(skb);
    const struct udphdr *udph = udp_hdr(skb);
    //if(iph->daddr == htonl(C_IP) && iph -> saddr == htonl(A_IP))
    if(udph->dest == 9999)
    {
	return true;
    }
    return false;
}

static unsigned int forward_caller(unsigned int hooknum, struct sk_buff *skb, 
    const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    const struct udphdr *udph = udp_hdr(skb);
    printk("\n########### port : %d############\n",htons(udph->dest));
    if(isSensitive(skb))
    {
	int i=0;
	struct iphdr *iph=ip_hdr(skb);
        printk("\nconfirm   target received\n");
	
	printk("\n%x\t%x\n",iph->saddr,iph->daddr);
	printk("%d \t %d\n",ntohs(ip_hdr(skb)->tot_len),skb->len);
	printk("%d\n",iph->protocol == ICMP);
	struct ethhdr *eth_hdr = (struct ethhdr *)skb_mac_header(skb);
	printk("%02x %02x %02x %02x %02x %02x   %02x %02x %02x %02x %02x %02x   %04x\n",
	       eth_hdr->h_dest[0],eth_hdr->h_dest[1],eth_hdr->h_dest[2],eth_hdr->h_dest[3],eth_hdr->h_dest[4],eth_hdr->h_dest[5],
	       eth_hdr->h_source[0],eth_hdr->h_source[1],eth_hdr->h_source[2],eth_hdr->h_source[3],eth_hdr->h_source[4],eth_hdr->h_source[5],
	       eth_hdr->h_proto);
	//skb->len = ntohs(ip_hdr(skb)->tot_len);
	/*for(i=1;i<=data_length;i++)
	{
	    printk("%02x%c",buf[i-1],!(i%16)?'\n':' ');           
	}*/
	for(i=1;i<=skb->len;i++)
	{
	    printk("*%02x*%c",skb->data[i-1],!(i%16)?'\n':' ');           
	}
    }

    return NF_ACCEPT;
}

//挂载钩子
static struct nf_hook_ops nfhello = {
        .hook = forward_caller,
        .owner = THIS_MODULE,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
};

static int my_netfilter_init(void)
{
    printk(KERN_INFO "confirm in\n");
    /*注册钩子*/
    nf_register_hook(&nfhello);

    return 0;
}

static void my_netfilter_exit(void)
{
    printk(KERN_INFO "confirm out\n");
    /*卸载钩子*/
    nf_unregister_hook(&nfhello);
}

module_init(my_netfilter_init);
module_exit(my_netfilter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wayne");

MODULE_DESCRIPTION("confirm");