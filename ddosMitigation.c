#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arina Sofiyeva");
MODULE_DESCRIPTION("A LKM to mitigate DDOS");
MODULE_VERSION("0.1");

static struct nf_hook_ops * ping_ops = NULL;

static unsigned int icmp_tester(void * priv, struct sk_buff * skb, const struct nf_hook_state * state) {
	if (skb == NULL) {
		return NF_ACCEPT;
	}
	
	struct iphdr * ip_header;
	struct icmphdr * icmp_header;

	ip_header = ip_hdr(skb);

	if (ip_header->protocol == IPPROTO_ICMP) { 
		icmp_header = icmp_hdr(skb);
		pr_info("ICMP packet source: %pI4 | dest: %pI4 | type: %u | code: %u | checksum : 0x%hx\n", &(ip_header->saddr), &(ip_header->daddr), icmp_header->type, icmp_header->code, ntohs(icmp_header->checksum));
		return NF_ACCEPT;
	}
	else {
		return NF_DROP;
	}
}

static int __init ping_flood_init(void) {
	printk(KERN_INFO "Hello, world\n");

	ping_ops = kzalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (!ping_ops) {
		pr_err("no memeory allocated");
		return -1;
	}

	ping_ops->hook = icmp_tester;
	ping_ops->pf = PF_INET;
	ping_ops->hooknum = NF_INET_PRE_ROUTING;
	ping_ops->priority = NF_IP_PRI_FIRST;

	int register_status = nf_register_net_hook(&init_net, ping_ops);
	if (register_status < 0) {
		pr_err("failed");
		kfree(ping_ops);
		return -1;
	}

	pr_info("module loaded!!!");
	return 0;
}

static void __exit ping_flood_exit(void) {
	printk(KERN_INFO "Goodbye\n");

	if (ping_ops) {
		nf_unregister_net_hook(&init_net, ping_ops);
		kfree(ping_ops);
	}
	
	pr_info("module is unloaded!!!");
}

module_init(ping_flood_init);
module_exit(ping_flood_exit);


