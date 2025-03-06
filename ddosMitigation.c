#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/jiffies.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arina Sofiyeva");
MODULE_DESCRIPTION("Netfilter LKM to mitigate ICMP ping flood attacks");

// Netfilter hook structure
static struct nf_hook_ops nfho;
// Rate limit threshold (ICMP echo requests per second)
static unsigned int icmp_rate_limit = 100;  // 100 pings per second allowed
module_param(icmp_rate_limit, uint, 0644);
MODULE_PARM_DESC(icmp_rate_limit, "ICMP Echo Request rate limit per second");

// State for rate limiting
static unsigned long last_time_jiffies = 0;
static unsigned int ping_count = 0;

// Hook function to inspect and filter packets
static unsigned int block_icmp_ping(void *priv, struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;

    if (!skb) return NF_ACCEPT;
    // Get IP header from socket buffer
    ip_header = ip_hdr(skb);
    if (!ip_header) return NF_ACCEPT;
    // Check if protocol is ICMP
    if (ip_header->protocol == IPPROTO_ICMP) {
        icmp_header = icmp_hdr(skb);   // get ICMP header
        if (!icmp_header) {
            return NF_ACCEPT;  // cannot retrieve ICMP header, let it pass
        }

        // Check for ICMP Echo Request (ping)
        if (icmp_header->type == ICMP_ECHO) {
            // Update rate limiting counter (per one-second interval)
            if (jiffies - last_time_jiffies < HZ) {
                ping_count++;
            } else {
                // New time window, reset counter
                last_time_jiffies = jiffies;
                ping_count = 1;
            }
            // If count exceeds the threshold, drop the packet
            if (ping_count > icmp_rate_limit) {
                printk(KERN_INFO "PING FLOOD: Dropping ICMP Echo from %pI4 (count=%u)\n",
                       &ip_header->saddr, ping_count);
                return NF_DROP;
            }
        }
    }
    // Accept all other traffic or ICMP below threshold
    return NF_ACCEPT;
}

// Module initialization: register Netfilter hook
static int __init ddos_icmp_init(void) {
    nfho.hook = block_icmp_ping;
    nfho.pf = PF_INET;                      // IPv4
    nfho.hooknum = NF_INET_PRE_ROUTING;     // intercept inbound packets early
    nfho.priority = NF_IP_PRI_FIRST;        // highest priority
    if (nf_register_net_hook(&init_net, &nfho) != 0) {
        pr_err("Failed to register Netfilter hook\n");
        return -1;
    }
    pr_info("ICMP flood mitigation module loaded (rate limit = %u pings/sec)\n", 
            icmp_rate_limit);
    return 0;
}

// Module cleanup: unregister Netfilter hook
static void __exit ddos_icmp_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    pr_info("ICMP flood mitigation module unloaded\n");
}

module_init(ddos_icmp_init);
module_exit(ddos_icmp_exit);

