#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/jiffies.h>
#include <linux/moduleparam.h>
#include <linux/atomic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arina Sofiyeva");
MODULE_DESCRIPTION("Netfilter LKM to mitigate ICMP ping flood attacks");

// Netfilter hook structure
static struct nf_hook_ops nfho;
static unsigned int icmp_rate_limit = 100;  // 100 pings per second allowed
					    
module_param(icmp_rate_limit, uint, 0644);
MODULE_PARM_DESC(icmp_rate_limit, "ICMP Echo Request rate limit per second");

// State for rate limiting
// Atomic vars are used here to prevent race conditions
static atomic_long_t last_time_jiffies = ATOMIC_LONG_INIT(0); 
static atomic_t ping_count = ATOMIC_INIT(0);

// Hook function to filter packets
static unsigned int block_icmp_ping(void *priv, struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;

    // tracking current time and time of the last accepted packet
    unsigned long current_jiffies, last_jiffies;
    // a local counter of pings
    int current_pings = 0;

    // if socket buffer does not exist, let it pass     
    if (!skb) return NF_ACCEPT;
    // Get IP header from socket buffer
    ip_header = ip_hdr(skb);

    // if ip header does not exist, let it pass 
    if (!ip_header) return NF_ACCEPT;
    // Check if protocol is ICMP
    if (ip_header->protocol == IPPROTO_ICMP) {
        icmp_header = icmp_hdr(skb);   // get ICMP header
        if (!icmp_header) {
            return NF_ACCEPT;  // cannot retrieve ICMP header, let it pass
        }

        // Check for ICMP request
        if (icmp_header->type == ICMP_ECHO) {
		// jiffies are stored into a local variable
		current_jiffies = jiffies;
		// Read last_time_jiffies and store into a local var
		last_jiffies = atomic_long_read(&last_time_jiffies);

                // Checking if less that one second has passed since the last recorded packet
		// In my system, HZ is 100, meaning jiffies increment 100 times per sec
                if (current_jiffies - last_jiffies < HZ) {
			// Increment the number of pings and store into a local var 
                	current_pings = atomic_inc_return(&ping_count);
		} else {
                	// New time window, reset counter
                	atomic_long_set(&last_time_jiffies, current_jiffies); // set atomic last_time_jiffies to have a value of current time
			atomic_set(&ping_count, 1); // set atomic ping_count to 1 (reset)
                	current_pings = 1; // set a local copy of pings to 1 (reset)
		}

            	// If num exceeds the threshold, drop the packet
            	if (atomic_read(&ping_count) > icmp_rate_limit) {
                	printk(KERN_INFO "PING FLOOD: Dropping ICMP Echo from %pI4 (count=%u)\n",
                       	&ip_header->saddr, atomic_read(&ping_count)); // dmesg to see logs
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

