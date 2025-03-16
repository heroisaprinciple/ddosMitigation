This project was completed as part of the NW Stack Implementation module, focusing on implementing a DDoS mitigation mechanism using Netfilter and a Linux Kernel Module (LKM) on a Raspberry Pi 4 (ARM x64 processor).

The primary goal was to detect and mitigate ICMP flood attacks, which is done by rate and size of packets limiting.

<h1>Building a Linux Kernel Module</h1>
A LKM requires a GPL for legal reasons as well as author’s name and module description:

````
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
````

Makefile is necessary in the compilation process. Here, I define that I want to see an object file. I specify the path to the kernel's modules, so the kernel would understand that this is a kernel module and it needs to be treated accordingly. After running `sudo make`, .ko file will be generated and loaded into the kernel:

````
# an obj file
obj-m += ddosMitigation.o

# linux kernel headers are here
KDIR = /lib/modules/$(shell uname -r)/build

# a target, tells the kernel to build the module
all:
	make -C $(KDIR) M=$(shell pwd) modules

# removes generated files with sudo clean 
clean:
	make -C $(KDIR) M=$(shell pwd) clean
````


To load this module, user should be a root user. With `dmesg | tail -n`, the kernel logs are seen, meaning the module was loaded successfully after doing `insmod ddosMitigation.ko`, which loads the module into the kernel.

<h1>Code in ddosMitigattion.c</h1>
Netfilter uses a hook system. Everytime a packet goes into the network stack, INET_PRE_ROUTING hook is triggered. After the kernel decides where to route this packet, INET_FORWARD hook is triggered. INET_POST_ROUTING is triggered when the packet leaves the linux machine. If those packets are to be processed locally, for userspace applications, hooks INET_LOCAL_IN and INET_LOCAL_OUT are triggered after INET_PRE_ROUTING and before INET_POST_ROUTING.  In my code I create an nfho structure that  will trigger the INET_PRE_ROUTING hook in ddos_icmp_init():

````
// Netfilter hook structure 
static struct nf_hook_ops nfho;
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
````

ddos_icmp_init(void) is not an ordinary function. It has an __init macro, meaning it will be responsible for LKM initialization. When the module is loaded, the message “ICMP flood mitigation module is loaded…” will appear (seen with `dmesg` command). The proof of that is the last screenshot in the Building an LKM section.  Here, I’ll be populating my structure. The business logic of filtering packets will be inside the block_icmp_ping() function that I’ll explain a little later. For now, I am calling it to be a hook. The field nfho.pf = PF_INET means that only IPv4 packets are to be received. The field nfho.hooknum = NF_INET_PRE_ROUTING means that block_icmp_ping() will be triggered at the pre-routing stage and nfho.priority = NF_IP_PRI_FIRST means that this hook has highest priority. 

````
 nf_register_net_hook(&init_net, &nfho); basically registers this hook.  If the register was not successful, errors will be shown in kernel logs.
````

When deregistering the module, the corresponding message will appear:

````
// Module cleanup: unregister Netfilter hook
static void __exit ddos_icmp_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    pr_info("ICMP flood mitigation module unloaded\n");
}
````

The main logic is in block_icmp_ping(). First things first, I am creating structures of ip and icmp headers:

````
static unsigned int block_icmp_ping(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    unsigned int packet_size;

    // if socket buffer does not exist, let it pass     
    if (!skb) return NF_ACCEPT;
    // Get IP header from socket buffer
    ip_header = ip_hdr(skb);
````

Then, I check if skb is NULL. Kernel should drop only existing packets, so skb is NULL, NF_ACCEPT is returned. This was confusing for me at first, because why would the kernel accept the packet that does not exist? Normally, when NF_ACCEPT is returned for a valid skb (non-NULL), the packet continues through the network stack, but when skb is NULL, there is no actual packet to continue, so the function just exits without doing anything. So, the kernel simply ignores the NULL skb and moves on. What is skb and sk_buffer? This is a socket buffer that has all the information about the packet. It operates at the kernel level. The most interesting part is that when a user creates a socket in the userspace, then this socket will point to the socket struct in the kernel and this struct will point to the sock struct, which has a protocol-specific information.  When a packet is received, it is stored in an sk_buff and added to the receive queue of struct sock. When a user sends data, the data is wrapped into an sk_buff, processed by the network stack, and sent to the network interface card:

````
// if ip header does not exist, let it pass 
    if (!ip_header) return NF_ACCEPT;
    // Check if protocol is ICMP
    if (ip_header->protocol == IPPROTO_ICMP) {
        icmp_header = icmp_hdr(skb);   // get ICMP header
        if (!icmp_header) {
            return NF_ACCEPT;  // cannot retrieve ICMP header, let it pass
        }
````

Then, I get the ip header from the socket buffer and check if it exists. If it is NULL, then I let it pass. The reason for that is that I allow the Linux kernel to handle it itself. If I drop them, then I could drop non-malicious packets. Sometimes packets just don’t have full headers. The same happens if the ICMP header does not exist. Blocking all ICMP packets with no or not full header would be inefficient. The kernel would do its job. The Linux networking stack has error handling mechanisms for dealing with malformed or corrupted packets, so after NF_ACCEPT, the packet continues through the kernel’s TCP/IP stack. The network stack parses the packet headers (IP, ICMP, etc.) to determine if it is valid. In <a href="https://github.com/torvalds/linux/blob/master/net/ipv4/icmp.c"> icmp.c </a> of the source code, it is seen that  the kernel implements strict header validation for ICMP packets, for instance is the packet long enough to contain a full ICMP header? (line 1237, icmp.c) or does the ICMP checksum match? (line 1234, icmp.c). If the packet fails these checks, the kernel will drop it automatically.
Otherwise, it proceeds. How does DDOS mitigation actually happen in my code? This is done by rate-limiting ping requests to prevent a ping flood attack. ICMP rate limit is set to 100, meaning only 100 pings per second are allowed. Moreover, I set a limit to the packet size. MTU is 1500 bytes, 28 bytes are required for IP and ICMP headers.  

````
static unsigned int icmp_rate_limit = 100;  // 100 pings per second allowed
static unsigned int max_packet_size = 1472; // max ICMP packet size: MTU of 1500 bytes - 28 bytes
````

Jiffies represent the number of clock ticks. Jiffies global variable comes from <linux/jiffiies.h>.
Ping_count will represent the number of pings. This value will be compared with the maximum rate to prevent ping flood. Additionally, the best practice is not to use global variables in the kernel. If there is a must, use spinlocks or semaphores. They might not improve my code implementation, as this would effectively let the attacker win because we would wait as one processor unlocks resources and give it to other cpus and this would not be efficient. The best option is to use local variables or automic. Atomics are quite interesting because they say that operations would be automic: fast and prevent race conditions. 
I’ll update the two tracking variables in my code later, but they are set to 0 for now. 

````
// State for rate limiting
// Atomic vars are used here to prevent race conditions
static atomic_long_t last_time_jiffies = ATOMIC_LONG_INIT(0); 
static atomic_t ping_count = ATOMIC_INIT(0);
````

If less than one second has passed ````(jiffies - last_time_jiffies < HZ)````, I’ll increase the ping number. Otherwise, if one second passes, I’ll set a new timestamp and set the ping number as 1. The size is checked here as well:

````
// Check for ICMP request
if (icmp_header->type == ICMP_ECHO) {
		// Getting a packet size from IP header 
		packet_size = ntohs(ip_header->tot_len);
		
		// check for size of the packet
		if (packet_size > max_packet_size) {
          printk(KERN_INFO "TOO LARGE: Dropping a packet from %pI4 (size=%u)\n", &ip_header->saddr, packet_size);
          return NF_DROP;
		}

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
          printk(KERN_INFO "PING FLOOD: Dropping ICMP Echo from %pI4 (count=%u)\n", &ip_header->saddr, atomic_read(&ping_count)); // dmesg to see logs
          return NF_DROP;
    }
````

If ping_count exceeds icmp_rate_limit, which is set as 100 (100 pings per second allowed), the kernel logs a message (printk(KERN_INFO)) showing the source IPv4 address (%pI4), the number of pings received from this source and drops the packet (return NF_DROP) , so the ping never reaches its destination. 
Any other traffic is accepted:

````
// Accept all other traffic or ICMP below threshold
return NF_ACCEPT
````

<h1>Test</h1>

To test this project, compile code with ````sudo make````.
Then, load the module with ````sudo insmod ddosMitigation.lo````


1) Test 150 pings per second with ````ping -i 0.005 -c 150 [ipAddr]````

![img](https://imgur.com/6SRy8wO.png)


![img](https://imgur.com/aD1JNbU.png)

100 packets and 50 packets would be dropped within 0.93s. What about kernel logs? After ````dmesg````, it would be seen that 50 packets were dropped by the kernel with the message <i>PING FLOOD: Dropping ICMP Echo from [ipAddr] (count = [n]) </i>


![img](https://imgur.com/7tb58Rw.png)



2) Test 500 packets that are processed with maximum speed. Run ````sudo tcpdump -i any icmp```` in one terminal window to see packets flow and ````ping -f -c 500 [ipAddr]```` in another terminal window. 
500 packets would be transmitted and received. In the right terminal window there would be 186 packets dropped, which is checked with ````dmesg | grep "PING FLOOD" | wc -l```` :



![img](https://imgur.com/1CTIYIc.png)



![img](https://imgur.com/kQuAKdV.png)


5) Test a thousand packets that are processed with maximum speed. Run ````sudo tcpdump -i any icmp```` in one terminal window to see packets flow and ````ping -f -c 1000 [ipAddr]```` in another terminal window. 
1000 packets would be transmitted, 628 received. In the right terminal window there would be 372 packets dropped.


![img](https://imgur.com/sBRVgCu.png)


![img](https://imgur.com/mJXUqVR.png)

