#include <bcc/proto.h>


/*struct config {
  u32 ifindex;
};


//Config Table
BPF_TABLE("hash", int, struct config, conf_ifc, 10);
//BPF TABLES TO CONTAIN ALL PROGRAMS INFO
*/
BPF_TABLE("prog", u32, u32, vnf_prog, 1);

int forwarding_function(struct __sk_buff *skb) {
 u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  
    u32 ifindex=skb->ifindex;
      skb->cb[0]=ifindex;
      bpf_trace_printk("Bridge: Packet came to me.");
      bpf_trace_printk("MAC : %llu \\n",ethernet->dst);
      //bpf_clone_redirect(skb,ifindex_p->ifindex, 1 /*ingress*/);
      vnf_prog.call(skb, 0); ///0 is the key in for accessing the routing function from map
      
  return 1;
}
