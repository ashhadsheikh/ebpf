#include <bcc/proto.h>

struct ifc_info {
  u32 ifindex; //phy interface number on which clone redirect will be called.
  u32 ip_address; //IP address assigned to the interface ( virtual )
  u64 mac_address; // virtual mac adderss assign to the physical interface.
  u64 rx_pkts; // increment when pkt reciencved i.e . when router function called.
  u64 tx_pkts;  // increment when clone redirect called.
};

struct router_host_info {
  u32 ifc_index; // conf_interface table key. before sending the packet, we will lookup conf_interface table and get relivent info.
  u64 dest_mac; // when sending packets out ( clone redirect ) we will put this mac as destionaiton mac.
};



//Interface Info Table
BPF_TABLE("hash", u32, struct ifc_info, conf_interface, 10);
///ARP TABLE
BPF_TABLE("hash", u32, struct router_host_info, r_arp_table, 1024); //here key represents IPaddress


int router_function(struct __sk_buff *skb) {

  //u32 ifindex = skb->ifindex;

 u32 fromWhere= skb->cb[0];
  struct ifc_info *my_info = conf_interface.lookup( &fromWhere);
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  bpf_trace_printk("Packet just came to router !\\n");
if(ethernet->type == 0x0806){
  struct arp_t *arp = cursor_advance(cursor, sizeof(*arp));
  bpf_trace_printk("Router: I recieved an ARP PACKET !\\n");
  u32 dst_ip = arp->tpa;
  u32 src_ip = arp->spa;
  
  u64 src_mac = ethernet->src;
  struct router_host_info host = {};
  host.ifc_index = fromWhere;
  host.dest_mac = ethernet->src;
  r_arp_table.lookup_or_init(&src_ip, &host);
  if ( my_info && arp->oper == 1 && dst_ip == my_info->ip_address){
    bpf_trace_printk("Router: Oh, This Packet is for my, I should send a response !\n");
    ethernet->src = my_info->mac_address;
    bpf_trace_printk("IP: %llu",my_info->mac_address);
    ethernet->dst = src_mac;
    arp->tha = src_mac;
    arp->tpa = src_ip;
    arp->spa = dst_ip;
    arp->sha = my_info->mac_address;
    u64 operation=2;
    arp->oper = operation;
    bpf_trace_printk("Oper : %u",arp->oper);
    struct ifc_info *ifindex_p=conf_interface.lookup(&fromWhere);
    if(ifindex_p){
    bpf_trace_printk("Response Sent to : %u",ifindex_p->ifindex);
         bpf_clone_redirect(skb, ifindex_p->ifindex, 1/*ingress*/);
         return 0;
    }

   }
}else if(ethernet->type == 0x0800){
bpf_trace_printk("I recieved an IP PACKET !\\n");
      struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
      u32 pkt_dst = ip->dst;
      struct router_host_info *host_dst = r_arp_table.lookup(&pkt_dst);
      if (host_dst && my_info){
        ethernet->src = my_info->mac_address;
        ethernet->dst = host_dst->dest_mac;
        bpf_clone_redirect(skb, host_dst->ifc_index, 1/*ingress*/);
        return 0;
      }
}	
  return 0;
}
