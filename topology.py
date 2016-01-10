#!/usr/bin/env python

from bcc import BPF
from builtins import input
from ctypes import c_uint, c_int, c_ulong
from pyroute2 import IPRoute, IPDB, NSPopen
from simulation import Simulation
from netaddr import IPAddress
from unittest import main, TestCase
from time import sleep
import sys
import socket
import struct
import subprocess
ipr = IPRoute()
ipdb = IPDB(nl=ipr)
sim = Simulation(ipdb)

class VM(object):

    def __init__(self, name, id, IPaddress, vethOut):
        self.name = name
        self.id = id
        self.IPaddress = IPaddress
        self.vethOut = vethOut


class Bridge(object):

    def __init__(self, name, id):
        self.name = name
        self.id = id

class Dummy(object):

    def __init__(self, name, id):
        self.name = name
        self.id = id


class TunnelSimulation(Simulation):

    def __init__(self, ipdb):
        super(TunnelSimulation, self).__init__(ipdb)
        self.ns_array = []
        self.br_array = []
        self.dm_array = []


    def mac2bin(self, mac):
        temp = "\0\0" + mac.replace(':', '').decode('hex')
        addr, = struct.unpack('!Q', temp)
        return addr


    def ip2bin(self, addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]

    def create_VM(self, name, IP):
        (ns1_ipdb, self.ns1_eth_out, _) = sim._create_ns(name, ipaddr=IP + '/24', disable_ipv6=True)
        self.ns_array.append(VM(name, ns1_ipdb, IP, self.ns1_eth_out))

    def create_bridge(self, br):
        with ipdb.create(ifname=br, kind="bridge") as br1:
            br1.up()
            self.br_array.append(Bridge(br, br1))
        subprocess.call(["sysctl", "-q", "-w", "net.ipv6.conf." + br + ".disable_ipv6=1"])

    def setup_bridge(self, br_info, ifc_info):
        br_info.id.add_port(ifc_info).commit()

    def create_dummy_ifc(self, str_name):
        if str_name in ipdb.interfaces:
            self.del_dummy_ifc(str_name)
        return ipdb.create(ifname=str_name, kind="dummy").up().commit()

    def del_dummy_ifc(self, str_name):
        if str_name in ipdb.interfaces:
            ipdb.interfaces[str_name].remove().commit()

    def set_bpf_ingress(self, ifc, fn):
        ipr.tc("add", "ingress", ifc.index, "ffff:")
        ipr.tc("add-filter", "bpf", ifc.index, ":1", fd=fn.fd,
               name=fn.name, parent="ffff:", action="drop", classid=1)

    def set_bpf_egress(self, ifc, fn):
        ipr.tc("add", "sfq", ifc.index, "1:")
        ipr.tc("add-filter", "bpf", ifc.index, ":1", fd=fn.fd,
               name=fn.name, parent="1:", action="drop", classid=1)

    def set_map_value(self, map, key, value):
        map[map.Key(key)] = map.Leaf(value)
    

    def set_RTR_map_value(self, map, key,ifindex,ip,mac):
        map[map.Key(key)] = map.Leaf(ifindex,ip,mac,0,0)


    def create_router(self, name,subnet):
	#Loading ebpf code 
        interface_code = BPF(src_file="interface1.c")
        rtr_interface_code = BPF(src_file="router.c")
	#Loading ebpf Functions 
        forwarding_fn = interface_code.load_func("forwarding_function", BPF.SCHED_CLS)
	routing_fn = rtr_interface_code.load_func("router_function", BPF.SCHED_CLS)
	#Loading ebpf Maps 
	self.vnf_prog   = interface_code.get_table("vnf_prog")
        #self.configuration_table = interface_code.get_table("conf_ifc")
        self.rtr_configuration_table = rtr_interface_code.get_table("conf_interface")


        self.vnf_prog[c_int(0)] = c_int(routing_fn.fd)


	for sub in range(0,subnet):
            self.dm_array.append(Dummy('dummy%d' % (sub),self.create_dummy_ifc('dummy%d' % (sub))))
	    self.setup_bridge(self.br_array[sub], self.dm_array[sub].id)
            self.set_bpf_egress(self.dm_array[sub].id,forwarding_fn)
	    print 'Dummy %d index %d' % (sub,self.dm_array[sub].id.index) 
	    self.set_RTR_map_value(self.rtr_configuration_table,self.dm_array[sub].id.index,self.dm_array[sub].id.index,self.ip2bin('192.168.%d.1' % (sub+5)),self.mac2bin('0d:b5:2f:54:0b:%df'% (sub+5)))
	   

    def add_values(self,subnet,VMs):
	x = 0
	for sub in range(5,subnet+5):
   	    for mac in range(2,VMs+2):
		print 'ns_array[%d], ARP address:  192.168.%d.1' % (x,sub)
                cmd1 = ["route", "add", "default", "gw",'192.168.%d.1' % (sub)]
                nsp = NSPopen(self.ns_array[x].id.nl.netns, cmd1)
                nsp.wait(); nsp.release()
                cmd1 = ["arping", "-c", "1", "-I", "eth0", '192.168.%d.1' % (sub),"-q"]
                nsp = NSPopen(self.ns_array[x].id.nl.netns, cmd1)
                nsp.wait(); nsp.release()
		x+=1


    def test_topology(self):
            nsp = NSPopen(self.ns_array[0].id.nl.netns, ["ping", "192.168.6.2", "-c", "2"]); nsp.wait(); nsp.release()
            # one arp request/reply, 2 icmp request/reply per VM, total 6 packets per VM, 12 packets total
            nsp_server = NSPopen(self.ns_array[2].id.nl.netns, ["iperf", "-s", "-xSC"])
            sleep(1)
            nsp = NSPopen(self.ns_array[0].id.nl.netns, ["iperf", "-c", "192.168.6.2", "-t", "1", "-xSC"])
            nsp.wait(); nsp.release()
            nsp_server.kill(); nsp_server.wait(); nsp_server.release()

            nsp_server = NSPopen(self.ns_array[2].id.nl.netns, ["netserver", "-D"])
            sleep(1)
            nsp = NSPopen(self.ns_array[0].id.nl.netns, ["netperf", "-l", "1", "-H", "192.168.6.2", "--", "-m", "65160"])
            nsp.wait(); nsp.release()
            nsp = NSPopen(self.ns_array[0].id.nl.netns, ["netperf", "-l", "1", "-H", "192.168.6.2", "-t", "TCP_RR"])
            nsp.wait(); nsp.release()
            nsp_server.kill(); nsp_server.wait(); nsp_server.release()


    def create_topology(self,subnet,VMs):
	x = 1
	for sub in range(5,subnet+5):
   	    for mac in range(2,VMs+2):
		print 'Creating namespace: ns%d, With IP address:  192.168.%d.%d' % (x,sub,mac)
		self.create_VM('ns%d' % (x), '192.168.%d.%d' % (sub,mac))
		x+=1

	for br_id in range(1,subnet+1):
	    print 'Creating Bridge: br%d' % (br_id)
            self.create_bridge('br%d' % (br_id))

	x = 0
	for sub in range(0,subnet):
   	    for mac in range(0,VMs):
		self.setup_bridge(self.br_array[sub], self.ns_array[x].vethOut)
		x+=1
	
       		
        self.create_router("r1",subnet)
        self.add_values(subnet,VMs)
	#self.test_topology()

try:
    no_of_subnets = int(sys.argv[1])
    no_of_VMs_in_each_subnet = int(sys.argv[2])
    sim = TunnelSimulation(ipdb)
    sim.create_topology(no_of_subnets,no_of_VMs_in_each_subnet)
# reading from cat /sys/kernel/debug/tracing/trace_pipe
    input("Press enter to quit:")
except Exception as e:
    print str(e)
finally:
    for bridge in sim.br_array:
        if bridge.name in ipdb.interfaces:
            ipdb.interfaces[bridge.name].remove().commit()

    for dummy in sim.dm_array:
        if dummy.name in ipdb.interfaces:
            ipdb.interfaces[dummy.name].remove().commit()

    sim.del_dummy_ifc("r1")
    sim.release()
    ipdb.release()
