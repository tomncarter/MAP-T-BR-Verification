#! /usr/bin/env python

from scapy.all import *
import argparse
import pyswmap
import scapy.contrib.igmp
import ipaddress
from threading import Thread
from Queue import Queue, Empty
from time import sleep
from multiprocessing import Pool, TimeoutError, current_process
import time
import os
import random
import scapy.contrib.igmp
from scapy.utils import PcapWriter


# Changing log level to suppress IPv6 error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#******************** BR FUNCTIONALITY TEST CLASS - START ******************#
class BRFunctionalityTestICMPv6:
        def __init__(self,
                        ipv4_source_address,
                        ipv4_destination_addres, ipv6_source_address,
                        ipv6_destination_address,
                        ipv4_udp_or_tcp_source_port,
                        ipv4_udp_or_tcp_destination_port,
                        ipv6_udp_or_tcp_source_port,
                        ipv6_udp_or_tcp_destination_port,
                        psid_number,
                        ipv4_interface,
                        ipv6_interface):
                self.ipv4_source_address = ipv4_source_address
                self.ipv4_destination_address = ipv4_destination_address
                self.ipv6_source_address = ipv6_source_address
                self.ipv6_destination_address = ipv6_destination_address
                self.ipv4_udp_or_tcp_source_port = ipv4_udp_or_tcp_source_port
                self.ipv4_udp_or_tcp_destination_port = ipv4_udp_or_tcp_destination_port
                self.ipv6_udp_or_tcp_source_port = ipv6_udp_or_tcp_source_port
                self.ipv6_udp_or_tcp_destination_port = ipv6_udp_or_tcp_destination_port
                self.psid_number = psid_number
                self.ipv4_interface=ipv4_interface
                self.ipv6_interface=ipv6_interface
                self.m_finished = False
                self.packet_error = False
                self.comment = ""
        #Upstram refers to IPv6 -> IPv4 direction
        #Downstream refers to IPv4 -> IPv6 direction

	def echo_request(self):
		self.m_finished=False
                self.packet_error=False
                self.comment = "ICMPv6_ECHO_REQUEST"
                q = Queue()
                v6_cap_filter = 'icmp'
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,1))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
			ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
			icmp = ICMPv6EchoRequest()
			icmp.id = self.ipv6_udp_or_tcp_source_port
			payload = "H"*10
			send(ip/icmp/payload, iface=self.ipv6_interface, verbose=False)
		if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                pktdump.write(pkt)
                                if pkt[0][1].proto != 1:
                                        self.comment+="\n  ICMPv6 not received"
                                        self.packet_error = True
                                else:
                                        if pkt[0][2].type != 8:
                                                self.comment+="\n  Incorrect Type Number"
                                                self.packet_error = True
                                        else:
                                                if pkt[0][2].code != 0:
                                                        self.comment+="\n  Incorrect Code Number"
                                                        self.packet_error = True
			if self.packet_error == True:
                                fh = open("test_results_icmpv6.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results_icmpv6.txt", "a")
                        fh.write(self.comment)
                        fh.close()
	
	def echo_reply(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "ICMPv6_ECHO_REPLY"
                q = Queue()
                v6_cap_filter = 'icmp'
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,1))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                        icmp = ICMPv6EchoReply()
                        icmp.id = self.ipv6_udp_or_tcp_source_port
                        payload = "H"*10
                        send(ip/icmp/payload, iface=self.ipv6_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                               	pktdump.write(pkt) 
                                if pkt[0][1].proto != 1:
                                        self.comment+="\n  ICMPv6 not received"
                                        self.packet_error = True
                                else:
                                        if pkt[0][2].type != 0:
                                                self.comment+="\n  Incorrect Type Number"
                                                self.packet_error = True
                                        else:
                                                if pkt[0][2].code != 0:
                                                        self.comment+="\n  Incorrect Code Number"
                                                        self.packet_error = True
			if self.packet_error == True:
                                fh = open("test_results_icmpv6.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results_icmpv6.txt", "a")
                        fh.write(self.comment)
                        fh.close()
	
	#Destination Unreachable - No route to destination, Communication with destination administratively prohibited, Beyond scope of source address, Address unreachable, Port unreachable (Type 1, Code - 0/1/2/3/4)
	def destination_unreachable(self):
		self.m_finished=False
                self.packet_error=False
                self.comment = "ICMPv6_DESTINATION_UNREACHABLE"
                q = Queue()
                v6_cap_filter = 'icmp'
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,5))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
			code_values = [0,1,2,3,4]
			for code_value in code_values:
                        	ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                        	icmp = ICMPv6DestUnreach()
                        	icmp.code = code_value
				ip1 = IPv6(src=self.ipv6_destination_address, dst=self.ipv6_source_address)
				udp = UDP(sport=self.ipv6_udp_or_tcp_destination_port, dport=self.ipv6_udp_or_tcp_source_port)
                        	payload = "H"*10
                        	send(ip/icmp/ip1/udp/payload, iface=self.ipv6_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
			while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                pktdump.write(pkt)
                                if pkt[0][1].proto != 1:
                                        self.comment+="\n  ICMPv6 not received"
                                        self.packet_error = True
                                else:
                                        if pkt[0][2].type != 3:
                                                self.comment+="\n  Incorrect Type Number"
                                                self.packet_error = True
                                        else:
                                                if pkt[0][2].code != 1 or pkt[0][2].code != 10 or pkt[0][2].code != 3:
                                                        self.comment+="\n  Incorrect Code Number"
                                                        self.packet_error = True
			if self.packet_error == True:
                                fh = open("test_results_icmpv6.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results_icmpv6.txt", "a")
                        fh.write(self.comment)
                        fh.close()
	
	def packet_too_big(self):
		self.m_finished=False
                self.packet_error=False
                self.comment = "ICMPv6_PACKET_TOO_BIG"
                q = Queue()
                v6_cap_filter = 'icmp'
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,17))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        mtu_values = [512, 513, 1024,1025,1278,1279,1280,1281,1282,1472,1480,1498,1499,1500,1518, 1550, 1600]
			for mtu_value in mtu_values:
                                ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                                icmp = ICMPv6PacketTooBig()
                                icmp.mtu = mtu_value
                                ip1 = IPv6(src=self.ipv6_destination_address, dst=self.ipv6_source_address)
                                udp = UDP(sport=self.ipv6_udp_or_tcp_destination_port, dport=self.ipv6_udp_or_tcp_source_port)
                                payload = "H"*10
                                send(ip/icmp/ip1/udp/payload, iface=self.ipv6_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
                                print(pkt.show())
                                pktdump.write(pkt)
                                if pkt[0][1].proto != 1:
                                        self.comment+="\n  ICMPv6 not received"
                                        self.packet_error = True
                                else:
                                        if pkt[0][2].type != 3:
                                                self.comment+="\n  Incorrect Type Number"
                                                self.packet_error = True
                                        else:
                                                if pkt[0][2].code != 4:
                                                        self.comment+="\n  Incorrect Code Number"
                                                        self.packet_error = True
						else:
							if pkt[0][ICMP].nexthopmtu not in mtu_values or pkt[0][ICMP].nexthopmtu != 1432:
								self.comment+="\n  Incorrect MTU values"
                                                        	self.packet_error = True
			if self.packet_error == True:
                                fh = open("test_results_icmpv6.txt", "a")
                                fh.write(self.comment)
                                fh.close()		
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results_icmpv6.txt", "a")
                        fh.write(self.comment)
                        fh.close()	
	
	
        def time_exceeded(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "ICMPv6_TIME_EXCEEDED"
                q = Queue()
                v6_cap_filter = 'icmp'
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,5))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        code_values = [0,1]
                        for code_value in code_values:
                                ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                                icmp = ICMPv6DestUnreach()
                                icmp.code = code_value
                                ip1 = IPv6(src=self.ipv6_destination_address, dst=self.ipv6_source_address)
                                udp = UDP(sport=self.ipv6_udp_or_tcp_destination_port, dport=self.ipv6_udp_or_tcp_source_port)
                                payload = "H"*10
                                send(ip/icmp/ip1/udp/payload, iface=self.ipv6_interface, verbose=False)
                if (not q.empty()):
                        file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                pktdump.write(pkt)
                                if pkt[0][1].proto != 1:
                                        self.comment+="\n  ICMPv6 not received"
                                        self.packet_error = True
                                else:
                                        if pkt[0][2].type != 11:
                                                self.comment+="\n  Incorrect Type Number"
                                                self.packet_error = True
                                        else:
                                                if pkt[0][2].code != 0 or pkt[0][2].code != 1:
                                                        self.comment+="\n  Incorrect Code Number"
                                                        self.packet_error = True
                        if self.packet_error == True:
                                fh = open("test_results_icmpv6.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results_icmpv6.txt", "a")
                        fh.write(self.comment)
                        fh.close()

        def parameter_problem_pointer(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "ICMPv6_PARAMETER_PROBLEM_POINTER"
                q = Queue()
                v6_cap_filter = 'icmp'
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,38))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        for ptr_value in range(0,40):
                                ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                                icmp = ICMPv6ParamProblem()
                                icmp.code = 0
				icmp.ptr = ptr_value
                                ip1 = IPv6(src=self.ipv6_destination_address, dst=self.ipv6_source_address)
                                udp = UDP(sport=self.ipv6_udp_or_tcp_destination_port, dport=self.ipv6_udp_or_tcp_source_port)
                                payload = "H"*10
                                send(ip/icmp/ip1/udp/payload, iface=self.ipv6_interface, verbose=False)
                if (not q.empty()):
                        file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
			count = 0
                        while not q.empty():
                                pkt = q.get()
                                print(pkt.show())
                                pktdump.write(pkt)
                                if pkt[0][1].proto != 1:
                                        self.comment+="\n  ICMPv6 not received"
                                        self.packet_error = True
                                else:
                                        if pkt[0][2].type != 12:
                                                self.comment+="\n  Incorrect Type Number"
                                                self.packet_error = True
                                        else:
                                                if pkt[0][2].code != 0:
                                                        self.comment+="\n  Incorrect Code Number"
                                                        self.packet_error = True
						else:
						 	ipv4_ptr_values = [x for x in range(17)]
							if pkt[0][ICMP].ptr not in ipv4_ptr_values:
								self.comment+="\n  Incorrect Pointer values"
								self.packet_error = True
				count+=1
			if count != 38:
				self.comment+="\n  All packets not received"
                                self.packet_error = True					
                        if self.packet_error == True:
                                fh = open("test_results_icmpv6.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results_icmpv6.txt", "a")
                        fh.write(self.comment)
                        fh.close()


	def parameter_problem(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "ICMPv6_PARAMETER_PROBLEM"
                q = Queue()
                v6_cap_filter = 'icmp'
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,2))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
			code_values = [1,2]
                        for code_value in code_values:
                                ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                                icmp = ICMPv6ParamProblem()
                                icmp.code = code_value
                                
                                ip1 = IPv6(src=self.ipv6_destination_address, dst=self.ipv6_source_address)
                                udp = UDP(sport=self.ipv6_udp_or_tcp_destination_port, dport=self.ipv6_udp_or_tcp_source_port)
                                payload = "H"*10
                                send(ip/icmp/ip1/udp/payload, iface=self.ipv6_interface, verbose=False)
                if (not q.empty()):
                        file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        count = 0
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                pktdump.write(pkt)
                                if pkt[0][1].proto != 1:
                                        self.comment+="\n  ICMPv6 not received"
                                        self.packet_error = True
                                else:
                                        if pkt[0][2].type != 3:
                                                self.comment+="\n  Incorrect Type Number"
                                                self.packet_error = True
                                        else:
                                                if pkt[0][2].code != 0:
                                                        self.comment+="\n  Incorrect Code Number"
                                                        self.packet_error = True
                                count+=1
                        if count == 2:
                                self.comment+="\n  Received two packets. Code 2 should be dropped"
                                self.packet_error = True
                        if self.packet_error == True:
                                fh = open("test_results_icmpv6.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results_icmpv6.txt", "a")
                        fh.write(self.comment)
                        fh.close()

	def v6sniffer(self,q,filter,count):
                packet = sniff(count=count, iface=ipv6_interface, filter=filter, prn = lambda x : q.put(x), timeout=5)
                self.m_finished = True
	
	def v4_address_check(self, pkt):
                if pkt[0][IP].src != self.ipv4_destination_address:
                        self.packet_error = True
                        self.comment+="\n  v4 Source Address Error"
                if pkt[0][IP].dst != self.ipv4_source_address:
                        self.packet_error = True
                        self.comment+="\n  v4 Destination Address Error"

        def v4_port_check(self, pkt):
                if pkt[0][2].sport != self.ipv4_udp_or_tcp_destination_port:
                        self.packet_error = True
                        self.comment+="\n  v4 UDP Source Port Error"
                if pkt[0][2].dport != self.ipv4_udp_or_tcp_source_port:
                        self.packet_error = True
                        self.comment+="\n  UDP Destination Port Error"

#******************** BR FUNCTIONALITY TEST CLASS - END ******************#


#******************** MAIN FUNCTION - START ******************#

if __name__ == '__main__':
        #******************** VARIABLES - START ******************#
        ipv4_source_address = "192.0.2.1"
        ipv4_destination_address = "198.18.0.12"
        ipv6_source_address = "2001:db8:f0:c30:0:c612:c:3"
        ipv6_destination_address = "2001:db8:ffff:ff00:c0:2:100:0"
        ipv4_udp_or_tcp_source_port = 65000
        ipv4_udp_or_tcp_destination_port = 16606
        ipv6_udp_or_tcp_source_port = 16606
        ipv6_udp_or_tcp_destination_port = 65000
        psid_number = 3
        ipv4_interface="ens160"
        ipv6_interface="ens160"
        #******************** VARIABLES - END ******************#

        BR_obj = BRFunctionalityTestICMPv6(ipv4_source_address,
                                                ipv4_destination_address, ipv6_source_address,
                                                ipv6_destination_address,
                                                ipv4_udp_or_tcp_source_port,
                                                ipv4_udp_or_tcp_destination_port,
                                                ipv6_udp_or_tcp_source_port,
                                                ipv6_udp_or_tcp_destination_port,
                                                psid_number,
                                                ipv4_interface,
                                                ipv6_interface)
	#BR_obj.echo_request()
	#BR_obj.echo_reply()
	#BR_obj.destination_unreachable()
	#BR_obj.packet_too_big()
	#BR_obj.time_exceeded()
	BR_obj.parameter_problem_pointer()
#******************** MAIN FUNCTION - END ******************#

