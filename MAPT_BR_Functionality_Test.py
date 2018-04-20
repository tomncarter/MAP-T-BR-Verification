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
class BRFunctionalityTest:
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

	#Check for normal translation of packets
	#Send 128 frame size packet for ipv4/udp. DF=0
	#Received packet should be translated into IPv6 packet and no fragment header
	def downstream_normal_packet_translation(self):
		self.m_finished=False
		self.packet_error=False
                self.comment = "IPv4_PACKET_NORMAL_TRANSLATION"
                q = Queue()
		v6_cap_filter = 'src {}'.format(self.ipv6_destination_address)
		sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,1))
		sniffer.daemon = True
		sniffer.start()
		while (self.m_finished==False):
			ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address)
			udp = UDP(sport=self.ipv4_udp_or_tcp_source_port, dport=self.ipv4_udp_or_tcp_destination_port)
			payload = "a"*82
			send(ip/udp/payload, iface=self.ipv4_interface, verbose=False)
		if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
			while not q.empty():
				pkt = q.get()
                                #print(pkt.show())
                                #file_name = self.comment.lower()+".pcap"
                                #wrpcap(file_name, pkt)
				pktdump.write(pkt)
				if pkt[0][1].nh != 44:
                                	self.v6_address_check(pkt)
					self.v6_port_check(pkt)
				else:
					self.packet_error = True
					self.comment+="\n  Fragment Header added"
                        if self.packet_error == True:
                                fh = open("test_results.txt", "a")
                                fh.write(self.comment)
                                fh.close()
		else:
			self.comment+="\n  No packets received"
			fh = open("test_results.txt", "a")
                        fh.write(self.comment)
                        fh.close()

	#Check for normal translation of packets
        #Send 128 frame size packet for ipv6/udp
        #Received packet should be translated into IPv4 packet with DF=1
        def upstream_normal_packet_translation(self):
                self.m_finished=False
		self.packet_error=False
		self.comment = "IPv6_PACKET_NORMAL_TRANSLATION"
                q = Queue()
                v4_cap_filter = 'src {}'.format(self.ipv4_destination_address)
		#v4_cap_filter = 'ip src 198.18.0.12'
		sniffer = Thread(target=self.v4sniffer, args=(q,v4_cap_filter,1))
                sniffer.daemon = True
                sniffer.start()
		while (self.m_finished==False):
                	ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
			udp = UDP(sport=self.ipv6_udp_or_tcp_source_port, dport=self.ipv6_udp_or_tcp_destination_port)
                	payload = "a"*82
                	send(ip/udp/payload, iface=self.ipv6_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
				#print(pkt.show())
				#file_name = self.comment.lower()+".pcap"
				#wrpcap(file_name, pkt)
				pktdump.write(pkt)
				self.v4_address_check(pkt)
				self.v4_port_check(pkt)
                                if pkt[0][IP].flags != 'DF':
					self.comment+="\n  DF bit not set"
					self.packet_error = True
			if self.packet_error == True:
				fh = open("test_results.txt", "a")
				fh.write(self.comment)
				fh.close()				
                else:
                        self.comment+="\n  No packets received"
			fh = open("test_results.txt", "a")
                        fh.write(self.comment)
                        fh.close()
	
	#Check for ttl_expired
        #Send 128 frame size packet for ipv4/udp. ttl=0
        #Received packet should be ICMP(Time-to-live exceeded)
        def downstream_ttl_expired(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "IPv4_TTL_EXPIRED"
                q = Queue()
                v4_cap_filter = 'icmp'
                sniffer = Thread(target=self.v4sniffer, args=(q,v4_cap_filter,1))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address, ttl=2)
                        udp = UDP(sport=self.ipv4_udp_or_tcp_source_port, dport=self.ipv4_udp_or_tcp_destination_port)
                        payload = "a"*82
                        send(ip/udp/payload, iface=self.ipv4_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                #file_name = self.comment.lower()+".pcap"
                                #wrpcap(file_name, pkt)
				pktdump.write(pkt)
				if pkt[0][1].proto != 1:
                                        self.comment+="\n  ICMPv4 not received"
                                        self.packet_error = True
                                else:
                                        if pkt[0][2].type != 11:
                                                self.comment+="\n  Incorrect Type Number"
                                                self.packet_error = True
                                        else:
                                                if pkt[0][2].code != 0:
                                                        self.comment+="\n  Incorrect Code Number"
                                                        self.packet_error = True
                        if self.packet_error == True:
                                fh = open("test_results.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results.txt", "a")
                        fh.write(self.comment)
                        fh.close()

	#Check for hop limit expired packets
        #Send 128 frame size packet for ipv6/udp and hop_limit=2
        #Received packet should be ICMPv6(Time-to-live exceeded)
        def upstream_hop_limit_expired(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "IPv6_TTL_EXPIRED"
                q = Queue()
                v6_cap_filter = 'icmp6'
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,1))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address, hlim=2)
                        udp = UDP(sport=self.ipv6_udp_or_tcp_source_port, dport=self.ipv6_udp_or_tcp_destination_port)
                        payload = "a"*82
                        send(ip/udp/payload, iface=self.ipv6_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                #file_name = self.comment.lower()+".pcap"
                                #wrpcap(file_name, pkt)
				pktdump.write(pkt)
                                if pkt[0][1].nh != 58:
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
				
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results.txt", "a")
                        fh.write(self.comment)
                        fh.close()
	
	#Check for mss clamping of packets
        #Send 128 frame size packet for ipv4/udp. mss = 2000
        #Received packet should be translated into IPv6 packet and mss clamped to 1432
        def downstream_mss_clamping(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "IPv4_MSS_CLAMPING"
                q = Queue()
                v6_cap_filter = 'src {}'.format(self.ipv6_destination_address)
                #v6_cap_filter = 'src 2001:db8:ffff:ff00:c0:2:100:0'
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,1))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address)
                        tcp = TCP(sport=self.ipv4_udp_or_tcp_source_port, dport=self.ipv4_udp_or_tcp_destination_port,  flags="S", seq=1001, options=[('MSS', 2000)])
                        payload = "a"*82
                        send(ip/tcp/payload, iface=self.ipv4_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                #file_name = self.comment.lower()+".pcap"
                                #wrpcap(file_name, pkt)
				pktdump.write(pkt)
                                self.v6_address_check(pkt)
				self.v6_port_check(pkt)
				if pkt[0][2].options[0][1] != 1432:
                                        self.comment+="\n  MSS not clamped to 1432"
                                        self.packet_error = True
                        if self.packet_error == True:
                                fh = open("test_results.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results.txt", "a")
                        fh.write(self.comment)
                        fh.close()

	#Check for mss clamping
        #Send 128 frame size packet for ipv6/tcp with mss value = 2000
        #Received packet should be translated into IPv4 packet with MSS value =2000
        def upstream_mss_clamping(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "IPv6_MSS_CLAMPING"
                q = Queue()
                v4_cap_filter = 'src {}'.format(self.ipv4_destination_address)
                #v4_cap_filter = 'ip src 198.18.0.12'
                sniffer = Thread(target=self.v4sniffer, args=(q,v4_cap_filter,1))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                        tcp = TCP(sport=self.ipv6_udp_or_tcp_source_port, dport=self.ipv6_udp_or_tcp_destination_port, flags="S", seq=1001, options=[('MSS', 2000)] )
                        payload = "a"*82
                        send(ip/tcp/payload, iface=self.ipv6_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                #file_name = self.comment.lower()+".pcap"
                                #wrpcap(file_name, pkt)
				pktdump.write(pkt)
                                self.v4_address_check(pkt)
				self.v4_port_check(pkt)
                                if pkt[0][2].options[0][1] != 1432:
                                        self.comment+="\n  MSS not clamped to 1432"
                                        self.packet_error = True
				
                        if self.packet_error == True:
                                fh = open("test_results.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results.txt", "a")
                        fh.write(self.comment)
                        fh.close()
		
	#Check for outside domain port number
        #Send 128 frame size packet for ipv4/udp, udp.dstport=1001
        #Received packet should be ICMPv4
        def downstream_outside_port(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "IPv4_OUTSIDE_PORT_NO"
                q = Queue()
                v4_cap_filter = 'icmp or src {}'.format(self.ipv6_destination_address)
                sniffer = Thread(target=self.v4sniffer, args=(q,v4_cap_filter,1))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address)
                        udp = UDP(sport=self.ipv4_udp_or_tcp_source_port, dport=1001)
                        payload = "a"*82
                        send(ip/udp/payload, iface=self.ipv4_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                #file_name = self.comment.lower()+".pcap"
                                #wrpcap(file_name, pkt)
				pktdump.write(pkt)
                                if pkt[0][1].proto != 1:
                                        self.comment+="\n  ICMPv4 Packet Not Received"
                                        self.packet_error = True
				else:
					if pkt[0][1].proto == 17:
						self.comment+="\n Packet Translated Normally"
						self.packet_error = True
					else:
						self.comment+="\n ICMPv4 Packet Received\n  "
						self.comment+=pkt[0][2].type
						self.comment+="\n  "
						self.comment+=pkt[0][2].code
                                        	self.comment+="\n"
                                        	self.packet_error = True
                        if self.packet_error == True:
                                fh = open("test_results.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results.txt", "a")
                        fh.write(self.comment)
                        fh.close()

	#Check for outside port
        #Send 128 frame size packet for ipv6/udp and udp.srcport = 1001
        #Received packet should be ICMPv6(Source address failed ingress/egress policy)
	def upstream_outside_port(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "IPv6_OUTSIDE_PORT"
                q = Queue()
                v6_cap_filter = 'icmp6'
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,1))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                        udp = UDP(sport=1001, dport=self.ipv6_udp_or_tcp_destination_port)
                        payload = "a"*82
                        send(ip/udp/payload, iface=self.ipv6_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                #file_name = self.comment.lower()+".pcap"
                                #wrpcap(file_name, pkt)
                                pktdump.write(pkt)
                                if pkt[0][1].nh != 58:
                                        self.comment+="\n  ICMP6 not received"
                                        self.packet_error = True
				else:
                                        if pkt[0][2].type != 1:
                                                self.comment+="\n  Incorrect Type Number"
                                                self.packet_error = True
                                        else:
                                                if pkt[0][2].code != 5:
                                                        self.comment+="\n  Incorrect Code Number"
                                                        self.packet_error = True

                        if self.packet_error == True:
                                fh = open("test_results.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n No packets received"
			fh = open("test_results.txt", "a")
                        fh.write(self.comment)
                        fh.close()
	
	#Check for packet fragmentation by the BR
        #Send 1499 frame size packet for ipv4/udp. DF=0
        #Received packet should be translated into IPv6 packet and fragmented by the BR
        def downstream_fragmentation(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "IPv4_PACKET_FRAGMENTED_BY_BR"
                q = Queue()
                v6_cap_filter = 'src {}'.format(self.ipv6_destination_address)
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,2))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address)
                        udp = UDP(sport=self.ipv4_udp_or_tcp_source_port, dport=self.ipv4_udp_or_tcp_destination_port)
                        payload = "a"*1453
                        send(ip/udp/payload, iface=self.ipv4_interface, verbose=False)
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
			count = 0
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                #file_name = self.comment.lower()+".pcap"
                                #wrpcap(file_name, pkt)
				pktdump.write(pkt)
				if count == 0:
                                	self.v6_address_check(pkt)
					self.v6_port_check(pkt)
				if pkt[0][1].nh != 44:
					self.comment+="\n  No Fragment Header found"
				if count==1: #Second Fragment
					self.v6_address_check(pkt)
				count+=1
			if count != 2:
				self.comment+="\n  Both fragments not received"
                        if self.packet_error == True:
                                fh = open("test_results.txt", "a")
                                fh.write(self.comment)
                                fh.close()
                else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results.txt", "a")
                        fh.write(self.comment)
                        fh.close()
	
	#Check for packet fragmets sent to the BR
        #Send fragments for ipv4/udp. DF=0
        #Received packet should be IPv6 fragments
        def downstream_fragments(self):
                self.m_finished=False
                self.packet_error=False
                self.comment = "IPv4_PACKET_FRAGMENTS"
                q = Queue()
                v6_cap_filter = 'src {}'.format(self.ipv6_destination_address)
                sniffer = Thread(target=self.v6sniffer, args=(q,v6_cap_filter,2))
                sniffer.daemon = True
                sniffer.start()
                while (self.m_finished==False):
                        ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address, id=30000)
                        udp = UDP(sport=self.ipv4_udp_or_tcp_source_port, dport=self.ipv4_udp_or_tcp_destination_port)
                        payload = "a"*1500
			packet = ip/udp/payload
			frags = scapy.all.fragment(packet, fragsize=1000)
			for fragment in frags:
        			send(fragment, iface="ens160")
                if (not q.empty()):
			file_name = self.comment.lower()+".pcap"
                        pktdump = PcapWriter(file_name, append=True, sync=True)
                        count = 0
                        while not q.empty():
                                pkt = q.get()
                                #print(pkt.show())
                                #file_name = self.comment.lower()+".pcap"
                                #wrpcap(file_name, pkt)
				pktdump.write(pkt)
                                if count == 0:
                                        self.v6_address_check(pkt)
					self.v6_port_check(pkt)
				if count == 1: #Second Fragment
                                        self.v6_port_check(pkt)
                                if pkt[0][1].nh != 44:
                                        self.comment+="\n  No Fragment Header found"
                                count+=1
                        if count != 2:
                                self.comment+="\n  Both fragments not received"
                        if self.packet_error == True:
                                fh = open("test_results.txt", "a")
                                fh.write(self.comment)
                                fh.close()
		else:
                        self.comment+="\n  No packets received"
                        fh = open("test_results.txt", "a")
                        fh.write(self.comment)
                        fh.close()

	def v6_address_check(self, pkt):
                if pkt[0][IPv6].src != self.ipv6_destination_address:
                        self.packet_error = True
                        self.comment+="\n  v6 Source Address Error"
                if pkt[0][IPv6].dst != self.ipv6_source_address:
                        self.packet_error = True
                        self.comment+="\n v6 Destination Address Error"
	

	def v6_port_check(self, pkt):
                if pkt[0][2].sport != self.ipv6_udp_or_tcp_destination_port:
                        self.packet_error = True
                        self.comment+="\n  v6 UDP Source Port Error"
                if pkt[0][2].dport != self.ipv6_udp_or_tcp_source_port:
                        self.packet_error = True
                        self.comment+="\n  v6 UDP Destination Port Error"
	
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

	def v6sniffer(self,q,filter,count):
		packet = sniff(count=count, iface=ipv6_interface, filter=filter, prn = lambda x : q.put(x), timeout=5)
		self.m_finished = True
	
	def v4sniffer(self,q,filter,count):
                packet = sniff(count=count, iface=ipv4_interface, filter=filter, prn = lambda x : q.put(x), timeout=5)
                self.m_finished = True

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
		
	BR_obj = BRFunctionalityTest(ipv4_source_address, 
						ipv4_destination_address, ipv6_source_address, 
						ipv6_destination_address, 
						ipv4_udp_or_tcp_source_port, 
						ipv4_udp_or_tcp_destination_port, 
						ipv6_udp_or_tcp_source_port, 
						ipv6_udp_or_tcp_destination_port,
						psid_number,
						ipv4_interface,
						ipv6_interface)	
	#BR_obj.downstream_normal_packet_translation()			
	#BR_obj.upstream_normal_packet_translation()
	#BR_obj.downstream_ttl_expired()
	#BR_obj.upstream_hop_limit_expired()
	#BR_obj.downstream_mss_clamping()
	#BR_obj.upstream_mss_clamping()
	#BR_obj.upstream_outside_port()
	#BR_obj.downstream_outside_port()
	#BR_obj.downstream_fragmentation()
	BR_obj.downstream_fragments()
#******************** MAIN FUNCTION - END ******************#
