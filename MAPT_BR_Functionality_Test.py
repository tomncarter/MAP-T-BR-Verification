#! /usr/bin/env python

from scapy.all import *
import argparse
import pyswmap
import scapy.contrib.igmp
import ipaddress
from threading import Thread
from queue import Queue, Empty
from time import sleep
from multiprocessing import Pool, TimeoutError, current_process
import time
import os
import random
import scapy.contrib.igmp
from scapy.utils import PcapWriter

# Changing log level to suppress IPv6 error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# ******************** BR FUNCTIONALITY TEST CLASS - START ******************#
class BRFunctionalityTest:
    def __init__(self,
                 ipv4_source_address,
                 ipv4_destination_addres,
                 ipv6_source_address,
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
        self.ipv4_interface = ipv4_interface
        self.ipv6_interface = ipv6_interface
        self.m_finished = False
        self.packet_error = False
        self.comment = ""

    # Upstream refers to IPv6 -> IPv4 direction
    # Downstream refers to IPv4 -> IPv6 direction
    # Check for normal translation of packets
    # Send 128 frame size packet for ipv4/udp. DF=0
    # Received packet should be translated into IPv6 packet and no fragment header
    def downstream_udp_packet_translation(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n IPv4_PACKET_NORMAL_TRANSLATION"
        q = Queue()
        v6_cap_filter = 'src {}'.format(self.ipv6_destination_address)
        sniffer = Thread(target=self.v6sniffer, args=(q, v6_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address)
            udp = UDP(sport=self.ipv4_udp_or_tcp_source_port, dport=self.ipv4_udp_or_tcp_destination_port)
            payload = "a" * 82
            send(ip / udp / payload, iface=self.ipv4_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                # file_name = self.comment.lower()+".pcap"
                # wrpcap(file_name, pkt)
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  IPv6 UDP Packet Not Received"
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            return
        self.v6_address_check(pkt)
        self.v6_port_check(pkt)
        if pkt[0][1].nh == 44:
            self.v6_address_check(pkt)
            self.v6_port_check(pkt)
            self.packet_error = True
            self.comment += "\n  Fragment Header added"
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("Downstream UDP Packet: FAIL")
        if not self.packet_error:
            print("Downstream UDP Packet: PASS")

    # Check for normal translation of packets
    # Send 128 frame size packet for ipv6/udp
    # Received packet should be translated into IPv4 packet with DF=1
    def upstream_udp_packet_translation(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n IPv6_PACKET_NORMAL_TRANSLATION"
        q = Queue()
        v4_cap_filter = 'src {}'.format(self.ipv4_destination_address)
        sniffer = Thread(target=self.v4sniffer, args=(q, v4_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
            udp = UDP(sport=self.ipv6_udp_or_tcp_source_port, dport=self.ipv6_udp_or_tcp_destination_port)
            payload = "a" * 82
            send(ip / udp / payload, iface=self.ipv6_interface, verbose=False)
            if not q.empty():
                file_name = self.comment.lower() + ".pcap"
                pktdump = PcapWriter(file_name, append=True, sync=True)
                while not q.empty():
                    pkt = q.get()
                    # print(pkt.show())
                    # file_name = self.comment.lower()+".pcap"
                    # wrpcap(file_name, pkt)
                    pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  IPv4 UDP Packet Not Received"
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            return
        self.v4_address_check(pkt)
        self.v4_port_check(pkt)
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("Upstream UDP Packet: FAIL")
        if not self.packet_error:
            print("Upstream UDP Packet: PASS")

    # Check for ttl_expired
    # Send 128 frame size packet for ipv4/udp. ttl=0
    # Received packet should be ICMP(Time-to-live exceeded)
    def downstream_ttl_expired(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n IPv4_TTL_EXPIRED"
        q = Queue()
        v4_cap_filter = 'icmp and dst {}'.format(self.ipv4_source_address)
        sniffer = Thread(target=self.v4sniffer, args=(q, v4_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address, ttl=2)
            udp = UDP(sport=self.ipv4_udp_or_tcp_source_port, dport=self.ipv4_udp_or_tcp_destination_port)
            payload = "a" * 82
            send(ip / udp / payload, iface=self.ipv4_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                # file_name = self.comment.lower()+".pcap"
                # wrpcap(file_name, pkt)
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  ICMPv6 Packets Not Received"
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            return
        if pkt[0][1].proto != 1:
            self.comment += "\n  Packet Type is not ICMP (Proto 1)"
            self.packet_error = True
        if pkt[0][2].type != 11:
            self.comment += "\n  Incorrect Type Number"
            self.packet_error = True
        if pkt[0][2].code != 0:
            self.comment += "\n  Incorrect Code Number"
            self.packet_error = True
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("TTL Expired: FAIL")
        if not self.packet_error:
            print("TTL Expired: PASS")

    # Check for hop limit expired packets
    # Send 128 frame size packet for ipv6/udp and hop_limit=2
    # Received packet should be ICMPv6(Time-to-live exceeded)
    def upstream_hop_limit_expired(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n IPv6_Hot_Limit_EXPIRED"
        q = Queue()
        v6_cap_filter = 'icmp6 and dst {}'.format(self.ipv6_source_address)
        sniffer = Thread(target=self.v6sniffer, args=(q, v6_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address, hlim=2)
            udp = UDP(sport=self.ipv6_udp_or_tcp_source_port, dport=self.ipv6_udp_or_tcp_destination_port)
            payload = "a" * 82
            send(ip / udp / payload, iface=self.ipv6_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                # file_name = self.comment.lower()+".pcap"
                # wrpcap(file_name, pkt)
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  ICMPv6 Hop Limit Expired not received"
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            return
        if pkt[0][1].nh != 58:
            self.comment += "\n  Packet Type is not ICMPv6 (Proto 58)"
            self.packet_error = True
        if pkt[0][2].type != 3:
            self.comment += "\n  Incorrect Type Number"
            self.packet_error = True
        if pkt[0][2].code != 0:
            self.comment += "\n  Incorrect Code Number"
            self.packet_error = True
        if not self.packet_error:
            print("ICMPv6 Hop Limit Expired: PASS")

    # Check for mss clamping of packets
    # Send 128 frame size packet for ipv4/udp. mss = 2000
    # Received packet should be translated into IPv6 packet and mss clamped to 1432
    def downstream_mss_clamping(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n IPv4_MSS_CLAMPING"
        q = Queue()
        v6_cap_filter = 'tcp and src {}'.format(self.ipv6_destination_address)
        # v6_cap_filter = 'src 2001:db8:ffff:ff00:c0:2:100:0'
        sniffer = Thread(target=self.v6sniffer, args=(q, v6_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address)
            tcp = TCP(sport=self.ipv4_udp_or_tcp_source_port, dport=self.ipv4_udp_or_tcp_destination_port, flags="S",
                      seq=1001, options=[('MSS', 2000)])
            payload = "a" * 82
            send(ip / tcp / payload, iface=self.ipv4_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                # file_name = self.comment.lower()+".pcap"
                # wrpcap(file_name, pkt)
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  IPv6 TCP Packet not received"
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            return
        self.v6_address_check(pkt)
        self.v6_port_check(pkt)
        if pkt[0][2].options[0][1] != 1432:
            self.comment += "\n  MSS not clamped to 1432"
            self.packet_error = True
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
        if not self.packet_error:
            print("Downstream TCP MSS Clamping: PASS")

    # Check for mss clamping
    # Send 128 frame size packet for ipv6/tcp with mss value = 2000
    # Received packet should be translated into IPv4 packet with MSS value =2000
    def upstream_mss_clamping(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n IPv6_MSS_CLAMPING"
        q = Queue()
        v4_cap_filter = 'tcp and dst {}'.format(self.ipv4_source_address)
        sniffer = Thread(target=self.v4sniffer, args=(q, v4_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
            tcp = TCP(sport=self.ipv6_udp_or_tcp_source_port, dport=self.ipv6_udp_or_tcp_destination_port, flags="S",
                      seq=1001, options=[('MSS', 2000)])
            payload = "a" * 82
            send(ip / tcp / payload, iface=self.ipv6_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                # file_name = self.comment.lower()+".pcap"
                # wrpcap(file_name, pkt)
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  IPv4 TCP Packet not received"
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            return
        self.v4_address_check(pkt)
        self.v4_port_check(pkt)
        if pkt[0][2].options[0][1] != 1432:
            self.comment += "\n  MSS not clamped to 1432 - clamped to " +  str(pkt[0][2].options[0][1])
            self.packet_error = True
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("Upstream TCP MSS Clamping: FAIL")
        if not self.packet_error:
            print("Upstream TCP MSS Clamping: PASS")

    # Check for outside domain port number
    # Send 128 frame size packet for ipv4/udp, udp.dstport=1001
    # Received packet should be ICMPv4
    def downstream_outside_port(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n IPv4_OUTSIDE_PORT_NO"
        q = Queue()
        v4_cap_filter = 'dst {}'.format(self.ipv4_source_address)
        sniffer = Thread(target=self.v4sniffer, args=(q, v4_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address)
            udp = UDP(sport=self.ipv4_udp_or_tcp_source_port, dport=1001)
            payload = "a" * 82
            send(ip / udp / payload, iface=self.ipv4_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                # file_name = self.comment.lower()+".pcap"
                # wrpcap(file_name, pkt)
                pktdump.write(pkt)
            try:
              pkt
            except NameError:
              self.comment += "\n  ICMPv4 not received - the packet might have been dropped silently"
              fh = open("test_results.txt", "a")
              fh.write(self.comment)
              fh.close()
              print("Packet to Reserved Port Dropped: CONDITIONAL PASS")
              return
        if pkt[0][1].proto != 1:
            self.comment += "\n  ICMPv4 Packet Not Received"
            self.packet_error = True
        if pkt[0][1].proto == 17:
            self.comment += "\n Packet Translated Normally"
            self.packet_error = True
            self.comment += "\n ICMPv4 Packet Received\n  "
            self.comment += pkt[0][2].type
            self.comment += "\n  "
            self.comment += pkt[0][2].code
            self.comment += "\n"
            self.packet_error = True
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("IPv4 Packet to Dest Reserved Port Dropped: FAIL")
        if not self.packet_error:
            print("IPv4 Packet to Dest Reserved Port Dropped: PASS")

    # Check for outside port
    # Send 128 frame size packet for ipv6/udp and udp.srcport = 1001
    # Received packet should be ICMPv6(Source address failed ingress/egress policy)
    def upstream_outside_port(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n IPv6_OUTSIDE_PORT"
        q = Queue()
        v6_cap_filter = 'icmp6 and dst {}'.format(self.ipv6_source_address)
        sniffer = Thread(target=self.v6sniffer, args=(q, v6_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
            udp = UDP(sport=1001, dport=self.ipv6_udp_or_tcp_destination_port)
            payload = "a" * 82
            send(ip / udp / payload, iface=self.ipv6_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                # file_name = self.comment.lower()+".pcap"
                # wrpcap(file_name, pkt)
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  ICMPv6 not received - the packet might have been dropped silently"
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("Packet to Reserved Port Dropped: CONDITIONAL PASS")
            return
        if pkt[0][1].nh != 58:
            self.comment += "\n  ICMP6 not received"
            self.packet_error = True
        if pkt[0][2].type != 1:
            self.comment += "\n  Incorrect Type Number"
            self.packet_error = True
        if pkt[0][2].code != 5:
            self.comment += "\n  Incorrect Code Number"
            self.packet_error = True
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("IPv6 Packet to Source Reserved Port Dropped: FAIL")
        if not self.packet_error:
            print("IPv4 Packet to Dest Reserved Port Dropped: PASS")

    # Check for packet fragmentation by the BR
    # Send 1499 frame size packet for ipv4/udp. DF=0
    # Received packet should be translated into IPv6 packet and fragmented by the BR
    def downstream_fragmentation(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n IPv4_PACKET_FRAGMENTED_BY_BR"
        q = Queue()
        v6_cap_filter = 'dst {}'.format(self.ipv6_source_address)
        sniffer = Thread(target=self.v6sniffer, args=(q, v6_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address)
            udp = UDP(sport=self.ipv4_udp_or_tcp_source_port, dport=self.ipv4_udp_or_tcp_destination_port)
            payload = "a" * 1453
            send(ip / udp / payload, iface=self.ipv4_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            count = 0
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                # file_name = self.comment.lower()+".pcap"
                # wrpcap(file_name, pkt)
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  Fragments not received"
            return
            print("IPv4 Fragmentation by BR:: FAIL")
        if count == 0:
            self.v6_address_check(pkt)
            self.v6_port_check(pkt)
        if pkt[0][1].nh != 44:
            self.comment += "\n  No Fragment Header found"
        if count == 1:  # Second Fragment
            self.v6_address_check(pkt)
            count += 1
        if count != 2:
            self.comment += "\n  Both fragments not received"
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("IPv4 Fragmentation by BR:: FAIL")
        if not self.packet_error:
            print("IPv4 Fragmentation by BR: PASS")

    # Check for packet fragmets sent to the BR
    # Send fragments for ipv4/udp. DF=0
    # Received packet should be IPv6 fragments
    def downstream_fragments(self):
        ip = IP(src=self.ipv4_source_address, dst=self.ipv4_destination_address, id=30000)
        udp = UDP(sport=self.ipv4_udp_or_tcp_source_port, dport=self.ipv4_udp_or_tcp_destination_port)
        payload = "a" * 1500
        packet = ip / udp / payload
        frags = scapy.all.fragment(packet, fragsize=1000)
        for fragment in frags:
            send(fragment, iface=ipv4_interface, verbose=False)
            self.m_finished = False
            self.packet_error = False
            self.comment = "\n IPv4_PACKET_FRAGMENTS"
            q = Queue()
            v6_cap_filter = 'dst {}'.format(self.ipv6_source_address)
            sniffer = Thread(target=self.v6sniffer, args=(q, v6_cap_filter, 2))
            sniffer.daemon = True
            sniffer.start()
            while not self.m_finished:
                send(fragment, iface=ipv4_interface, verbose=False)
            if not q.empty():
                file_name = self.comment.lower() + ".pcap"
                pktdump = PcapWriter(file_name, append=True, sync=True)
                count = 0
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                # file_name = self.comment.lower()+".pcap"
                # wrpcap(file_name, pkt)
                pktdump.write(pkt)
            try:
                pkt
            except NameError:
                self.comment += "\n Fragments forwarded by BR not received"
                print("IPv4 Fragments forwarded by BR: FAIL")
                return
            if count == 0:
                self.v6_address_check(pkt)
                self.v6_port_check(pkt)
            if count == 1:  # Second Fragment
                self.v6_address_check(pkt)
                if pkt[0][1].nh != 44:
                    self.comment += "\n  No Fragment Header found"
                count += 1
            if count != 2:
                self.comment += "\n  Both fragments not received"
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("IPv4 Fragments forwarded by BR: FAIL")
        if not self.packet_error:
            print("IPv4 Fragments forwarded by BR: PASS")

    def echo_request(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n ICMPv6_ECHO_REQUEST"
        q = Queue()
        v4_cap_filter = 'icmp and dst {}'.format(self.ipv4_source_address)
        sniffer = Thread(target=self.v6sniffer, args=(q, v4_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
            icmp = ICMPv6EchoRequest()
            icmp.id = self.ipv6_udp_or_tcp_source_port
            payload = "H" * 10
            send(ip / icmp / payload, iface=self.ipv6_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  ICMPv4 Echo Request Not Received"
            print("Upstream Echo Request: FAIL")
            return
        self.v4_address_check(pkt)
        if pkt[0][1].proto != 1:
            self.comment += "\n  IP Protocol is not ICMPv6"
            self.packet_error = True
        if pkt[0][2].type != 8:
            self.comment += "\n  Incorrect Type Number"
            self.packet_error = True
        if pkt[0][2].code != 0:
            self.comment += "\n  Incorrect Code Number"
            self.packet_error = True
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("Upstream Echo Request: FAIL")
        if not self.packet_error:
            print("Upstream Echo Request: PASS")

    def echo_reply(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n ICMPv6_ECHO_REPLY"
        q = Queue()
        v4_cap_filter = 'icmp and dst {}'.format(self.ipv4_source_address)
        sniffer = Thread(target=self.v6sniffer, args=(q, v4_cap_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
            icmp = ICMPv6EchoReply()
            icmp.id = self.ipv6_udp_or_tcp_source_port
            payload = "H" * 10
            send(ip / icmp / payload, iface=self.ipv6_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  ICMPv4 Packet not received"
            print("Upstream Reply Respone: FAIL")
            return
        self.v4_address_check(pkt)
        if pkt[0][1].proto != 1:
            self.comment += "\n  ICMPv6 not received"
            self.packet_error = True
        if pkt[0][2].type != 0:
            self.comment += "\n  Incorrect Type Number"
            self.packet_error = True
        if pkt[0][2].code != 0:
            self.comment += "\n  Incorrect Code Number"
            self.packet_error = True
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("Upstream Reply Respone: FAIL")
        if not self.packet_error:
            print("Upstream Reply Respone: PASS")

    # Destination Unreachable - No route to destination, Communication with destination administratively prohibited,
    # Beyond scope of source address, Address unreachable, Port unreachable (Type 1, Code - 0/1/2/3/4)
    def destination_unreachable(self):
        code_values = [0, 1, 2, 3, 4]
        for code_value in code_values:
            self.m_finished = False
            self.packet_error = False
            self.comment = "\n ICMPv6_DESTINATION_UNREACHABLE"
            q = Queue()
            v4_cap_filter = 'icmp and dst {}'.format(self.ipv4_source_address)
            sniffer = Thread(target=self.v4sniffer, args=(q, v4_cap_filter, 5))
            sniffer.daemon = True
            sniffer.start()
            while not self.m_finished:
                ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                icmp = ICMPv6DestUnreach()
                icmp.code = code_value
                ip1 = IPv6(src=self.ipv6_destination_address, dst=self.ipv6_source_address)
                udp = UDP(sport=self.ipv6_udp_or_tcp_destination_port, dport=self.ipv6_udp_or_tcp_source_port)
                payload = "H" * 10
                send(ip / icmp / ip1 / udp / payload, iface=self.ipv6_interface, verbose=False)
            if not q.empty():
                file_name = self.comment.lower() + ".pcap"
                pktdump = PcapWriter(file_name, append=True, sync=True)
                while not q.empty():
                    pkt = q.get()
                    # print(pkt.show())
                    pktdump.write(pkt)
            try:
                pkt
            except NameError:
                self.comment += "\n  ICMPv4 Packet not received"
                print("Upstream Dest Unreachable Translation: FAIL")
                return
            self.v4_address_check(pkt)
            if pkt[0][1].proto != 1:
                self.comment += "\n  ICMPv6 not received"
                self.packet_error = True
            if pkt[0][2].type != 3:
                self.comment += "\n  Incorrect Type Number"
                self.packet_error = True
            if code_value == 0 and pkt[0][2].code != 1:
                self.comment += "\n  Incorrect Code Number for ICMPv6 Code 0 - was " + str(pkt[0][2].code)
                self.packet_error = True
            if code_value == 1 and pkt[0][2].code != 10:
                self.comment += "\n  Incorrect Code Number for ICMPv6 Code 1 - was " + str(pkt[0][2].code)
                self.packet_error = True
            if code_value == 2 and pkt[0][2].code != 1:
                self.comment += "\n  Incorrect Code Number for ICMPv6 Code 2 - was " + str(pkt[0][2].code)
                self.packet_error = True
            if code_value == 3 and pkt[0][2].code != 1:
                self.comment += "\n  Incorrect Code Number for ICMPv6 Code 3 - was " + str(pkt[0][2].code)
                self.packet_error = True
            if code == 4 and pkt[0][2].code != 3:
                self.comment += "\n  Incorrect Code Number for ICMPv6 Code 4 - was " + str(pkt[0][2].code)
                self.packet_error = True
            if self.packet_error:
                fh = open("test_results.txt", "a")
                fh.write(self.comment)
                fh.close()
                print("Upstream Dest Unreachable Translation for ICMPv6 Code " + str(code_value) + " : FAIL")
            if not self.packet_error:
                print("Upstream Dest Unreachable Translation for ICMPv6 Code " + str(code_value) + " : PASS")

    def packet_too_big(self):
        mtu_values = [512, 513, 1024, 1025, 1278, 1279, 1280, 1281, 1282, 1472, 1480, 1498, 1499, 1500, 1518, 1550, 1600]
        for mtu_value in mtu_values: 
            self.m_finished = False
            self.packet_error = False
            self.comment = "\n ICMPv6_PACKET_TOO_BIG"
            q = Queue()
            v4_cap_filter = 'icmp and dst {}'.format(self.ipv4_source_address)
            sniffer = Thread(target=self.v6sniffer, args=(q, v4_cap_filter, 17))
            sniffer.daemon = True
            sniffer.start()
            rx_mtu = mtu_value - 20 
            while not self.m_finished:
                ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                icmp = ICMPv6PacketTooBig()
                icmp.mtu = mtu_value
                ip1 = IPv6(src=self.ipv6_destination_address, dst=self.ipv6_source_address)
                udp = UDP(sport=self.ipv6_udp_or_tcp_destination_port, dport=self.ipv6_udp_or_tcp_source_port)
                payload = "H" * 10
                send(ip / icmp / ip1 / udp / payload, iface=self.ipv6_interface, verbose=False)
            if not q.empty():
                file_name = self.comment.lower() + ".pcap"
                pktdump = PcapWriter(file_name, append=True, sync=True)
                while not q.empty():
                    pkt = q.get()
                    #print(pkt.show())
                    pktdump.write(pkt)
                    q.task_done()
            try:
                pkt
            except NameError:
                self.comment += "\n  ICMPv4 Packet not received"
                print("Upstream Packet too Big Translation: FAIL")
                return
            self.v4_address_check(pkt)
            if pkt[0][1].proto != 1:
                self.comment += "\n  ICMPv6 not received"
                self.packet_error = True
            if pkt[0][2].type != 3:
                self.comment += "\n  Incorrect Type Number"
                self.packet_error = True
            if pkt[0][2].code != 4:
                self.comment += "\n  Incorrect Code Number"
                self.packet_error = True
            if pkt[0][ICMP].nexthopmtu != rx_mtu:
                self.comment += "\n  Incorrect MTU values - should be " + str(rx_mtu) + " but was " + str(pkt[0][ICMP].nexthopmtu)
                self.packet_error = True
            if self.packet_error:
                fh = open("test_results.txt", "a")
                fh.write(self.comment)
                fh.close()
                print("Upstream Packet Too Big Translation (IPv6: " + str(mtu_value) + ", IPv4: " + str(rx_mtu) + "): FAIL")
            if not self.packet_error:
                print("Upstream Packet Too Big Translation (IPv6: " + str(mtu_value) + ", IPv4: " + str(rx_mtu) + "): PASS")

    def time_exceeded(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n ICMPv6_TIME_EXCEEDED"
        q = Queue()
        v4_cap_filter = 'icmp and dst {}'.format(self.ipv4_source_address)
        sniffer = Thread(target=self.v6sniffer, args=(q, v4_cap_filter, 5))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
            icmp = ICMPv6TimeExceeded()
            icmp.code = 0
            ip1 = IPv6(src=self.ipv6_destination_address, dst=self.ipv6_source_address)
            udp = UDP(sport=self.ipv6_udp_or_tcp_destination_port, dport=self.ipv6_udp_or_tcp_source_port)
            payload = "H" * 10
            send(ip / icmp / ip1 / udp / payload, iface=self.ipv6_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  ICMPv4 Packet not received"
            print("Upstream Time Exceeded Translation: FAIL")
            return
        self.v4_address_check(pkt)
        if pkt[0][1].proto != 1:
            self.comment += "\n  ICMPv6 not received" 
            self.packet_error = True
        if pkt[0][2].type != 11:
            self.comment += "\n  Incorrect Type Number"
            self.packet_error = True
        if pkt[0][2].code != 0:
            self.comment += "\n  Incorrect Code Number, Code was " + str(pkt[0][2].code)
            self.packet_error = True
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("Upstream Time Exceeded Translation: FAIL")
        if not self.packet_error:
            print("Upstream Time Exceeded Translation: PASS")

    def parameter_problem_pointer(self):
        self.comment = "\n ICMPv6_PARAMETER_PROBLEM_POINTER"
        self.packet_error = True
        for ptr_value in range(0, 40):
            self.m_finished = False
            q = Queue()
            v4_cap_filter = 'icmp and dst {}'.format(self.ipv4_source_address)
            sniffer = Thread(target=self.v6sniffer, args=(q, v4_cap_filter, 38))
            sniffer.daemon = True
            sniffer.start()
            count = 0
            while not self.m_finished:
                ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                icmp = ICMPv6ParamProblem()
                icmp.code = 0
                icmp.ptr = ptr_value
                ip1 = IPv6(src=self.ipv6_destination_address, dst=self.ipv6_source_address)
                udp = UDP(sport=self.ipv6_udp_or_tcp_destination_port, dport=self.ipv6_udp_or_tcp_source_port)
                payload = "H" * 10
                send(ip / icmp / ip1 / udp / payload, iface=self.ipv6_interface, verbose=False)
            if not q.empty():
                file_name = self.comment.lower() + ".pcap"
                pktdump = PcapWriter(file_name, append=True, sync=True)
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                pktdump.write(pkt)
            try:
                pkt
            except NameError:
                self.comment += "\n  ICMPv4 Packet not received"
                print("Upstream Parameter Problem Pointer Translation: FAIL")
                return
            if pkt[0][1].proto != 1:
                self.comment += "\n  ICMPv4 not received"
                self.packet_error = True
            if pkt[0][2].type != 12:
                self.comment += "\n  Incorrect Type Number"
                self.packet_error = True
            if pkt[0][2].code != 0:
               self.comment += "\n  Incorrect Code Number"
               self.packet_error = True
            ipv4_ptr_values = [x for x in range(17)]
            if pkt[0][ICMP].ptr not in ipv4_ptr_values:
                self.comment += "\n  Incorrect Pointer values"
                self.packet_error = True
            count += 1
        if count != 39:
            self.comment += "\n  All packets not received"
            self.packet_error = True
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("Upstream Parameter Problem Pointer Translation: FAIL")
        if not self.packet_error:
            print("Upstream Parameter Problem Pointer Translation: PASS")


    def parameter_problem(self):
        self.m_finished = False
        self.packet_error = False
        self.comment = "\n ICMPv6_PARAMETER_PROBLEM"
        q = Queue()
        v4_cap_filter = 'icmp and dst {}'.format(self.ipv4_source_address)
        sniffer = Thread(target=self.v6sniffer, args=(q, v4_cap_filter, 2))
        sniffer.daemon = True
        sniffer.start()
        while not self.m_finished:
            code_values = [1, 2]
            for code_value in code_values:
                ip = IPv6(src=self.ipv6_source_address, dst=self.ipv6_destination_address)
                icmp = ICMPv6ParamProblem()
                icmp.code = code_value

                ip1 = IPv6(src=self.ipv6_destination_address, dst=self.ipv6_source_address)
                udp = UDP(sport=self.ipv6_udp_or_tcp_destination_port, dport=self.ipv6_udp_or_tcp_source_port)
                payload = "H" * 10
                send(ip / icmp / ip1 / udp / payload, iface=self.ipv6_interface, verbose=False)
        if not q.empty():
            file_name = self.comment.lower() + ".pcap"
            pktdump = PcapWriter(file_name, append=True, sync=True)
            count = 0
            while not q.empty():
                pkt = q.get()
                # print(pkt.show())
                pktdump.write(pkt)
        try:
            pkt
        except NameError:
            self.comment += "\n  ICMPv4 Packet not received"
            print("Upstream Parameter Problem Translation: FAIL")
            return
        self.v4_address_check(pkt)
        if pkt[0][1].proto != 1:
            self.comment += "\n  ICMPv6 not received"
            self.packet_error = True
        if pkt[0][2].type != 3:
            self.comment += "\n  Incorrect Type Number"
            self.packet_error = True
        if pkt[0][2].code != 0:
            self.comment += "\n  Incorrect Code Number"
            self.packet_error = True
            count += 1
        if count == 2:
            self.comment += "\n  Received two packets. Code 2 should be dropped"
            self.packet_error = True
        if self.packet_error:
            fh = open("test_results.txt", "a")
            fh.write(self.comment)
            fh.close()
            print("Upstream Parameter Problem Translation: FAIL")
        if not self.packet_error:
            print("Upstream Parameter Problem Translation: PASS")

    def v6_address_check(self, pkt):
        if pkt[0][IPv6].src != self.ipv6_destination_address:
            self.packet_error = True
            self.comment += "\n  v6 Source Address Error"
        if pkt[0][IPv6].dst != self.ipv6_source_address:
            self.packet_error = True
            self.comment += "\n v6 Destination Address Error"

    def v6_port_check(self, pkt):
        if pkt[0][2].sport != self.ipv6_udp_or_tcp_destination_port:
            self.packet_error = True
            self.comment += "\n  v6 UDP Source Port Error"
        if pkt[0][2].dport != self.ipv6_udp_or_tcp_source_port:
            self.packet_error = True
            self.comment += "\n  v6 UDP Destination Port Error"

    def v4_address_check(self, pkt):
        if pkt[0][IP].src != self.ipv4_destination_address:
            self.packet_error = True
            self.comment += "\n  v4 Source Address Error"
        if pkt[0][IP].dst != self.ipv4_source_address:
            self.packet_error = True
            self.comment += "\n  v4 Destination Address Error"

    def v4_port_check(self, pkt):
        if pkt[0][2].sport != self.ipv4_udp_or_tcp_destination_port:
            self.packet_error = True
            self.comment += "\n  v4 UDP Source Port Error"
        if pkt[0][2].dport != self.ipv4_udp_or_tcp_source_port:
            self.packet_error = True
            self.comment += "\n  UDP Destination Port Error"

    def v6sniffer(self, q, filter, count):
        packet = sniff(count=count, iface=ipv6_interface, filter=filter, prn=lambda x: q.put(x), timeout=5)
        self.m_finished = True

    def v4sniffer(self, q, filter, count):
        packet = sniff(count=count, iface=ipv4_interface, filter=filter, prn=lambda x: q.put(x), timeout=5)
        self.m_finished = True

# ******************** BR FUNCTIONALITY TEST CLASS - END ******************#

# ******************** MAIN FUNCTION - START ******************#

if __name__ == '__main__':
    # ******************** VARIABLES - START ******************#
    ipv4_source_address = "192.0.2.1"
    ipv4_destination_address = "198.18.0.12"
    ipv6_source_address = "2001:db8:f0:c30:0:c612:c:3"
    ipv6_destination_address = "2001:db8:ffff:ff00:c0:2:100:0"
    ipv4_udp_or_tcp_source_port = 65000
    ipv4_udp_or_tcp_destination_port = 16606
    ipv6_udp_or_tcp_source_port = 16606
    ipv6_udp_or_tcp_destination_port = 65000
    psid_number = 3
    ipv4_interface = "eth1"
    ipv6_interface = "eth1"
    # ******************** VARIABLES - END ******************#

    BR_obj = BRFunctionalityTest(ipv4_source_address,
                                 ipv4_destination_address,
                                 ipv6_source_address,
                                 ipv6_destination_address,
                                 ipv4_udp_or_tcp_source_port,
                                 ipv4_udp_or_tcp_destination_port,
                                 ipv6_udp_or_tcp_source_port,
                                 ipv6_udp_or_tcp_destination_port,
                                 psid_number,
                                 ipv4_interface,
                                 ipv6_interface)
    BR_obj.downstream_udp_packet_translation()
    BR_obj.upstream_udp_packet_translation()
    BR_obj.downstream_ttl_expired()
    BR_obj.upstream_hop_limit_expired()
    BR_obj.downstream_mss_clamping()
    BR_obj.upstream_mss_clamping()
    BR_obj.downstream_outside_port()
    BR_obj.upstream_outside_port()
    BR_obj.downstream_fragmentation()
    BR_obj.downstream_fragments()
    BR_obj.echo_request()
    BR_obj.echo_reply()
    BR_obj.destination_unreachable()
    BR_obj.packet_too_big()
    BR_obj.time_exceeded()
    BR_obj.parameter_problem_pointer()
# ******************** MAIN FUNCTION - END ******************#
