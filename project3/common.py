#!/usr/bin/env python

import time
import threading
from scapy.all import *
import sys
import socket
import json
import Queue
import interfaces

maxhop = 25

# A request that will trigger the great firewall but will NOT cause
# the web server to process the connection.  You probably want it here

triggerfetch = "GET /search?q=falun+gong HTTP/1.1\r\nhost: www.google.com\r\n\r\n"

# A couple useful functions that take scapy packets
def isRST(p):
    return (TCP in p) and (p[IP][TCP].flags & 0x4 != 0)

def isICMP(p):
    return ICMP in p

def isTimeExceeded(p):
    return ICMP in p and p[IP][ICMP].type == 11

# A general python object to handle a lot of this stuff...
#
# Use this to implement the actual functions you need.
class PacketUtils:
    def __init__(self, dst=None):
        # Get one's SRC IP & interface
        i = interfaces.interfaces()
        self.src = i[1][0]
        self.iface = i[0]
        self.netmask = i[1][1]
        self.enet = i[2]
        self.dst = dst
        sys.stderr.write("SIP IP %s, iface %s, netmask %s, enet %s\n" %
                         (self.src, self.iface, self.netmask, self.enet))
        # A queue where received packets go.  If it is full
        # packets are dropped.
        self.packetQueue = Queue.Queue(100000)
        self.dropCount = 0
        self.idcount = 0

        self.ethrdst = ""

        # Get the destination ethernet address with an ARP
        self.arp()
        
        # You can add other stuff in here to, e.g. keep track of
        # outstanding ports, etc.
        
        # Start the packet sniffer
        t = threading.Thread(target=self.run_sniffer)
        t.daemon = True
        t.start()
        time.sleep(.1)

    # generates an ARP request
    def arp(self):
        e = Ether(dst="ff:ff:ff:ff:ff:ff",
                  type=0x0806)
        gateway = ""
        srcs = self.src.split('.')
        netmask = self.netmask.split('.')
        for x in range(4):
            nm = int(netmask[x])
            addr = int(srcs[x])
            if x == 3:
                gateway += "%i" % ((addr & nm) + 1)
            else:
                gateway += ("%i" % (addr & nm)) + "."
        sys.stderr.write("Gateway %s\n" % gateway)
        a = ARP(hwsrc=self.enet,
                pdst=gateway)
        p = srp1([e/a], iface=self.iface, verbose=0)
        self.etherdst = p[Ether].src
        sys.stderr.write("Ethernet destination %s\n" % (self.etherdst))


    # A function to send an individual packet.
    def send_pkt(self, payload=None, ttl=32, flags="",
                 seq=None, ack=None,
                 sport=None, dport=80,ipid=None,
                 dip=None,debug=False):
        if sport == None:
            sport = random.randint(1024, 32000)
        if seq == None:
            seq = random.randint(1, 31313131)
        if ack == None:
            ack = random.randint(1, 31313131)
        if ipid == None:
            ipid = self.idcount
            self.idcount += 1
        t = TCP(sport=sport, dport=dport,
                flags=flags, seq=seq, ack=ack)
        ip = IP(src=self.src,
                dst=self.dst,
                id=ipid,
                ttl=ttl)
        p = ip/t
        if payload:
            p = ip/t/payload
        else:
            pass
        e = Ether(dst=self.etherdst,
                  type=0x0800)
        # Have to send as Ethernet to avoid interface issues
        sendp([e/p], verbose=1, iface=self.iface)
        # Limit to 20 PPS.
        time.sleep(.05)
        # And return the packet for reference
        return p


    # Has an automatic 5 second timeout.
    def get_pkt(self, timeout=5):
        try:
            return self.packetQueue.get(True, timeout)
        except Queue.Empty:
            return None

    # The function that actually does the sniffing
    def sniffer(self, packet):
        try:
            # non-blocking: if it fails, it fails
            self.packetQueue.put(packet, False)
        except Queue.Full:
            if self.dropCount % 1000 == 0:
                sys.stderr.write("*")
                sys.stderr.flush()
            self.dropCount += 1

    def run_sniffer(self):
        sys.stderr.write("Sniffer started\n")
        rule = "src net %s or icmp" % self.dst
        sys.stderr.write("Sniffer rule \"%s\"\n" % rule);
        sniff(prn=self.sniffer,
              filter=rule,
              iface=self.iface,
              store=0)

    # Sends the message to the target in such a way
    # that the target receives the msg without
    # interference by the Great Firewall.
    #
    # ttl is a ttl which triggers the Great Firewall but is before the
    # server itself (from a previous traceroute incantation
    def evade(self, target, msg, ttl):
        """

        1.  Sends packets in such a way that web server constructs correctly
            but the firewall doesn't. 
        2.  Successful response from the web server.
        3.  Return all payload returned by server over next 5 seconds.
        4.  Firewall and receiver reception is different. 

        """

        # Get \search?= HTTP\1.1 \r\n \r\n

        # Initial handshake. 
        source = random.randint(2000, 30000)
        seq = random.randint(1, 31313131)
        self.send_pkt(flags = "S", seq = seq, sport = source)
        pkt = self.get_pkt()

        y = pkt[TCP].seq

        self.send_pkt(flags = "A", seq = seq+1, ack = y+1, sport = source)

        seq = seq + 1
        msgSize = len(msg)
        for i in range(0, msgSize):
            char = msg[i]
            dummChar = "z"
            self.send_pkt(flags = "PA", payload = char, seq = seq,
                          ack = y+1, sport = source, ttl = 32)
            self.send_pkt(flags = "PA", payload = dummChar, seq = seq,
                          ack = y+1, sport = source, ttl = ttl)
            seq = seq + 1

        pkt = self.get_pkt()
        payload = ""

        # CurrTime + 5 
        endtime = time.time() + 5
        while pkt:
            if not isTimeExceeded(pkt) and 'Raw' in pkt:
                pkt.show()
                part_payload = pkt['Raw'].load
                payload += part_payload  
            pkt = self.get_pkt(endtime - time.time())
            
        return payload
        
    # Returns "DEAD" if server isn't alive,
    # "LIVE" if teh server is alive,
    # "FIREWALL" if it is behind the Great Firewall
    def ping(self, target):
        # 1. Select random source port between 2000 and 30000. 
        # 2. Create a random TCP SYN.
        # 3. Send TCP SYN to the server, wait for the SYN/ACK or a 5 second timeout. 
        # 4. Wait for the SYN/ACK or a 5 second timeout. 
        # 5. Once function receives the SYN/ACK, send an ACK and a single data packet 
        #   that would trigger the Great Firewall.
        # 6. Wait another 5 seconds to see if I receive a RST packet back from server. 


        source = random.randint(2000, 30000)
        seq = random.randint(1, 31313131)
        self.send_pkt(flags = "S", seq = seq, sport = source)
        pkt = self.get_pkt()

        if (isTimeExceeded(pkt)):
            return "DEAD"
        else: 
            y = pkt[TCP].seq
            self.send_pkt(payload = triggerfetch, flags = "A", seq = seq + 1,
                          ack = y+1,  sport = source)
                          
            pkt = self.get_pkt()
            while pkt:
                if isRST(pkt):
                    return "FIREWALL"
                pkt = self.get_pkt()
            return "LIVE"

    # Format is
    # ([], [])
    # The first list is the list of IPs that have a hop
    # or none if none
    # The second list is T/F 
    # if there is a RST back for that particular request
    def traceroute(self, target, hops):
        # RST and ICMP shoudl be treated the same by storing the ip and T/F values in corresponding lists.
        ip_list = []
        rst_list = []

        sent_p = self.send_pkt(flags = "S")
        sequence = sent_p.seq
        source = sent_p.sport
        pkt = self.get_pkt()

        if pkt is None:
            return

        y = pkt[TCP].seq

        for i in range(1, hops + 1):
            for y in range(3):
                self.send_pkt(ttl = i, payload = triggerfetch, flags = "PA",
                          seq = sequence + 1, ack = y + 1, sport = source)

            pkt = self.get_pkt(1)

            rst_list.append(False)
            ip_list.append(None)
            last_index = len(rst_list) - 1

            while pkt:
                if isTimeExceeded(pkt):
                    ip_list[last_index] = pkt[IP].src

                if isRST(pkt):
                    rst_list[last_index] = True

                pkt = self.get_pkt(1)

        return ip_list, rst_list
