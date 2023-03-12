import unittest
from datetime import time
from socket import socket

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff

from Dns import dns_cache, handle_dns_request
mac = "7e:b1:37:1c:4b:d4"  # The mac address
DNS_IP = "10.0.0.12"
CLIENP_IP = "10.0.0.18"
IFACE = socket.if_nameindex()[1][1]  # network name
class TestDNSCache(unittest.TestCase):

    def test_dns_cache_hit(self):
        # create a DNS query packet for a domain name in the cache
        domain_name = 'www.google.com'
        dns_query = Ether(dst=mac, src=mac) / \
                    IP(dst=DNS_IP, src=CLIENP_IP) / \
                    UDP(dport=53, sport=5353) / \
                    DNS(rd=1, qd=DNSQR(qname=domain_name, qtype=1))

        # send DNS request packet and receive response
        time.sleep(1)
        sendp(dns_query, iface=IFACE, verbose=2)

        anser = sniff(filter="udp and port 5353", timeout=5, count=1)
        # ensure that the handle_dns_request function returns the correct response packet
        self.assertEqual(anser[0][DNSRR][0].rdata, "8.8.8.8")




if __name__ == '__main__':
    unittest.main()