from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import time

IFACE = socket.if_nameindex()[1][1]  # network name

# Dictionary to hold the DNS mappings
dns_cache = {
    'www.google.com': '216.58.194.174',
    'www.facebook.com': '31.13.92.36',
    'www.twitter.com': '104.244.42.129',
    'www.my_ftp.com': '10.0.0.18'
}

# IP address of the upstream DNS server to query if a domain name is not found in the cache
google_dns = "8.8.8.8"


# Function to handle DNS requests
def handle_dns_request(packet):
    if packet.haslayer(DNSQR):
        # Extract the requested domain name from the DNS query
        domain_name = packet[DNSQR].qname.decode('utf-8')[:-1]
        print(f"Received DNS query for {domain_name} domin")

        if domain_name in dns_cache:  # If the IP address for the domain name is found in the cache,
            # create a DNS response packet and send it back to the client

            print("the IP address for the domain name is found in the cache ")
            dns_response = Ether(dst=packet[Ether].src, src=packet[Ether].dst) / \
                           IP(dst=packet[IP].src, src=packet[IP].dst) / \
                           UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                           DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                               an=DNSRR(rrname=packet[DNSQR].qname, ttl=60, rdata=dns_cache[domain_name]))
            time.sleep(1)
            sendp(dns_response, iface=IFACE)
            print(f"Sent DNS response for {domain_name}: {dns_cache[domain_name]}")
        else:  # If the IP address for the domain name is not found in the cache, query the google DNS server and  cache the response
            print("the IP address for the domain name is not found in the cache")

            # Create the DNS request packet
            dns_query = IP(dst=google_dns) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain_name))

            # Send the DNS request packet and receive response
            response = sr1(dns_query, multi=False, verbose=0)
            print(f"the rcode is: {response[DNS].rcode}")

            if response[DNS].rcode==0:
                # Extract the IP address from the DNS response
                ip_address = response[DNS].an.rdata
                # Adds it to DNS_Cache
                dns_cache[domain_name] = ip_address

                # Create a DNS response packet and send it back to the client
                dns_response = Ether(dst=packet[Ether].src, src=packet[Ether].dst) / \
                               IP(dst=packet[IP].src, src=packet[IP].dst) / \
                               UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                               DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                   an=DNSRR(rrname=packet[DNSQR].qname, ttl=60, rdata=ip_address))
                time.sleep(1)
                sendp(dns_response, iface=IFACE)
                print(f"Sent DNS response for {domain_name}: {ip_address} (from upstream DNS)")
            if response[DNS].rcode == 3:
                print(f"No ip address found for domain {domain_name}")

# Start sniffing for DNS requests
print("DNS server id runing........")
sniff(filter="udp port 53", prn=handle_dns_request, count=1)
