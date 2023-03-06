from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import sys
import time

DHCP_IP = "10.0.0.11"
CLIENT_IP = "10.0.0.13"
DNS_IP = "10.0.0.12"
IFACE = "enp0s1"  # network name


def handle_dhcp_request(packet):
    if packet[DHCP]:
        if packet[DHCP].options[0][1] == 1:  # DHCP discover message
            print(f"Received DHCP discover message from client {packet[Ether].src}")
            # # Create DHCP offer packet
            dhcp_mac = str(get_if_hwaddr(IFACE))  # Enter the computer name here
            dhcp_offer = Ether(src=dhcp_mac, dst=packet[Ether].src) / \
                         IP(src=DHCP_IP, dst="255.255.255.255") / \
                         UDP(sport=67, dport=68) / \
                         BOOTP(op=2, yiaddr=CLIENT_IP, siaddr=DHCP_IP, xid=packet[BOOTP].xid,
                               chaddr=packet[BOOTP].chaddr) / \
                         DHCP(options=[("message-type", "offer"), ("subnet_mask", "255.255.255.0"),
                                       ("router", DNS_IP), ("lease_time", 86400), ("dns_server", DNS_IP),
                                       "end"])
            # # Send DHCP offer packet
            time.sleep(1)
            sendp(dhcp_offer, iface=IFACE)
            print("Sent DHCP offer message to client")


        elif packet[DHCP].options[0][1] == 3:  # DHCP request message
            print(f"Received DHCP request message from client {packet[Ether].src}")
            # Create DHCP ack packet
            dhcp_mac = str(get_if_hwaddr(IFACE))  # Enter the computer name here
            dhcp_ack = Ether(src=dhcp_mac, dst=packet[Ether].src) / \
                       IP(src=DHCP_IP, dst="255.255.255.255") / \
                       UDP(sport=67, dport=68) / \
                       BOOTP(op=2, yiaddr=CLIENT_IP, siaddr=DHCP_IP, xid=packet[BOOTP].xid,
                             chaddr=packet[BOOTP].chaddr) / \
                       DHCP(options=[("message-type", "ack"), ("subnet_mask", "255.255.255.0"),
                                     ("router", DNS_IP), ("lease_time", 86400), ("dns_server", DNS_IP),
                                     "end"])
            # Send DHCP ack packet
            time.sleep(1)
            sendp(dhcp_ack, iface="enp0s1")
            print("Sent DHCP ack message to client")
            # end the program
            sys.exit()


# Start sniffing DHCP requests
print("DHCP server id runing........")
sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp_request, iface=IFACE)




