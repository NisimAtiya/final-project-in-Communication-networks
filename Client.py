from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.l2 import Ether
import time
from scapy.layers.inet import fragment

IFACE = "enp0s1"  # network name
CLIENP_IP = 0
DNS_IP = 0
DHCP_IP = 0
AP_IP = 0
domain_name = "www.my_ftp.com"#input("Enter the desired domain name: ")  # domain name to query
mac = "7e:b1:37:1c:4b:d4"  # The mac address

def get_ips(packet):
    print("dhcp offer chath!!!")
    global CLIENP_IP
    global DHCP_IP
    global DNS_IP
    CLIENP_IP = packet[BOOTP].yiaddr
    DHCP_IP = packet[BOOTP].siaddr
    DNS_IP = packet[DHCP].options[2][1]



def get_ip_domain(packet):
    AP_IP = packet[DNSRR][0].rdata
    print(f"The  ip is : {AP_IP}")
    print(f"Sent DNS response for {domain_name} -> {AP_IP}")


# Set up DHCP discover packet
dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff') / \
                IP(src='0.0.0.0', dst='255.255.255.255') / \
                UDP(sport=68, dport=67) / \
                BOOTP() / \
                DHCP(options=[('message-type', 'discover'), 'end'])

# Send DHCP discover
time.sleep(1)
sendp(dhcp_discover, iface=IFACE)

# Sniff for DHCP Offer response and pulls out the ips
sniff(filter="udp and port 67", prn=get_ips, count=1, iface=IFACE)

# Set up DHCP request packet
dhcp_request = Ether(dst='ff:ff:ff:ff:ff:ff') / \
               IP(src='0.0.0.0', dst='255.255.255.255') / \
               UDP(sport=68, dport=67) / \
               BOOTP() / \
               DHCP(options=[('message-type', 'request'), 'end'])

# Send DHCP request
time.sleep(1)
sendp(dhcp_request, iface=IFACE)

# Sniff for DHCP ack response
dhcp_ack = sniff(filter="udp and (port 67)", count=1)

print(f"your ip is : {CLIENP_IP}")
print(f"The DHCP server ip is : {DHCP_IP}")
print(f"The DNS ip is : {DNS_IP}")

# create DNS request packet

dns_query = Ether(dst=mac, src=mac) /\
            IP(dst=DNS_IP, src=CLIENP_IP) /\
            UDP(dport=53, sport=5353) /\
            DNS(rd=1, qd=DNSQR(qname=domain_name, qtype=1))

# send DNS request packet and receive response
time.sleep(1)
sendp(dns_query, iface=IFACE, verbose=2)

sniff(filter="udp and port 5353", prn=get_ip_domain, timeout=5, count=1)


src_port = 30663
dest_port = 20027
choice = input("(0) to exit\n"
               "(1) to see the server's files.\n"
               "(2) to upload a file to the server.\n"
               "ֿֿ(3) to download a file to the server.\n"
               "Enter what you want to do: ")
while choice != "0":
    if choice == "1":
        print("1")
    if choice == "2":
        file_to_open = input("Enter the name of the file you want to upload: ")
        packet = Ether(src=mac, dst=mac) /\
                IP(src=CLIENP_IP, dst=AP_IP) / \
                UDP(sport=src_port, dport=dest_port) /\
                file_to_open
        time.sleep(1)

        sendp(packet, iface=IFACE)

        # with open("client_file/" + file_to_open, "r") as file:
        #     file_data = file.read()
        # # Split the file data into chunks of 1000 bytes
        # data_chunks = [file_data[i:i + 1000] for i in range(0, len(file_data), 1000)]
        # # Send each packet and handle retransmissions
        # for packet in data_chunks:
        #     response = None
        #     while response is None:
        #         # Send the packet and wait for a response
        #         response = sr1(IP(src=CLIENP_IP, dst=AP_IP) /
        #                        UDP(sport=src_port, dport=dest_port) /
        #                        packet, timeout=1,verbose=0)
        #         if response is None:
        #             # No response received, retransmit the packet
        #             print("Retransmitting packet...")
        #         else:
        #             # Response received, check for errors
        #             if response.haslayer(ICMP):
        #                 # Packet was lost, retransmit
        #                 print("Packet lost, retransmitting...")
        #                 response = None
        #             elif response.haslayer(UDP) and response[UDP].sport == dest_port:
        #                 # Packet was received correctly, move on to the next packet
        #                 break

        print("The file has been uploaded successfully.")
    if choice == "3":
        print("3")
    choice = input("(0) to exit\n"
                   "(1) to see the server's files.\n"
                   "(2) to upload a file to the server.\n"
                   "ֿֿ(3) to download a file to the server.\n"
                   "Enter what you want to do: ")
print("Bye Bye")
