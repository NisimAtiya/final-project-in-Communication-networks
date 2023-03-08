from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.layers.l2 import Ether
import time
import os
from scapy.layers.inet import fragment

IFACE = "enp0s1"  # network name
CLIENP_IP = "10.0.0.13"
DNS_IP = "10.0.0.12"
DHCP_IP = "10.0.0.11"
AP_IP = "10.0.0.18"
domain_name = "www.my_ftp.com"  # input("Enter the desired domain name: ")  # domain name to query
mac = "7e:b1:37:1c:4b:d4"  # The mac address

#
# def get_ips(packet):
#     print("dhcp offer chath!!!")
#     global CLIENP_IP
#     global DHCP_IP
#     global DNS_IP
#     CLIENP_IP = packet[BOOTP].yiaddr
#     DHCP_IP = packet[BOOTP].siaddr
#     DNS_IP = packet[DHCP].options[2][1]
#
#
# def get_ip_domain(packet):
#     global AP_IP
#     AP_IP = packet[DNSRR][0].rdata
#     print(f"The  ip is : {AP_IP}")
#     print(f"Sent DNS response for {domain_name}: {AP_IP}")
#
#
# # Set up DHCP discover packet
# dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff') / \
#                 IP(src='0.0.0.0', dst='255.255.255.255') / \
#                 UDP(sport=68, dport=67) / \
#                 BOOTP() / \
#                 DHCP(options=[('message-type', 'discover'), 'end'])
#
# # Send DHCP discover
# time.sleep(1)
# sendp(dhcp_discover, iface=IFACE)
#
# # Sniff for DHCP Offer response and pulls out the ips
# sniff(filter="udp and port 67", prn=get_ips, count=1, iface=IFACE)
#
# # Set up DHCP request packet
# dhcp_request = Ether(dst='ff:ff:ff:ff:ff:ff') / \
#                IP(src='0.0.0.0', dst='255.255.255.255') / \
#                UDP(sport=68, dport=67) / \
#                BOOTP() / \
#                DHCP(options=[('message-type', 'request'), 'end'])
#
# # Send DHCP request
# time.sleep(1)
# sendp(dhcp_request, iface=IFACE)
#
# # Sniff for DHCP ack response
# dhcp_ack = sniff(filter="udp and (port 67)", count=1)
#
# print(f"your ip is : {CLIENP_IP}")
# print(f"The DHCP server ip is : {DHCP_IP}")
# print(f"The DNS ip is : {DNS_IP}")
#
# # create DNS request packet
#
# dns_query = Ether(dst=mac, src=mac) / \
#             IP(dst=DNS_IP, src=CLIENP_IP) / \
#             UDP(dport=53, sport=5353) / \
#             DNS(rd=1, qd=DNSQR(qname=domain_name, qtype=1))
#
# # send DNS request packet and receive response
# time.sleep(1)
# sendp(dns_query, iface=IFACE, verbose=2)
#
# sniff(filter="udp and port 5353", prn=get_ip_domain, timeout=5, count=1)

src_port = 30663
dest_port = 20027
choice = input("(0) to exit\n"
               "(1) to see the server's files.\n"
               "(2) to upload a file to the server.\n"
               "(3) to download a file to the server.\n"
               "Enter what you want to do: ")
while choice != "0":
    if choice == "1":
        print("1")
    if choice == "2":
        # Sending to the server I want to upload a file
        request = Ether(src=mac, dst=mac) / \
                  (IP(src=CLIENP_IP, dst=AP_IP) /
                   UDP(sport=src_port, dport=dest_port) /
                   "put")
        time.sleep(1)
        sendp(request, iface=IFACE)

        reply = sniff(filter="udp and udp src port 20027", count=1)
        ack_nack = reply[0].load.decode()
        if (ack_nack == "ack"):
            file_to_upload = input("Enter the name of the file you want to upload: ")
            while os.path.exists("client_file/" + file_to_upload) == False:
                print(f"the file {file_to_upload} is not exsiting")
                file_to_upload = input("Enter the name of the file you want to upload: ")
            # Sending the name of the file I upload
            packet = Ether(src=mac, dst=mac) / \
                     IP(src=CLIENP_IP, dst=AP_IP) / \
                     UDP(sport=src_port, dport=dest_port) / \
                     file_to_upload
            time.sleep(1)
            sendp(packet, iface=IFACE)
            # Sending the size of the file I upload
            file_size_bytes = os.path.getsize("client_file/" + file_to_upload)
            packet = Ether(src=mac, dst=mac) / \
                     IP(src=CLIENP_IP, dst=AP_IP) / \
                     UDP(sport=src_port, dport=dest_port) / \
                     str(file_size_bytes)
            time.sleep(1)
            sendp(packet, iface=IFACE)

            file = open("client_file/" + file_to_upload, "r")
            file_data = file.read()
            file.close()

            # Create the TCP packet with the file data as the payload
            packet = Ether(src=mac, dst=mac) / \
                     IP(src=CLIENP_IP, dst=AP_IP) / \
                     TCP(sport=src_port, dport=dest_port) / \
                     Raw(load=file_data)
            time.sleep(1)
            sendp(packet, iface=IFACE)

            # # Split the file data into chunks of 1000 bytes
            # data_chunks = [file_data[i:i + 1000] for i in range(0, len(file_data), 1000)]
            # # Send each packet and handle retransmissions
            # for packet in data_chunks:
            #     response = None
            #     while response is None:
            #         # Send the packet and wait for a response
            #         chunk = Ether(src=mac, dst=mac) / \
            #                 (IP(src=CLIENP_IP, dst=AP_IP) /
            #                  UDP(sport=src_port, dport=dest_port) /
            #                  packet)
            #         time.sleep(1)
            #         sendp(chunk, iface=IFACE)
            #         response = sniff(filter="udp and udp src port 20027", count=1)
            #         ackNack = response[0].load.decode()
            #
            #         if ackNack == "nack":
            #             # No response received, retransmit the packet
            #             print("Retransmitting packet...")
            #             response = None
            #         else:
            #             # Response received, check for errors
            #             if response.haslayer(ICMP):
            #                 # Packet was lost, retransmit
            #                 print("Packet lost, retransmitting...")
            #                 response = None
            #             elif response.haslayer(UDP) and ackNack == "ack":
            #                 # Packet was received correctly, move on to the next packet
            #                 break

            print("The file has been uploaded successfully.")

    if choice == "3":
        # Sending to the server I want to download a file
        request = Ether(src=mac, dst=mac) / \
                  (IP(src=CLIENP_IP, dst=AP_IP) /
                   UDP(sport=src_port, dport=dest_port) /
                   "get")
        time.sleep(1)
        sendp(request, iface=IFACE)
        # Waiting for confirmation from the server
        reply = sniff(filter="udp and udp src port 20027", count=1)
        ack_nack = reply[0].load.decode()

        if (ack_nack == "ack"):

            file_to_download = input("Enter the name of the file you want to download: ")
            packet = Ether(src=mac, dst=mac) / \
                     IP(src=CLIENP_IP, dst=AP_IP) / \
                     UDP(sport=src_port, dport=dest_port) / \
                     file_to_download
            time.sleep(1)
            sendp(packet, iface=IFACE)
            # Waiting for confirmation if there is a file named file_to_download from the server
            reply = sniff(filter="udp and udp src port 20027", count=1)
            ack_nack = reply[0].load.decode()
            while (ack_nack == "nack"):
                print(f"The server has no file named {file_to_download}")
                file_to_download = input("Enter the name of the file you want to download: ")
                packet = Ether(src=mac, dst=mac) / \
                         IP(src=CLIENP_IP, dst=AP_IP) / \
                         UDP(sport=src_port, dport=dest_port) / \
                         file_to_download
                time.sleep(1)
                sendp(packet, iface=IFACE)
                # Waiting for confirmation if there is a file named file_to_download from the server
                reply = sniff(filter="udp and udp src port 20027", count=1)
                ack_nack = reply[0].load.decode()

            # capture packets until the entire file has been received
            file_data = b""
            # sniffing file
            packet = sniff(filter="tcp and tcp src port 20027", count=1, timeout=5)[0]
            # Put in file_data the contents of the file
            file_data += bytes(packet[TCP].payload)

            # save file data to disk and close him and prints a message that the file has been successfully downloaded
            f = open("client_file/" + file_to_download, "wb")
            f.write(file_data)
            f.close()
            print(f"A file {file_to_download} has been added to the ftp server successfully")

    choice = input("(0) to exit\n"
                   "(1) to see the server's files.\n"
                   "(2) to upload a file to the server.\n"
                   "\u05bf\u05bf(3) to download a file to the server.\n"
                   "Enter what you want to do: ")
print("Bye Bye")
