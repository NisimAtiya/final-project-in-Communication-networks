import pwd

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.layers.l2 import Ether
import time

# Define the destination IP and port to receive the packet
mac = "7e:b1:37:1c:4b:d4"  # The mac address
AP_IP = "10.0.0.18"
src_port = 20027
dest_port = 30663
IFACE = socket.if_nameindex()[1][1]  # network name
CLIENP_IP = "10.0.0.13"
# Define a filter for the filename packet
filename_filter = "udp and udp src port 30663"


def put():
    # Gets the name of the file to upload
    file_name = sniff(filter=filename_filter, count=1)
    name = file_name[0].load.decode()
    # Gets the size of the file to upload
    file_size = sniff(filter=filename_filter, count=1)
    size = int(file_size[0].load.decode())
    print(f"The name of the file to upload is: {name}, and its size is: {size} bytes")

    # capture packets until the entire file has been received
    file_data = b""
    # sniffing file
    packet = sniff(filter="tcp and tcp src port 30663", count=1, timeout=5)[0]
    # Put in file_data the contents of the file
    file_data += bytes(packet[TCP].payload)

    # save file data to disk and close him and prints a message that the file has been successfully downloaded
    f = open("ftp_file/" + name, "wb")
    f.write(file_data)
    f.close()

    # set the path of the file you want to change the permissions of
    file_path = "ftp_file/" + name

    # set the desired permissions for the file (in octal format)
    new_permissions = 0o777

    # use the os module to change the permissions of the file
    os.chmod(file_path, new_permissions)

    # set the username of the new owner of the file
    new_owner = socket.getfqdn().split('.')[0]

    # get the uid of the new owner
    new_owner_uid = pwd.getpwnam(new_owner).pw_uid

    # use the os module to change the owner of the file
    os.chown(file_path, new_owner_uid, -1)

    print(f"A file {name} has been added to the ftp server successfully")



def get():
    # Gets the name of the file to download
    file_name = sniff(filter=filename_filter, count=1)
    name = file_name[0].load.decode()
    while os.path.exists("ftp_file/" + name)==False:
        ack_nack = Ether(src=mac, dst=mac) / \
                  (IP(src=AP_IP, dst=CLIENP_IP) /
                   UDP(sport=src_port, dport=dest_port) /
                   "nack")
        time.sleep(1)
        sendp(ack_nack, iface=IFACE)
        # Gets the name of the file to upload
        file_name = sniff(filter=filename_filter, count=1)
        name = file_name[0].load.decode()

    ack_nack = Ether(src=mac, dst=mac) / \
               (IP(src=AP_IP, dst=CLIENP_IP) /
                UDP(sport=src_port, dport=dest_port) /
                "ack")
    time.sleep(1)
    sendp(ack_nack, iface=IFACE)

    file = open("ftp_file/" + name, "r")
    file_data = file.read()
    file.close()

    # Create the TCP packet with the file data as the payload
    packet = Ether(src=mac, dst=mac) / \
             IP(src=AP_IP, dst=CLIENP_IP) / \
             TCP(sport=src_port, dport=dest_port) / \
             Raw(load=file_data)
    time.sleep(1)
    sendp(packet, iface=IFACE)
    print("The file has been download successfully.")

def ls():
    # Set the path to the directory containing the files
    directory_path = "ftp_file"


    # Get a list of all the file names in the directory
    file_names = os.listdir(directory_path)

    # Sort the list of file names alphabetically
    sorted_file_names = sorted(file_names)
    sorted_file_names_string = ', '.join(sorted_file_names)


    # Create the TCP packet with the file data as the payload
    packet = Ether(src=mac, dst=mac) / \
             IP(src=AP_IP, dst=CLIENP_IP) / \
             UDP(sport=src_port, dport=dest_port) / \
             sorted_file_names_string
    time.sleep(1)
    sendp(packet, iface=IFACE)
    print("The files has been sent to shown successfully.")






# Define a callback function to extract the filename from the packet
def extract_wahttodo(pkt):
    print("packet catch")
    # Gets from the client what he wants to do
    what_todo = pkt[0].load.decode()
    print(f"the command that the server will aplay is {what_todo}")
    if what_todo == "put":
        # Sends the client a confirmation that he wants to upload files
        request = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / \
                  (IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                   UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                   "ack")
        time.sleep(1)
        sendp(request, iface=IFACE)

        put()
    elif what_todo == "get":
        # Sends the client a confirmation that he wants to upload files
        request = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / \
                  (IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                   UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                   "ack")
        time.sleep(1)
        sendp(request, iface=IFACE)
        get()
    else:
        # Sends the client a confirmation that he when to see the file
        request = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / \
                  (IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                   UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                   "ack")
        time.sleep(1)
        sendp(request, iface=IFACE)
        ls()

    # Start sniffing for incoming packets
    # sniff(filter=f"udp and src {RECEIVER_IP} and dst {listen_ip} and port {dest_port}", prn=get)


# Start sniffing for what to do(put\get\ls)
print("my_ftp server is online.....")
sniff(filter=filename_filter, prn=extract_wahttodo)
