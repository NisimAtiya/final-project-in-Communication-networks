# final-project-in-Communication-networks
## Communication System with DNS, DHCP, and FTP Servers
#### Introduction
This project aims to build a communication system that enables clients to connect with a DNS server, DHCP server, and an application server running an FTP (File Transfer Protocol) application. The system allows clients to upload and download files to/from the FTP server and view the available files on the server.

#### Dynamic Host Configuration Protocol (DHCP)
DHCP is a network protocol used for automatically assigning IP addresses and other network configuration information to devices on a network. It eliminates the need for manual IP address assignment and simplifies the process of connecting devices to the network and facilitating communication between them.

The DHCP communication process between the server and the client involves four main phases: Discover, Offer, Request, and Acknowledge.

1. Discover: When a device connects to the network, it sends a Discover DHCP message as a broadcast, requesting an IP address. The DHCP server responds with an Offer DHCP message, which includes an available IP address and other network configuration information.

2. Offer: The DHCP server receives the Discover message and sends an Offer message to the client. This message contains the server's IP address, subnet mask, lease time (how long the IP address is valid), and other configuration options.

3. Request: Upon receiving the Offer message, the client sends a Request DHCP message to the server, formally requesting the offered IP address and confirming the other network configuration information.

4. Acknowledge: If the offered IP address is still available, the server responds with an Acknowledge DHCP message (ACK). The ACK message confirms the assignment of the IP address to the client and provides the lease time and other network configuration details. The client configures its network settings based on the received ACK message and starts using the assigned IP address.

The DHCP protocol simplifies IP address management, saves time, and reduces the likelihood of errors in network setup and management.

#### Domain Name System (DNS)
DNS is a protocol used to translate human-readable domain names (e.g., example.com) into computer-readable IP addresses (e.g., 192.168.0.1). It is an essential part of the Internet infrastructure that allows users to access websites and other network resources using domain names instead of remembering numeric IP addresses.

The DNS communication process involves several stages:

1. User Query: When a user enters a domain name in their web browser, the browser sends a DNS query to the DNS server. The query includes the domain name the user wants to access.

2. Recursive Query: If the DNS server does not have the IP address of the requested domain name in its cache, it performs a recursive query. The server starts from the root DNS servers and works down the hierarchy of DNS to locate the authoritative DNS server for the requested domain name.

3. Root Servers: The root DNS servers are a global network of servers that store information about top-level domains and their associated authoritative DNS servers. The recursive query starts at one of the root servers and requests the IP addresses for the requested domain.

4. TLD Servers: Once the root server responds with the IP address of the authoritative DNS server for the requested top-level domain, the recursive query is sent to the top-level domain (TLD) server. The TLD server provides the IP address of the authoritative DNS server for the next level down in the DNS hierarchy.

5. Authoritative Server: The recursive query continues down the DNS hierarchy until it reaches the authoritative DNS server for the requested domain name. The authoritative server responds with the requested IP address for the domain.

6. DNS Response: The DNS server receives the IP address from the authoritative server and returns it to the user. This allows the user to establish a connection to the requested domain server.

The DNS protocol plays a critical role in translating domain names to IP addresses, enabling seamless access to network resources.

#### FTP (File Transfer Protocol)
FTP is a standard protocol used for transferring files over the Internet. It allows users to transfer files between a client and a server. The FTP communication process involves establishing a connection, authentication, file transfer, and issuing commands.

1. Connection Establishment: The FTP client sends a request to connect to the FTP server using the server's IP address and port number via IP/TCP.

2. Authentication: Once the client and server are connected, the client must authenticate itself by providing a username and password. If the credentials are correct, the server grants access to the client for file transfer.

3. File Transfer: After authentication, the client can issue commands to the server to upload or download files. FTP supports two transfer modes: ASCII mode for text files and binary mode for non-text files like images or executables.

4. Commands: FTP includes a set of commands that the client can use to interact with the server. Some common commands include GET (download a file from the server to the client), PUT (upload a file from the client to the server), and LS (list the contents of the current directory on the server).

5. Connection Termination: After the file transfer is complete, the client can close the connection to the server by sending a request to terminate the connection. The server responds with confirmation, and the connection is closed.

FTP can be secured using encryption, such as FTPS (FTP over SSL) or SFTP (Secure File Transfer Protocol), to protect the transmission of sensitive information. However, FTP has limitations, including vulnerabilities to eavesdropping and data tampering during file transfer. It may not be suitable for transferring large files at high rates or frequently transferring many small files.

### Conclusion
The communication system developed for this project combines the functionalities of DNS, DHCP, and FTP servers. It enables clients to automatically obtain IP addresses and network configuration information using DHCP, resolve domain names to IP addresses using DNS, and transfer files to/from the FTP server. By integrating these protocols, the system provides a comprehensive solution for network communication, IP address management, and file transfer within a network environment.
