# ssh_mitm
Python scripts which perform a ssh mitm with scapy and paramiko.

In arp_poisoning.py you need to change some values:
- interface
- ARP_Obj.target_ip = "target_ip"
- ARP_Obj.gateway_ip = "gateway_ip"
- packet_count = number of packets sniffed before closing arp poisoning

The ssh tunnel, used with paramiko, listens on port 2200. Every packets from 22 are forwarded to port 2200.

In sshmitm.py, change REMOTE_PORT. This variable is the port of the remote ssh server.

Only the logging infos are logged.
