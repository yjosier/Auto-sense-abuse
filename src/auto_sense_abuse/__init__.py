__version__ = "0.1.0"

import os
import subprocess
import sys
import random
import socket
from scapy.all import *
from scapy.contrib.lldp import *
from scapy.contrib.isis import *

#a=rdpcap("Wireshark_captures/sha-256-one-side-from-startup.pcapng")
#p_rcv = PacketList(a)[0]

#print(p_rcv.getlayer(LLDPDUChassisID).id) # Extract the MAC address from the Chassis ID field

# print("####################")
# lldp_layer = p[0].getlayer(LLDPDUChassisID)
# if lldp_layer:
#     print(lldp_layer.subtype)
#     print(lldp_layer.fields)
#     print(lldp_layer.id)
# print("####################")

def derive_mac(input: str) -> str:
    parts = input.split(":")
    parts[4] = f"{random.randint(0, 255):02x}"
    new_mac = ":".join(parts)
    return new_mac

def derive_ip(input: bytes) -> bytes:
    parts = list(input)
    parts[3] = random.randint(1, 254)
    new_ip = bytes(parts)
    return new_ip

def derive_autosense(input: bytes) -> bytes:
    output = input[:3] + os.urandom(6) + input[-8:]
    return output

def main():
    #packet = sniff(ifaces="eth0", filter="ether proto 0x88cc", count=1)
    packet = sniff(offline="Wireshark_captures/sha-256-one-side-from-startup.pcapng", filter="ether proto 0x88cc", count=1)

    src_mac = packet[0].getlayer(LLDPDUChassisID).id
    src_ip = packet[0].getlayer(LLDPDUManagementAddress).management_address
    src_fa = packet[0].getlayer(LLDPDUGenericOrganisationSpecific, 1)
    src_autosense = packet[0].getlayer(LLDPDUGenericOrganisationSpecific, 2)

    #packet[0].layers()
    #print("###############################")
    #packet.show()
    #print(lastlayer(packet[0]))
    #print(packet[0].lastlayer)
    #print(type(src_mac))
    #print(mac2str(src_mac))
    #print(src_mac)
    #print(socket.inet_ntoa(src_ip))
    #print(list(src_org))
    #print("FA show")
    #print(type(src_fa))
    #src_fa.show()
    #print(src_fa.data[:-10])
    #print("Autosense show")
    #src_autosense.show()
    #print("###############################")

    #packet[0].getlayer(LLDPDUManagementAddress).show()
    #print(packet[0].getlayer(LLDPDUChassisID).id)
    

    new_mac = derive_mac(src_mac)
    new_ip = derive_ip(src_ip)
    new_fa = src_fa.data[:-10] + mac2str(new_mac) + bytearray(b'\x00\x00\x00\xc0')
    new_autosense = derive_autosense(src_autosense.data)

    # print(new_mac)
    # print(mac2str(new_mac))
    # print(src_fa.data)
    # print(new_fa)
    #print(socket.inet_ntoa(new_ip))
    pkt_to_send=packet[0]
    pkt_to_send[Ether].src = new_mac
    pkt_to_send[LLDPDUChassisID].id = new_mac
    pkt_to_send[LLDPDUManagementAddress].management_address = new_ip

    if pkt_to_send[LLDPDUGenericOrganisationSpecific:1].org_code == 1037 :
        pkt_to_send[LLDPDUGenericOrganisationSpecific:1].data = new_fa
    if pkt_to_send[LLDPDUGenericOrganisationSpecific:2].org_code == 14189670 :
        pkt_to_send[LLDPDUGenericOrganisationSpecific:2].data = new_autosense

    pkt_to_send.show()
    wrpcap(filename="Wireshark_captures/output.pcapng",pkt=pkt_to_send)



if __name__ == "__main__":
    main()