__version__ = "0.1.0"

import os
import subprocess
import sys
from scapy.all import *

a=rdpcap("Wireshark_captures/sha-256-toto.pcapng")
a.show()
