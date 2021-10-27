#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zlib

from rc4 import RC4
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11WEP

"""
Manually encrypt a WEP message using a given WEP key and IV.
The packet is created from scratch with scapy, it is not read from the arp.cap file.
"""

# Clé WEP : AA:AA:AA:AA:AA
iv = b'\x0cM\\'  # IV du packet ARP fourni
key = b'\xaa\xaa\xaa\xaa\xaa'

# On crée un nouveau message et on calcule son ICV.
message = b'hello_world!'
icv = zlib.crc32(message).to_bytes(4, byteorder='little')

# On chiffre le message + icv.
seed = iv + key
cipher = RC4(seed, streaming=False)
encrypted_message = cipher.crypt(message + icv)

# On crée un nouveau packet avec les bonnes valeurs.
wepdata = encrypted_message[:-4]
encrypted_icv = int.from_bytes(encrypted_message[-4:], byteorder='big')
pck = RadioTap() / Dot11(type='Data', FCfield='to-DS+protected') / Dot11WEP(iv=iv, wepdata=wepdata, icv=encrypted_icv)

# On écrit le packet dans une nouvelle capture pcap.
wrpcap('ex2.cap', pck, append=False)
print(pck.show())
