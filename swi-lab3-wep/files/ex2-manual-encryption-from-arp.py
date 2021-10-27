#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zlib

from rc4 import RC4
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11WEP

"""
Manually encrypt a WEP message using a given WEP key and IV.
The packet is read from the arp.cap file and then modified.
"""

# Clé WEP : AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

# On part du message chiffré pour le modifier par la suite.
pck = rdpcap('arp.cap')[0]

# On crée un nouveau message et on calcule l'ICV.
message = b'hello_world!'
icv = zlib.crc32(message).to_bytes(4, byteorder='little')

# On chiffre le message + icv.
seed = pck.iv + key
cipher = RC4(seed, streaming=False)
encrypted_message = cipher.crypt(message + icv)

# On modifie le message (arp.wepdata) ainsi que l'ICV.
pck.wepdata = encrypted_message[:-4]
pck.icv = int.from_bytes(encrypted_message[-4:], byteorder='big')

# On écrit le packet dans une nouvelle capture pcap.
pck[RadioTap].len = None  # pour que la taille du packet soit recalculée par scapy
wrpcap('ex2.cap', pck, append=False)
print(pck.show())
