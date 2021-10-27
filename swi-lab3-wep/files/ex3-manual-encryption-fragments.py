#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zlib

from rc4 import RC4
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11WEP

"""
Manually encrypt a WEP message in fragments using a given WEP key and IV.
The packet is created from scratch with scapy, it is not read from the arp.cap file.
"""

# Clé WEP : AA:AA:AA:AA:AA
iv = b'\x0cM\\'  # IV du packet ARP fourni
key = b'\xaa\xaa\xaa\xaa\xaa'

message = b'hello this is a fragmented message !'
for i in range(3):
    # Warning : afin de tester, message non divisible par 3 peut avoir des pertes d'informations
    fragmentSize = int(len(message) / 3)
    # Découpe le message en fragments
    fragmentMessage = message[fragmentSize*i:fragmentSize*(i+1)]
    # Calcul de l'ICV du fragment actuel
    icv = zlib.crc32(fragmentMessage).to_bytes(4, byteorder='little')

    # On chiffre le fragment + icv.
    seed = iv + key
    cipher = RC4(seed, streaming=False)
    encrypted_message = cipher.crypt(fragmentMessage + icv)

    # On crée un nouveau packet avec les bonnes valeurs.
    wepdata = encrypted_message[:-4]
    encrypted_icv = int.from_bytes(encrypted_message[-4:], byteorder='big')
    # Si ce n'est pas le dernier fragment (!= 2) l'on rajout MF (More Fragments) à notre frame Dot11
    if i != 2:
        pck = RadioTap() / Dot11(type='Data', FCfield='to-DS+protected+MF') / Dot11WEP(iv=iv, wepdata=wepdata, icv=encrypted_icv)
    else:
        pck = RadioTap() / Dot11(type='Data', FCfield='to-DS+protected') / Dot11WEP(iv=iv, wepdata=wepdata, icv=encrypted_icv)
    
    pck.SC = i
    # On ajoute le fragment dans une capture pcap.
    wrpcap('ex3.cap', pck, append=True)
    print(pck.show())
