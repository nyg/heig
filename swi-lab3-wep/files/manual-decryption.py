#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__ = "Abraham Rubinstein"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from rc4 import RC4
from scapy.all import *

# Clé wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

# lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv + key

# Récupération de icv dans le message (arp.icv) (en chiffré) — je passe au format "text".
# Il y a d'autres manières de faire ceci...
icv_encrypted = '{:x}'.format(arp.icv)

# text chiffré y compris l'icv
message_encrypted = arp.wepdata + bytes.fromhex(icv_encrypted)

# déchiffrement rc4
cipher = RC4(seed, streaming=False)
cleartext = cipher.crypt(message_encrypted)

# le ICV est les derniers 4 octets — je le passe en format Long big endian
icv_enclair = cleartext[-4:]
icv_enclair = icv_enclair
icv_numerique = struct.unpack('!L', icv_enclair)

# le message sans le ICV
text_enclair = cleartext[:-4]

print('msg chiffré:  ', arp.wepdata.hex())
print('msg déchiffré:', text_enclair.hex())
print('icv chiffré:  ', icv_encrypted)
print('icv déchiffré:', icv_enclair.hex())
print('icv (num):    ', str(icv_numerique))
