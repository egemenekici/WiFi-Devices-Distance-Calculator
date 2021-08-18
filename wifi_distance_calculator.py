from scapy.all import *
from threading import Thread
import pandas
import time
import os

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto", "Distance"])

# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

global frequency

def callback(packet):
    if packet.haslayer(Dot11Beacon):

        # get the MAC address of the network
        bssid = packet[Dot11].addr2

        # get the Name
        ssid = packet[Dot11Elt].info.decode()

        # get the RSSI power
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        # extract network stats
        stats = packet[Dot11Beacon].network_stats()

        # get the channel of the AP
        channel = stats.get("channel")

        # get the crypto
        crypto = stats.get("crypto")

        # enter the frequency of each channel
        global frequency

        if channel == 1:
            frequency = 2412
        elif channel == 2:
            frequency = 2417
        elif channel == 3:
            frequency = 2422
        elif channel == 4:
            frequency = 2427
        elif channel == 5:
            frequency = 2432
        elif channel == 6:
            frequency = 2437
        elif channel == 7:
            frequency = 2442
        elif channel == 8:
            frequency = 2447
        elif channel == 9:
            frequency = 2452
        elif channel == 10:
            frequency = 2457
        elif channel == 11:
            frequency = 2462
        elif channel == 12:
            frequency = 2467
        elif channel == 13:
            frequency = 2472
        elif channel == 14:
            frequency = 2477

        # use FSPL algorithm to calculate distance
        distance = math.pow(10,(27.55 - (20 * math.log10(frequency)) + math.fabs(dbm_signal)) / 20.0)

        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto, distance)

def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.5)


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")

        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


if __name__ == "__main__":

    # interface name, check before using with iwconfig
    interface = "wlan0"

    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()

    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    sniff(prn=callback, iface=interface)

