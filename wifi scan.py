from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp

def wifi_scanner(interface):
    networks = {}

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
            bssid = packet[Dot11].addr3
            if bssid not in networks:
                networks[bssid] = ssid
                print(f"SSID: {ssid}, BSSID: {bssid}")

    print("Scanning for Wi-Fi networks...")
    sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
    interface = input("Enter the wireless interface (e.g., wlan0): ")
    wifi_scanner(interface)