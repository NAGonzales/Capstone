#Barebones functional Network Intrusion Detection System
from scapy import *
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sniff
from scapy.utils import rdpcap
from collections import deque
from tkinter import *
from tkinter import messagebox
import sys
import time
import os



# Function to check if the packet is a TCP packet
def is_tcp(packet):
    return packet.haslayer(TCP)

# Function to check if the packet is an IP packet
def is_ip(packet):
    return packet.haslayer(IP)

# Function to check if the packet is an ICMP packet
def is_icmp(packet):
    return packet.haslayer(ICMP)

# Function to check if the packet is a UDP packet
def is_udp(packet):
    return packet.haslayer(UDP)

# Function to check if the packet is a Raw packet
def is_raw(packet):
    return packet.haslayer(Raw)


packet_counts = {"tcp": 0, "ip": 0, "icmp": 0, "udp": 0, "raw": 0, "unknown": 0}
connections = {}


# Function to summarize the connection
def connection_summary(packet):
    if is_tcp(packet):
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if src not in connections:
            connections[src] = []
        connections[src].append((dst, sport, dport))
        if dst not in connections:
            connections[dst] = []
        connections[dst].append((src, dport, sport))
        print(connections)

# Keep track of the timestamps of the last 100 SYN packets
syn_timestamps = deque(maxlen=100)

# Function to analyze the packet
def analyze_packet(packet):
    if is_tcp(packet):
        packet_counts["tcp"] += 1
        print("TCP Packet")
        print(packet.show())
        print(packet_counts)

        #check for SYN packets
        if 'S' in packet[TCP].flags:
            syn_timestamps.append(time.time())
            if len(syn_timestamps) >= 100 and syn_timestamps[-1] - syn_timestamps[0] < 3:
                    print("SYN Flood Detected")
                    print("100 SYN packets in less than 3 seconds")
                    print("Attacker IP: ", packet[IP].src)
                    print("Target IP: ", packet[IP].dst)
                    print("Target Port: ", packet[TCP].dport)
                    print("Timestamps: ", syn_timestamps)
                    print(packet.show())

                    # Create a popup window to alert the user of the SYN Flood
                    root = Tk()
                    root.withdraw()
                    messagebox.showinfo("Denial of Service!", "Syn Flood Detected - 100 SYN packets in less than 3 seconds")
                    root.destroy()
        else:
            print("Not a SYN Packet")
            print(packet.show())
    elif is_ip(packet):
        packet_counts["ip"] += 1
        print("IP Packet")
        print(packet.show())
        print(packet_counts)
    elif is_icmp(packet):
        packet_counts["icmp"] += 1
        print("ICMP Packet")
        print(packet.show())
        print(packet_counts)
    elif is_udp(packet):
        packet_counts["udp"] += 1
        print("UDP Packet")
        print(packet.show())
        print(packet_counts)
    elif is_raw(packet):
        packet_counts["raw"] += 1
        print("Raw Packet")
        print(packet.show())
        print(packet_counts)
    else:
        print("Unknown Packet")
        print(packet.show())
        packet_counts["unknown"] += 1
        print(packet_counts)


scan_attempts = {} # Track scan attempts per IP
scan_threshold = 50 # Adjust threshold as needed
scan_time_window = 30 # Time Window (in seconds)
last_packet_time = {}
# This feature allows for detection of port scanning
def port_scanning(packet):
    if is_tcp(packet) and (packet[TCP.flags & 0x02 or packet[TCP].flags & 0x10]):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        key = (src_ip, dst_port)
        current_time = time.time()

        if src_ip in last_packet_time:
            if current_time - last_packet_time[src_ip] < 1:
                root = Tk()
                root.withdraw()
                messagebox.showinfo("Possible port scan detected from:", src_ip)
                root.destroy()

        # Update scan attempts and timestamps    
        if key in scan_attempts:
            last_time, count = scan_attempts[key]
            if current_time - last_time <= scan_time_window:
                count +=1
            else:
                count = 1
            scan_attempts[key] = (current_time, count)

            # Check if scan threshold is exceeded
            if count >= scan_threshold:
                root = Tk()
                root.withdraw()
                messagebox.showinfo("Possible port scan detected from:", src_ip)
                root.destroy()

                # Reset the count for this IP and port
                del scan_attempts[key]

# Payload Analysis
def analyze_payload(packet):
    if is_tcp(packet):
        payload = packet[TCP].payload

def ping_of_death(packet):
    if IP in packet and len(packet[IP]) >= 60000:
            print("Ping of Death Detected")
            root = Tk()
            root.withdraw()
            messagebox.showinfo("PING OF DEATH DETECTED!")
            root.destroy()

sniff(prn=analyze_packet)
sniff(prn=connection_summary)
sniff(prn=port_scanning)
sniff(prn=ping_of_death)

# sudo /bin/python /home/noe/Capstone/nids.py = This Command is used to run the scriptb