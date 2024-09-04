from scapy.all import IP, TCP, UDP, Raw, sniff

def packet_callback(packet):
    # Check if the packet contains an IP layer
    if IP in packet:
        ip_src = packet[IP].src  # Source IP address
        ip_dest = packet[IP].dst  # Destination IP address
        protocol = packet[IP].proto  # Protocol number

        print(f"[+] Packet captured: {ip_src} --> {ip_dest} (Protocol: {protocol})")

    # Check if the packet contains a TCP layer
    if TCP in packet:
        print(f" - Protocol: TCP (Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport})")
    
    # Check if the packet contains a UDP layer
    elif UDP in packet:
        print(f" - Protocol: UDP (Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport})")

    # Check if the packet contains a Raw layer (payload data)
    if Raw in packet:
        print(f" - Payload: {packet[Raw].load}")

def start_sniffing(interface=None):
    print("[*] Starting packet capture...")
    try:
        # Start sniffing on the specified interface
        sniff(iface=interface, prn=packet_callback, store=False)
    except PermissionError:
        print("[!] Permission denied: Try running with elevated privileges.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == '__main__':
    # Replace "Intel(R) Wi-Fi 6 AX201 160MHz" with the appropriate network interface from the list printed earlier
    start_sniffing(interface="Intel(R) Wi-Fi 6 AX201 160MHz")