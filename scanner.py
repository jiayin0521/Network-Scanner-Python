import scapy.all as scapy

def scan(ip):
    print(f"[*] Scanning network: {ip}")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def port_scan(ip):
    # Common ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 445 (SMB)
    common_ports = [22, 80, 443, 445]
    open_ports = []
    
    for port in common_ports:
        # Sending a SYN packet to check if the port is open
        syn_packet = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(syn_packet, timeout=0.5, verbose=False)
        
        if response and response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
            open_ports.append(port)
            # Send a Reset packet to close the connection politely
            scapy.sr(scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="R"), timeout=0.5, verbose=False)
            
    return open_ports

# --- MAIN EXECUTION ---
target_ip = "192.168.100.0/24" # Keep your specific range here
scan_results = scan(target_ip)

print("\nIP Address\t\tMAC Address\t\tOpen Ports")
print("------------------------------------------------------------")
for client in scan_results:
    # This runs the port scan for every device found
    found_ports = port_scan(client["ip"])
    ports_str = ", ".join(map(str, found_ports)) if found_ports else "None"
    print(f"{client['ip']}\t\t{client['mac']}\t{ports_str}")
