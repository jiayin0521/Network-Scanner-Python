import scapy.all as scapy

def scan(ip):
    print(f"Scanning the network range: {ip}")
    # This creates an ARP request to find devices on your WiFi
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

# Change this to your home WiFi IP range (usually 192.168.1.1/24)
scan("192.168.100.0/24")