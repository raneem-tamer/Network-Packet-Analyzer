from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
# Function to handle each captured packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        protocol_name = get_protocol_name(protocol)
        # Check for TCP or UDP and get payload
        if protocol_name == 'TCP':
            payload = bytes(packet[TCP].payload)
        elif protocol_name == 'UDP':
            payload = bytes(packet[UDP].payload)
        else:
            payload = bytes(packet[IP].payload)

        # Print packet details
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol_name}")
        print(f"Payload: {payload.hex()}")
        print("="*50)

# Function to map protocol numbers to names
def get_protocol_name(protocol_num):
    protocol_map = {6: 'TCP', 17: 'UDP'}
    return protocol_map.get(protocol_num, 'Other')
# Start packet sniffing
sniff(prn=packet_callback, count=10)
