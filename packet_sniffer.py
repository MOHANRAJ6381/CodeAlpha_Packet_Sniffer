from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
def process_packet(packet):
    # Check if the packet has an Ethernet layer
    if Ether in packet:
        eth = packet[Ether]
        print(f'\nEthernet Frame: Source MAC: {eth.src}, Destination MAC: {eth.dst}')
    
    # Check if the packet has an IP layer
    if IP in packet:
        ip = packet[IP]
        print(f'IPv4 Packet: Source: {ip.src}, Destination: {ip.dst}, TTL: {ip.ttl}')

        # Check if it's a TCP Packet
        if TCP in packet:
            tcp = packet[TCP]
            print(f'TCP Segment: Source Port: {tcp.sport}, Destination Port: {tcp.dport}, Sequence: {tcp.seq}')
        
        # Check if it's a UDP Packet
        elif UDP in packet:
            udp = packet[UDP]
            print(f'UDP Segment: Source Port: {udp.sport}, Destination Port: {udp.dport}')
        
        # Check if it's an ICMP Packet
        elif ICMP in packet:
            icmp = packet[ICMP]
            print(f'ICMP Packet: Type: {icmp.type}, Code: {icmp.code}')

# Main function to start sniffing
def main():
    # Sniff network packets (use filter for specific protocols if needed)
    print("Starting packet sniffing...")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
