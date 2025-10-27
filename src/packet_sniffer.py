from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
from datetime import datetime
from typing import Dict, Optional, Callable

class PacketSniffer:
    def __init__(self, interface: Optional[str] = None, packet_callback: Optional[Callable] = None):
        self.interface = interface
        self.packet_callback = packet_callback
        self.running = False
        self.packet_count = 0

        print(f" Packet Sniffer initialized")
        print(f"   Interface: {interface or 'Auto-detect'}")

    def parse_packet(self, packet) -> Optional[Dict]:
        try:
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': 'Unknown',
                'length': len(packet),
                'flags': '',
                'info': ''
            }
            # IP layer
            if IP in packet:
                packet_data['src_ip'] = packet[IP].src
                packet_data['dst_ip'] = packet[IP].dst
                packet_data['length'] = packet[IP].len
            else:
                packet_data['src_ip'] = "0.0.0.0"
                packet_data['dst_ip'] = "0.0.0.0"
            # TCP layer
            if TCP in packet:
                packet_data['protocol'] = 'TCP'
                packet_data['src_port'] = packet[TCP].sport
                packet_data['dst_port'] = packet[TCP].dport
                flags = []
                if packet[TCP].flags.S: flags.append('SYN')
                if packet[TCP].flags.A: flags.append('ACK')
                if packet[TCP].flags.F: flags.append('FIN')
                if packet[TCP].flags.R: flags.append('RST')
                if packet[TCP].flags.P: flags.append('PSH')
                packet_data['flags'] = '|'.join(flags)
                packet_data['info'] = f"TCP {packet[TCP].sport} → {packet[TCP].dport}"
            elif UDP in packet:
                packet_data['protocol'] = 'UDP'
                packet_data['src_port'] = packet[UDP].sport
                packet_data['dst_port'] = packet[UDP].dport
                packet_data['info'] = f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
            elif ICMP in packet:
                packet_data['protocol'] = 'ICMP'
                packet_data['info'] = f"ICMP Type {packet[ICMP].type}"
            elif ARP in packet:
                packet_data['protocol'] = 'ARP'
                packet_data['src_ip'] = packet[ARP].psrc
                packet_data['dst_ip'] = packet[ARP].pdst
                packet_data['info'] = f"ARP {packet[ARP].op}"
            if Raw in packet:
                payload_len = len(packet[Raw].load)
                packet_data['info'] += f" [Payload: {payload_len} bytes]"
            return packet_data
        except Exception as e:
            print(f" Error parsing packet: {e}")
            return None

    def packet_handler(self, packet):
        self.packet_count += 1
        data = self.parse_packet(packet)
        if self.packet_callback and data:
            self.packet_callback(data)

    def start(self, count=0, filter_str=None):
        if self.running:
            print("  Sniffer already running")
            return
        self.running = True
        self.packet_count = 0
        print(f" Starting packet capture...")
        print(f"   Interface: {self.interface or 'All'}")
        print(f"   Count: {count if count > 0 else 'Unlimited'}")
        print(f"   Filter: {filter_str or 'None'}")
        print(f"   Press Ctrl+C to stop\n")
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=count,
                filter=filter_str,
                store=False
            )
        except Exception as e:
            print(f" Sniffing error: {e}")
        finally:
            print(f"Capture finished after {self.packet_count} packets")
            self.running = False

    def stop(self):
        if self.running:
            self.running = False
            print(f"\n Sniffer stopped after capturing {self.packet_count} packets")
        else:
            print("Sniffer already stopped")

    def is_running(self):
        return self.running
