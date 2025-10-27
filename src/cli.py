"""
CLI Interface for Network Packet Sniffer
Provides interactive command-line control
"""

import argparse
import signal
import sys
import time
from datetime import datetime

from packet_sniffer import PacketSniffer
from anomaly_detector import AnomalyDetector
from database import PacketDatabase
from alert_system import AlertSystem
import config

class PacketSnifferCLI:
    """Command-line interface for packet sniffer"""
    
    def __init__(self):
        self.sniffer = None
        self.detector = None
        self.database = None
        self.alert_system = None
        self.running = False
    
    def setup(self):
        """Initialize all components"""
        print("=" * 60)
        print("🔒 NETWORK PACKET SNIFFER WITH ANOMALY DETECTION")
        print("=" * 60)
        
        # Initialize database
        self.database = PacketDatabase(config.DB_PATH)
        
        # Initialize anomaly detector
        self.detector = AnomalyDetector(
            port_scan_threshold=config.PORT_SCAN_THRESHOLD,
            flood_threshold=config.FLOOD_THRESHOLD,
            time_window=config.TIME_WINDOW
        )
        
        # Initialize alert system
        smtp_config = {
            'smtp_server': config.SMTP_SERVER,
            'smtp_port': config.SMTP_PORT,
            'sender_email': config.SENDER_EMAIL,
            'sender_password': config.SENDER_PASSWORD,
            'receiver_email': config.RECEIVER_EMAIL
        } if config.EMAIL_ALERTS_ENABLED else None
        
        self.alert_system = AlertSystem(
            log_file=config.LOG_FILE,
            email_enabled=config.EMAIL_ALERTS_ENABLED,
            smtp_config=smtp_config
        )
        
        # Initialize sniffer with callback
        self.sniffer = PacketSniffer(
            interface=config.NETWORK_INTERFACE,
            packet_callback=self.process_packet
        )
        
        print("\n✅ All systems initialized")
    
    def process_packet(self, packet_data):
        """
        Process each captured packet
        
        Args:
            packet_data: Dictionary containing packet information
        """
        # Store in database
        self.database.insert_packet(packet_data)
        
        # Check for anomalies
        alerts = self.detector.analyze_packet(packet_data)
        
        # Process any alerts
        for alert in alerts:
            self.database.insert_alert(alert)
            self.alert_system.send_alert(alert)
        
        # Display packet info
        src = f"{packet_data['src_ip']}:{packet_data['src_port'] or 'N/A'}"
        dst = f"{packet_data['dst_ip']}:{packet_data['dst_port'] or 'N/A'}"
        
        print(f"[{packet_data['timestamp'].split('T')[1][:8]}] "
              f"{packet_data['protocol']:5s} | {src:21s} → {dst:21s} | "
              f"{packet_data['length']:5d}B | {packet_data['flags']}")
    
    def start_sniffing(self, args):
        """Start packet capture"""
        self.running = True
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
        print(f"\n{'='*60}")
        print("🔍 STARTING PACKET CAPTURE")
        print(f"{'='*60}")
        
        # Start sniffer
        self.sniffer.start(
            count=args.count,
            filter_str=args.filter
        )
        
        # Keep running until stopped
        try:
            while self.running and self.sniffer.is_running():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop all operations"""
        print("\n\n Shutting down...")
        self.running = False
        
        if self.sniffer:
            self.sniffer.stop()
        
        # Show final statistics
        self.show_statistics()
        
        # Close database
        if self.database:
            self.database.close()
        
        print("\n Shutdown complete")
        sys.exit(0)
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        self.stop()
    
    def show_statistics(self):
        """Display capture statistics"""
        print(f"\n{'='*60}")
        print(" CAPTURE STATISTICS")
        print(f"{'='*60}")
        
        if self.database:
            stats = self.database.get_statistics()
            
            print(f"\n Packets:")
            print(f"   Total: {stats.get('total_packets', 0)}")
            
            print(f"\n🔌 Protocol Distribution:")
            for proto, count in list(stats.get('protocols', {}).items())[:5]:
                print(f"   {proto}: {count}")
            
            print(f"\n Top Source IPs:")
            for ip, count in list(stats.get('top_src_ips', {}).items())[:5]:
                print(f"   {ip}: {count} packets")
            
            print(f"\n Top Destination IPs:")
            for ip, count in list(stats.get('top_dst_ips', {}).items())[:5]:
                print(f"   {ip}: {count} packets")
            
            print(f"\n Alerts:")
            print(f"   Total: {stats.get('total_alerts', 0)}")
            for alert_type, count in stats.get('alert_types', {}).items():
                print(f"   {alert_type}: {count}")
    
    def show_recent_alerts(self, limit=10):
        """Display recent alerts"""
        print(f"\n{'='*60}")
        print(f" RECENT ALERTS (Last {limit})")
        print(f"{'='*60}\n")
        
        alerts = self.database.get_recent_alerts(limit)
        
        if not alerts:
            print("No alerts recorded")
            return
        
        for alert in alerts:
            print(f"[{alert[1]}] {alert[2]} ({alert[3]})")
            print(f"   IP: {alert[4]} | {alert[5]}")
            print(f"   Details: {alert[6]}\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Network Packet Sniffer with Anomaly Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/cli.py                    # Start with default settings
  python src/cli.py -c 1000            # Capture 1000 packets
  python src/cli.py -f "tcp port 80"   # Filter HTTP traffic
  python src/cli.py -i Ethernet        # Specify interface (Windows)
  python src/cli.py --stats            # Show statistics only
  python src/cli.py --alerts           # Show recent alerts
        """
    )
    
    parser.add_argument('-i', '--interface', 
                       help='Network interface to sniff')
    parser.add_argument('-c', '--count', type=int, default=0,
                       help='Number of packets to capture (0=unlimited)')
    parser.add_argument('-f', '--filter',
                       help='BPF filter string (e.g., "tcp port 80")')
    parser.add_argument('--stats', action='store_true',
                       help='Show statistics and exit')
    parser.add_argument('--alerts', action='store_true',
                       help='Show recent alerts and exit')
    
    args = parser.parse_args()
    
    # Create CLI instance
    cli = PacketSnifferCLI()
    cli.setup()
    
    # Handle different modes
    if args.stats:
        cli.show_statistics()
        sys.exit(0)
    
    if args.alerts:
        cli.show_recent_alerts()
        sys.exit(0)
    
    # Override config with command line args
    if args.interface:
        config.NETWORK_INTERFACE = args.interface
    
    # Start sniffing
    cli.start_sniffing(args)


if __name__ == "__main__":
    main()
