"""
Anomaly Detection Engine for Network Packet Sniffer
Detects various types of network anomalies like port scanning, flooding, etc.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class AnomalyDetector:
    """
    Detects network traffic anomalies using various detection algorithms
    """
    
    def __init__(self, 
                 port_scan_threshold: int = 10,
                 flood_threshold: int = 100,
                 time_window: int = 60):
        """
        Initialize anomaly detector with configurable thresholds
        
        Args:
            port_scan_threshold: Number of unique ports to trigger port scan alert
            flood_threshold: Packets per second to trigger flood alert
            time_window: Time window in seconds for anomaly detection
        """
        self.port_scan_threshold = port_scan_threshold
        self.flood_threshold = flood_threshold
        self.time_window = time_window
        
        # Tracking dictionaries
        self.ip_port_map = defaultdict(set)     # Track ports accessed by each IP
        self.ip_timestamps = defaultdict(list)  # Track packet timestamps per IP
        self.protocol_counts = defaultdict(int) # Track protocol distribution
        
        # Alert tracking to prevent duplicate alerts
        self.recent_alerts = defaultdict(lambda: datetime.min)
        self.alert_cooldown = timedelta(seconds=30)  # Minimum time between same alerts
        
        print(" Anomaly Detector initialized")
        print(f"   Port Scan Threshold: {port_scan_threshold} unique ports")
        print(f"   Flood Threshold: {flood_threshold} packets/sec")
        print(f"   Time Window: {time_window} seconds")
    
    def analyze_packet(self, packet_data: Dict) -> List[Dict]:
        """
        Analyze a packet for anomalies
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            List of detected anomaly alerts (empty if no anomalies)
        """
        alerts = []
        
        src_ip = packet_data.get('src_ip')
        dst_port = packet_data.get('dst_port')
        protocol = packet_data.get('protocol')
        timestamp = datetime.fromisoformat(packet_data.get('timestamp', datetime.now().isoformat()))
        
        if not src_ip:
            return alerts
        
        # Update tracking data
        self.ip_timestamps[src_ip].append(timestamp)
        if dst_port:
            self.ip_port_map[src_ip].add(dst_port)
        if protocol:
            self.protocol_counts[protocol] += 1
        
        # Clean old data outside time window
        self._clean_old_data(src_ip, timestamp)
        
        # Check for port scanning
        port_scan_alert = self._detect_port_scan(src_ip, timestamp)
        if port_scan_alert:
            alerts.append(port_scan_alert)
        
        # Check for flooding/DoS
        flood_alert = self._detect_flood(src_ip, timestamp)
        if flood_alert:
            alerts.append(flood_alert)
        
        # Check for suspicious protocols
        suspicious_protocol_alert = self._detect_suspicious_protocol(packet_data)
        if suspicious_protocol_alert:
            alerts.append(suspicious_protocol_alert)
        
        # Check for unusual packet sizes
        size_alert = self._detect_unusual_packet_size(packet_data)
        if size_alert:
            alerts.append(size_alert)
        
        return alerts
    
    def _clean_old_data(self, src_ip: str, current_time: datetime):
        """
        Remove data older than time window
        
        Args:
            src_ip: Source IP address
            current_time: Current timestamp
        """
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        # Remove old timestamps
        self.ip_timestamps[src_ip] = [
            ts for ts in self.ip_timestamps[src_ip] 
            if ts > cutoff_time
        ]
        
        # If no recent activity, clean up IP data
        if not self.ip_timestamps[src_ip]:
            self.ip_port_map.pop(src_ip, None)
    
    def _detect_port_scan(self, src_ip: str, timestamp: datetime) -> Optional[Dict]:
        """
        Detect potential port scanning activity
        
        A port scan is detected when a single IP accesses many different ports in a short time window
        """
        unique_ports = len(self.ip_port_map[src_ip])
        
        if unique_ports >= self.port_scan_threshold:
            alert_key = f"port_scan_{src_ip}"
            if self._should_alert(alert_key, timestamp):
                return {
                    'timestamp': timestamp.isoformat(),
                    'alert_type': 'Port Scan',
                    'severity': 'HIGH',
                    'src_ip': src_ip,
                    'description': f'Potential port scan detected from {src_ip}',
                    'details': f'Scanned {unique_ports} unique ports in {self.time_window} seconds.'
                }
        return None
    
    def _detect_flood(self, src_ip: str, timestamp: datetime) -> Optional[Dict]:
        """
        Detect flooding/DoS attacks
        
        Flooding is detected when packet rate exceeds threshold
        """
        recent_timestamps = self.ip_timestamps[src_ip]
        if len(recent_timestamps) < 10:
            return None
        
        time_span = (recent_timestamps[-1] - recent_timestamps[0]).total_seconds()
        if time_span > 0:
            packets_per_second = len(recent_timestamps) / time_span
            if packets_per_second >= self.flood_threshold:
                alert_key = f"flood_{src_ip}"
                if self._should_alert(alert_key, timestamp):
                    return {
                        'timestamp': timestamp.isoformat(),
                        'alert_type': 'Traffic Flood',
                        'severity': 'CRITICAL',
                        'src_ip': src_ip,
                        'description': f'Potential DoS/DDoS attack from {src_ip}',
                        'details': f'Traffic rate: {packets_per_second:.2f} packets/sec (threshold: {self.flood_threshold})'
                    }
        return None
    
    def _detect_suspicious_protocol(self, packet_data: Dict) -> Optional[Dict]:
        """
        Detect usage of suspicious or uncommon protocols
        """
        protocol = packet_data.get('protocol', '').upper()
        src_ip = packet_data.get('src_ip')
        dst_port = packet_data.get('dst_port')
        suspicious_ports = {
            23: 'Telnet (unencrypted)',
            445: 'SMB (ransomware vector)',
            3389: 'RDP (remote desktop)'
        }
        if dst_port in suspicious_ports:
            alert_key = f"suspicious_port_{src_ip}_{dst_port}"
            timestamp = datetime.fromisoformat(packet_data.get('timestamp', datetime.now().isoformat()))
            if self._should_alert(alert_key, timestamp):
                return {
                    'timestamp': timestamp.isoformat(),
                    'alert_type': 'Suspicious Protocol',
                    'severity': 'MEDIUM',
                    'src_ip': src_ip,
                    'description': f'Connection to suspicious port {dst_port}',
                    'details': f'{suspicious_ports[dst_port]} - Port {dst_port} from {src_ip}'
                }
        return None
    
    def _detect_unusual_packet_size(self, packet_data: Dict) -> Optional[Dict]:
        """
        Detect unusually large or small packets (potential exfiltration or fragmentation attacks)
        """
        length = packet_data.get('length', 0)
        src_ip = packet_data.get('src_ip')
        
        # Very large packets might indicate data exfiltration
        if length > 60000:  # Approaching maximum MTU
            alert_key = f"large_packet_{src_ip}"
            timestamp = datetime.fromisoformat(packet_data.get('timestamp', datetime.now().isoformat()))
            if self._should_alert(alert_key, timestamp):
                return {
                    'timestamp': timestamp.isoformat(),
                    'alert_type': 'Unusual Packet Size',
                    'severity': 'LOW',
                    'src_ip': src_ip,
                    'description': 'Unusually large packet detected',
                    'details': f'Packet size: {length} bytes from {src_ip}'
                }
        return None
    
    def _should_alert(self, alert_key: str, timestamp: datetime) -> bool:
        """
        Check if enough time has passed since last alert of this type
        
        Args:
            alert_key: Unique identifier for alert type
            timestamp: Current timestamp
            
        Returns:
            True if should alert, False if in cooldown period
        """
        last_alert = self.recent_alerts[alert_key]
        if timestamp - last_alert >= self.alert_cooldown:
            self.recent_alerts[alert_key] = timestamp
            return True
        return False

    def get_statistics(self) -> Dict:
        """
        Get current anomaly detection statistics
        
        Returns:
            Dictionary containing current tracking statistics
        """
        return {
            'monitored_ips': len(self.ip_port_map),
            'total_unique_ports_scanned': sum(len(ports) for ports in self.ip_port_map.values()),
            'protocol_distribution': dict(self.protocol_counts),
            'active_connections': len(self.ip_timestamps)
        }

    def reset(self):
        """Reset all tracking data"""
        self.ip_port_map.clear()
        self.ip_timestamps.clear()
        self.protocol_counts.clear()
        self.recent_alerts.clear()
        print(" Anomaly detector reset")

# Example usage and testing
if __name__ == "__main__":
    detector = AnomalyDetector(port_scan_threshold=5, flood_threshold=50, time_window=30)
    
    # Simulate port scan
    print("\n🧪 Testing Port Scan Detection:")
    for port in range(80, 90):
        test_packet = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'dst_port': port,
            'protocol': 'TCP',
            'length': 60
        }
        alerts = detector.analyze_packet(test_packet)
        if alerts:
            print(f"  Alert: {alerts[0]['description']}")
    
    # Simulate flood
    print("\n Testing Flood Detection:")
    import time
    for i in range(60):
        test_packet = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.200',
            'dst_ip': '10.0.0.1',
            'dst_port': 80,
            'protocol': 'TCP',
            'length': 1500
        }
        alerts = detector.analyze_packet(test_packet)
        if alerts:
            print(f"  Alert: {alerts[0]['description']}")
            break
        time.sleep(0.01)  # simulate real traffic
    
    print("\n Detector Statistics:")
    stats = detector.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
