"""
Alert System for Network Packet Sniffer
Handles alert notifications via email and logging
"""

import smtplib
import logging
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Optional

class AlertSystem:
    """
    Manages alert notifications through multiple channels
    """
    
    def __init__(self, 
                 log_file: str = "logs/alerts.log",
                 email_enabled: bool = False,
                 smtp_config: Optional[Dict] = None):
        """
        Initialize alert system
        
        Args:
            log_file: Path to log file for alerts
            email_enabled: Enable email notifications
            smtp_config: SMTP configuration dictionary
        """
        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Setup logging
        self.log_file = log_file
        self.logger = self._setup_logger()
        
        # Email configuration
        self.email_enabled = email_enabled
        self.smtp_config = smtp_config or {}
        
        if self.email_enabled:
            self._validate_smtp_config()
        
        print(f" Alert System initialized")
        print(f"   Log file: {log_file}")
        print(f"   Email alerts: {'Enabled' if email_enabled else 'Disabled'}")
    
    def _setup_logger(self) -> logging.Logger:
        """
        Configure logging for alerts
        
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger('PacketSnifferAlerts')
        logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        logger.handlers.clear()
        
        # File handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _validate_smtp_config(self):
        """Validate SMTP configuration"""
        required_keys = ['smtp_server', 'smtp_port', 'sender_email', 'sender_password', 'receiver_email']
        
        for key in required_keys:
            if key not in self.smtp_config:
                raise ValueError(f"Missing SMTP configuration: {key}")
        
        print(f"   SMTP Server: {self.smtp_config['smtp_server']}:{self.smtp_config['smtp_port']}")
    
    def send_alert(self, alert_data: Dict):
        """
        Send alert through all configured channels
        
        Args:
            alert_data: Dictionary containing alert information
        """
        # Log alert
        self._log_alert(alert_data)
        
        # Send email if enabled
        if self.email_enabled:
            self._send_email_alert(alert_data)
    
    def _log_alert(self, alert_data: Dict):
        """
        Log alert to file and console
        
        Args:
            alert_data: Alert information dictionary
        """
        severity = alert_data.get('severity', 'INFO')
        alert_type = alert_data.get('alert_type', 'Unknown')
        description = alert_data.get('description', 'No description')
        src_ip = alert_data.get('src_ip', 'Unknown')
        details = alert_data.get('details', '')
        
        # Format log message
        log_message = (
            f"[{alert_type}] {description} | "
            f"Source: {src_ip} | "
            f"Details: {details}"
        )
        
        # Log based on severity
        if severity == 'CRITICAL':
            self.logger.critical(log_message)
            print(f" CRITICAL: {log_message}")
        elif severity == 'HIGH':
            self.logger.error(log_message)
            print(f"  HIGH: {log_message}")
        elif severity == 'MEDIUM':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def _send_email_alert(self, alert_data: Dict):
        """
        Send email notification for alert
        
        Args:
            alert_data: Alert information dictionary
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config['sender_email']
            msg['To'] = self.smtp_config['receiver_email']
            msg['Subject'] = f" Network Alert: {alert_data.get('alert_type', 'Unknown')}"
            
            # Create email body
            body = self._format_email_body(alert_data)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_config['smtp_server'], self.smtp_config['smtp_port']) as server:
                server.starttls()
                server.login(
                    self.smtp_config['sender_email'],
                    self.smtp_config['sender_password']
                )
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent for {alert_data.get('alert_type')}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    def _format_email_body(self, alert_data: Dict) -> str:
        """
        Format alert data into HTML email body
        
        Args:
            alert_data: Alert information dictionary
            
        Returns:
            HTML formatted email body
        """
        severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#17a2b8',
            'INFO': '#6c757d'
        }
        
        severity = alert_data.get('severity', 'INFO')
        color = severity_colors.get(severity, '#6c757d')
        
        html = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .header {{ background-color: {color}; color: white; padding: 20px; }}
                    .content {{ padding: 20px; }}
                    .detail {{ margin: 10px 0; }}
                    .label {{ font-weight: bold; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h2> Network Security Alert</h2>
                    <h3>{alert_data.get('alert_type', 'Unknown Alert')}</h3>
                </div>
                <div class="content">
                    <div class="detail">
                        <span class="label">Severity:</span> 
                        <span style="color: {color}; font-weight: bold;">{severity}</span>
                    </div>
                    <div class="detail">
                        <span class="label">Timestamp:</span> 
                        {alert_data.get('timestamp', datetime.now().isoformat())}
                    </div>
                    <div class="detail">
                        <span class="label">Source IP:</span> 
                        {alert_data.get('src_ip', 'Unknown')}
                    </div>
                    <div class="detail">
                        <span class="label">Description:</span> 
                        {alert_data.get('description', 'No description')}
                    </div>
                    <div class="detail">
                        <span class="label">Details:</span> 
                        <pre>{alert_data.get('details', 'No additional details')}</pre>
                    </div>
                    <hr>
                    <p style="color: #6c757d; font-size: 12px;">
                        This is an automated alert from your Network Packet Sniffer system.
                        <br>Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    </p>
                </div>
            </body>
        </html>
        """
        
        return html
    
    def get_recent_logs(self, lines: int = 50) -> list:
        """
        Retrieve recent log entries
        
        Args:
            lines: Number of recent lines to retrieve
            
        Returns:
            List of recent log lines
        """
        try:
            with open(self.log_file, 'r') as f:
                return f.readlines()[-lines:]
        except FileNotFoundError:
            return []
    
    def clear_logs(self):
        """Clear alert logs"""
        try:
            with open(self.log_file, 'w') as f:
                f.write(f"# Alert log cleared at {datetime.now().isoformat()}\n")
            self.logger.info("Alert logs cleared")
            print(" Alert logs cleared")
        except Exception as e:
            print(f" Error clearing logs: {e}")


# Example usage and testing
if __name__ == "__main__":
    # Initialize alert system (without email for testing)
    alert_system = AlertSystem(
        log_file="logs/test_alerts.log",
        email_enabled=False
    )
    
    # Test different severity alerts
    test_alerts = [
        {
            'timestamp': datetime.now().isoformat(),
            'alert_type': 'Port Scan',
            'severity': 'HIGH',
            'src_ip': '192.168.1.100',
            'description': 'Potential port scan detected',
            'details': 'Scanned 15 ports in 30 seconds'
        },
        {
            'timestamp': datetime.now().isoformat(),
            'alert_type': 'Traffic Flood',
            'severity': 'CRITICAL',
            'src_ip': '10.0.0.50',
            'description': 'Potential DoS attack',
            'details': 'Traffic rate: 250 packets/sec'
        },
        {
            'timestamp': datetime.now().isoformat(),
            'alert_type': 'Suspicious Protocol',
            'severity': 'MEDIUM',
            'src_ip': '172.16.0.20',
            'description': 'Connection to suspicious port',
            'details': 'Telnet connection detected on port 23'
        }
    ]
    
    print("\n Testing Alert System:")
    for alert in test_alerts:
        alert_system.send_alert(alert)
    
    print("\n Recent Logs:")
    recent_logs = alert_system.get_recent_logs(10)
    for log in recent_logs:
        print(log.strip())
