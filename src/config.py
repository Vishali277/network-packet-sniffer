"""
Configuration file for Network Packet Sniffer
Stores all configurable parameters
"""

# Network Configuration
NETWORK_INTERFACE = None  # None = auto-detect, or specify like 'eth0', 'wlan0', 'Ethernet'
PACKET_COUNT = 0          # 0 = unlimited, or set a number

# Anomaly Detection Thresholds
PORT_SCAN_THRESHOLD = 10  # Number of unique ports from same IP in time window
FLOOD_THRESHOLD = 100     # Packets per second from same source
TIME_WINDOW = 60          # Time window in seconds for anomaly detection

# Database Configuration
DB_PATH = "data/packets.db"

# Logging Configuration
LOG_FILE = "logs/alerts.log"
LOG_LEVEL = "INFO"

# Email Alert Configuration (Optional)
EMAIL_ALERTS_ENABLED = False
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your_email@gmail.com"
SENDER_PASSWORD = "your_app_password"  # Use app-specific password
RECEIVER_EMAIL = "alert_recipient@gmail.com"

# GUI Configuration (if you add a GUI later)
GUI_UPDATE_INTERVAL = 1000  # milliseconds
GRAPH_MAX_POINTS = 100
