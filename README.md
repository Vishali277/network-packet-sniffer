# Network Packet Sniffer with Alert System

## Overview
This project implements a network packet sniffer tool with an integrated alert system. It captures live network packets, parses essential packet information, stores data in a database, and generates alerts upon detecting suspicious network activities, helping in real-time network monitoring and security awareness.

## Features
- Captures and displays live network traffic information.
- Parses key packet details including protocol, source/destination IP and ports, flags, and payload size.
- Logs packet data and alerts into a SQLite database.
- Detects suspicious activities like port scans and flooding, generating alerts.
- Configurable via command-line interface for packet count, filters, and interface selection.
- Optional email alert functionality.

## Demonstration Results
- Successfully captured packets with detailed metadata.
- Alerts generated during the detection of potential network threats.
- Clear command-line outputs showing live capture and alert messages.
- Automatic stopping after a specified packet count.
- Reliable storage of packet data and alert logs in a local database.

## Key Concepts & Learnings
- Packet sniffing using Scapy in Python.
- Parsing and handling multiple network protocols (TCP, UDP, ICMP, ARP).
- Real-time anomaly detection and alert generation.
- Database integration with SQLite for efficient data storage.
- Command-line interface design for usability.
- Fundamentals of network security monitoring.

## Files in This Repository
- `src/cli.py` – Command-line interface to run the sniffer.
- `src/packet_sniffer.py` – Core packet capture and parsing logic.
- `src/database.py` – Database schema and operations for packets and alerts.
- `src/anomaly_detector.py` – Logic for detecting suspicious network behavior.
- `src/alert_system.py` – Alert logging and notification mechanisms.
- `data/packets.db` – SQLite database file storing captured data.
- `logs/alerts.log` – File logging alerts generated during sniffing.
- `requirements.txt` – List of required Python packages.

## Future Enhancements
- Extend anomaly detection rules for advanced threats.
- Develop a graphical user interface (GUI).
- Integrate real-time visualization dashboards.
- Implement richer alert notification options (SMS, webhook).
- Support for additional network protocols and data export formats.

---
