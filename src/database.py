import sqlite3
from datetime import datetime
from typing import Dict

class PacketDatabase:
    def __init__(self, db_path='data/packets.db'):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                length INTEGER NOT NULL,
                flags TEXT,
                info TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT,
                severity TEXT,
                src_ip TEXT,
                description TEXT,
                details TEXT
            )
        ''')
        self.conn.commit()

    def insert_packet(self, packet_data: Dict) -> int:
        self.cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_data.get('timestamp', datetime.now().isoformat()),
            packet_data.get('src_ip', '0.0.0.0'),
            packet_data.get('dst_ip', '0.0.0.0'),
            packet_data.get('src_port'),
            packet_data.get('dst_port'),
            packet_data.get('protocol', 'Unknown'),
            packet_data.get('length', 0),
            packet_data.get('flags', ''),
            packet_data.get('info', '')
        ))
        self.conn.commit()
        return self.cursor.lastrowid

    def insert_alert(self, alert_data: Dict) -> int:
        try:
            self.cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, severity, src_ip, description, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                alert_data.get('timestamp', datetime.now().isoformat()),
                alert_data.get('alert_type', 'Unknown'),
                alert_data.get('severity', 'INFO'),
                alert_data.get('src_ip', ''),
                alert_data.get('description', ''),
                alert_data.get('details', '')
            ))
            self.conn.commit()
            return self.cursor.lastrowid
        except Exception as e:
            print(f"Error inserting alert: {e}")
            return -1

    def get_statistics(self) -> Dict[str, int]:
        self.cursor.execute('SELECT COUNT(*) FROM packets')
        total_packets = self.cursor.fetchone()[0]
        # Additional statistics can be added here
        return {'total_packets': total_packets}

    def close(self):
        try:
            if self.conn:
                self.conn.close()
                print("Database connection closed.")
        except Exception as e:
            print(f"Error closing database connection: {e}")
