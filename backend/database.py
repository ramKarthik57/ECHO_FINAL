import sqlite3
import os
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional

class DatabaseManager:
    def __init__(self, db_path: str):
        """Initialize database connection and ensure tables exist."""
        self.db_path = db_path
        self._ensure_data_dir()
        self._create_tables()

    def _ensure_data_dir(self):
        """Ensure the directory for the database file exists."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    def _get_connection(self):
        """Get a connection to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _create_tables(self):
        """Create necessary tables if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Investigators table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS investigators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    badge_number_hash TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    rank TEXT
                )
            ''')
            
            # Warrants table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS warrants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigator_id INTEGER NOT NULL,
                    case_id TEXT NOT NULL,
                    target_ip TEXT NOT NULL,
                    warrant_number TEXT NOT NULL,
                    expiry_date TEXT,
                    FOREIGN KEY (investigator_id) REFERENCES investigators (id)
                )
            ''')
            
            # Login logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigator_id INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT,
                    status TEXT,
                    FOREIGN KEY (investigator_id) REFERENCES investigators (id)
                )
            ''')
            conn.commit()

    def _hash_badge(self, badge_number: str) -> str:
        """Hash the badge number for secure storage."""
        return hashlib.sha256(badge_number.encode()).hexdigest()

    # Investigator Methods
    def add_investigator(self, badge_number: str, name: str, rank: str) -> int:
        badge_hash = self._hash_badge(badge_number)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO investigators (badge_number_hash, name, rank) VALUES (?, ?, ?)",
                (badge_hash, name, rank)
            )
            conn.commit()
            return cursor.lastrowid

    def get_investigators(self, sort_by: str = "name", order: str = "ASC") -> List[Dict]:
        valid_sort_fields = ["name", "rank", "id"]
        if sort_by not in valid_sort_fields:
            sort_by = "name"
        
        direction = "ASC" if order.upper() == "ASC" else "DESC"
        
        query = f"SELECT id, name, rank FROM investigators ORDER BY {sort_by} {direction}"
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]

    def get_investigator_by_badge(self, badge_number: str) -> Optional[Dict]:
        badge_hash = self._hash_badge(badge_number)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM investigators WHERE badge_number_hash = ?", (badge_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # Warrant Methods
    def add_warrant(self, investigator_id: int, case_id: str, target_ip: str, warrant_number: str, expiry_date: str) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO warrants (investigator_id, case_id, target_ip, warrant_number, expiry_date) VALUES (?, ?, ?, ?, ?)",
                (investigator_id, case_id, target_ip, warrant_number, expiry_date)
            )
            conn.commit()
            return cursor.lastrowid

    def get_warrants(self, sort_by: str = "expiry_date", order: str = "ASC") -> List[Dict]:
        valid_sort_fields = ["case_id", "target_ip", "warrant_number", "expiry_date"]
        if sort_by not in valid_sort_fields:
            sort_by = "expiry_date"
        
        direction = "ASC" if order.upper() == "ASC" else "DESC"
        
        query = f"""
            SELECT w.*, i.name as investigator_name 
            FROM warrants w 
            JOIN investigators i ON w.investigator_id = i.id 
            ORDER BY w.{sort_by} {direction}
        """
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]

    # Login Logic
    def log_login(self, investigator_id: int, ip_address: str, status: str = "success"):
        timestamp = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO login_logs (investigator_id, timestamp, ip_address, status) VALUES (?, ?, ?, ?)",
                (investigator_id, timestamp, ip_address, status)
            )
            conn.commit()
