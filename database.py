import os
import sqlite3


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "phishing.db")


def init_db(db_path=None):
    db_path = db_path or DEFAULT_DB_PATH

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            prediction TEXT,
            confidence REAL,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.commit()
    conn.close()

    return db_path


if __name__ == "__main__":
    init_db()
    print("Database Ready ✅")