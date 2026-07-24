import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from database import init_db
from gmail_api import get_gmail_messages


class DatabaseInitializationTests(unittest.TestCase):
    def test_init_db_creates_scan_history_table(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "phishing.db")

            init_db(db_path)

            conn = sqlite3.connect(db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'"
                )
                self.assertIsNotNone(cursor.fetchone())
            finally:
                conn.close()


class GmailAuthTests(unittest.TestCase):
    @patch("gmail_api.load_gmail_credentials")
    def test_get_gmail_messages_wraps_authentication_errors(self, mock_load):
        mock_load.side_effect = RuntimeError("expired token")

        with self.assertRaisesRegex(RuntimeError, "Gmail authentication expired"):
            get_gmail_messages()


if __name__ == "__main__":
    unittest.main()
