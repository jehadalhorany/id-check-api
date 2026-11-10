"""Optional isolated PostgreSQL concurrency test. Uses a disposable schema only.

Set NFC_TEST_DATABASE_URL to a dedicated test database to run this test.
No existing schemas, products, counters, or application configuration are changed.
"""
import concurrent.futures
import os
import secrets
import threading
import unittest

import nfc_verification as nfc


@unittest.skipUnless(os.environ.get('NFC_TEST_DATABASE_URL'), 'Dedicated PostgreSQL test URL not configured')
class PostgreSQLReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        cls.psycopg, cls.sql = psycopg, sql
        cls.schema = 'nfc_test_' + secrets.token_hex(8)
        with psycopg.connect(os.environ['NFC_TEST_DATABASE_URL']) as conn:
            conn.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(cls.schema)))
            conn.execute(sql.SQL('SET LOCAL search_path TO {}').format(sql.Identifier(cls.schema)))
            nfc.init_counter_schema(conn, cls.execute)

    @classmethod
    def tearDownClass(cls):
        with cls.psycopg.connect(os.environ['NFC_TEST_DATABASE_URL']) as conn:
            conn.execute(cls.sql.SQL('DROP SCHEMA {} CASCADE').format(cls.sql.Identifier(cls.schema)))

    @staticmethod
    def execute(conn, statement, values=()):
        return conn.execute(statement.replace('?', '%s'), values)

    def test_concurrent_duplicate_and_lower_counter(self):
        barrier = threading.Barrier(12)
        uid = '04DE5F1EACC040'
        def attempt(counter, simultaneous=False):
            if simultaneous:
                barrier.wait()
            try:
                with self.psycopg.connect(os.environ['NFC_TEST_DATABASE_URL']) as conn:
                    conn.execute(self.sql.SQL('SET LOCAL search_path TO {}').format(self.sql.Identifier(self.schema)))
                    nfc.accept_counter(conn, self.execute, nfc.VerifiedScan(uid, counter))
                return 'accepted'
            except nfc.VerificationError:
                return 'rejected'
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(lambda _: attempt(42, True), range(12)))
        self.assertEqual(results.count('accepted'), 1, results)
        self.assertEqual(results.count('rejected'), 11, results)
        self.assertEqual(attempt(42), 'rejected')
        self.assertEqual(attempt(41), 'rejected')
        self.assertEqual(attempt(43), 'accepted')
