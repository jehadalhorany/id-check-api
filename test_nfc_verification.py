"""Crypto vectors, failure paths, response parity, and concurrent replay checks.
All keys below are public documentation/test keys, not the project's POC secret.
"""
import concurrent.futures
import hashlib
import io
import json
import logging
import os
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

import app
import nfc_verification as nfc

TEST_KEY_HEX = '00112233445566778899AABBCCDDEEFF'
TEST_KEY = bytes.fromhex(TEST_KEY_HEX)
UID = bytes.fromhex('04DE5F1EACC040')


def sample_scan(counter=1, uid=UID, picc_uid=None, text='test-id', header=0xC7, template=''):
    key1, key2 = nfc.derive_tag_keys(TEST_KEY, uid)
    actual_uid = uid if picc_uid is None else picc_uid
    ctr = counter.to_bytes(3, 'little')
    plain = bytes([header]) + actual_uid + ctr + bytes(5)
    encrypted = nfc._aes_cbc(key2, plain).hex().upper()
    payload = {'id': text, 'uid': uid.hex().upper(), 'e': encrypted}
    session = nfc.session_mac_key(key1, actual_uid, ctr)
    payload['c'] = nfc.truncated_sdm_cmac(session, template.format_map(payload).encode('ascii')).hex().upper()
    return payload


class CryptoVectors(unittest.TestCase):
    def test_an10922_published_vector(self):
        m = bytes.fromhex('04782E21801D803042F54E585020416275')
        self.assertEqual(nfc.an10922_aes128(TEST_KEY, m).hex().upper(), 'A8DD63A3B89D54B37CA802473FDA9175')

    def test_nist_empty_cmac(self):
        self.assertEqual(nfc.aes_cmac(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'), b'').hex(), 'bb1d6929e95937287fa37d129b756746')

    def test_an12196_picc_session_and_empty_cmac_vectors(self):
        uid, counter = nfc.decrypt_picc(bytes(16), bytes.fromhex('EF963FF7828658A599F3041510671E88'))
        self.assertEqual(uid, UID)
        self.assertEqual(counter, bytes.fromhex('3D0000'))
        key = nfc.session_mac_key(bytes(16), uid, counter)
        self.assertEqual(key.hex().upper(), '3FB5F6E3A807A03D5E3570ACE393776F')
        self.assertEqual(nfc.truncated_sdm_cmac(key, b'').hex().upper(), '94EED9EE65337086')

    def test_an12196_nonempty_mac_vector(self):
        key = nfc.session_mac_key(bytes(16), bytes.fromhex('04958CAA5C5E80'), bytes.fromhex('080000'))
        self.assertEqual(key.hex().upper(), '3ED0920E5E6A0320D823D5987FEAFBB1')
        data = b'CEE9A53E3E463EF1F459635736738962&cmac='
        self.assertEqual(nfc.truncated_sdm_cmac(key, data).hex().upper(), 'ECC1E7F6C6C73BF6')

    def test_short_diversification_is_two_blocks_with_role_suffix(self):
        key1, key2 = nfc.derive_tag_keys(TEST_KEY, UID)
        self.assertEqual(key1, nfc.an10922_aes128(TEST_KEY, UID + b'\x01'))
        self.assertNotEqual(key1, nfc.aes_cmac(TEST_KEY, b'\x01' + UID + b'\x01'))
        self.assertNotEqual(key1, key2)
        self.assertNotEqual(key1, nfc.an10922_aes128(TEST_KEY, b'\x01' + UID))

    def test_counter_is_little_endian(self):
        result = nfc.verify_scan(sample_scan(0x010203), nfc.VerificationConfig(TEST_KEY, ''))
        self.assertEqual(result.counter, 0x010203)
        self.assertEqual(result.uid, UID.hex().upper())

    def test_uid_mismatch_and_bad_picc_flags(self):
        for payload in [sample_scan(picc_uid=bytes.fromhex('04000000000001')), sample_scan(header=0x87)]:
            with self.assertRaises(nfc.VerificationError):
                nfc.verify_scan(payload, nfc.VerificationConfig(TEST_KEY, ''))

    def test_no_mac_profile_guessing_or_case_normalization(self):
        data = sample_scan(template='{e}&c=')
        nfc.verify_scan(data, nfc.VerificationConfig(TEST_KEY, '{e}&c='))
        with self.assertRaises(nfc.VerificationError):
            nfc.verify_scan(data, nfc.VerificationConfig(TEST_KEY, ''))
        with self.assertRaises(nfc.VerificationError):
            nfc.verify_scan(dict(data, e=data['e'].lower()), nfc.VerificationConfig(TEST_KEY, '{e}&c='))

    def test_config_requires_explicit_mac_input_and_valid_secret(self):
        env = {'NFC_MASTER_KEY_HEX': TEST_KEY_HEX, 'NFC_SDM_MAC_INPUT_JSON': '""'}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(nfc.load_config().mac_input_template, '')
            self.assertNotIn(TEST_KEY_HEX.lower(), repr(nfc.load_config()).lower())
        for changes in [{'NFC_MASTER_KEY_HEX':''}, {'NFC_MASTER_KEY_HEX':'x'*32}, {'NFC_SDM_MAC_INPUT_JSON':''}, {'NFC_SDM_MAC_INPUT_JSON':'null'}, {'NFC_SDM_MAC_INPUT_JSON':'"{c}"'}, {'NFC_SDM_MAC_INPUT_JSON':'"{e.__class__}"'}]:
            with patch.dict(os.environ, dict(env, **changes), clear=True), self.assertRaises(nfc.VerificationError):
                nfc.load_config()
        with patch.dict(os.environ, {'NFC_MASTER_KEY_HEX':TEST_KEY_HEX}, clear=True), self.assertRaises(nfc.VerificationError):
            nfc.load_config()


class EndpointGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.enterContext(patch.object(app, 'DATABASE_URL', ''))
        self.enterContext(patch.object(app, 'SQLITE_PATH', self.tmp.name+'/test.db'))
        self.enterContext(patch.dict(os.environ, {'NFC_MASTER_KEY_HEX': TEST_KEY_HEX, 'NFC_SDM_MAC_INPUT_JSON':'""'}))
        app.init_db()
        with app.database() as conn:
            self.item = app.save_record(conn, 'abo_liath', {'id':'test-id','name':'Product','text':'Existing product text','description':'Original description','active':True})

    def request(self, payload):
        body = json.dumps(payload).encode()
        env = {'PATH_INFO':'/api/check','REQUEST_METHOD':'POST','CONTENT_LENGTH':str(len(body)), 'CONTENT_TYPE':'application/json','HTTP_HOST':'original.example','wsgi.url_scheme':'https', 'wsgi.input':io.BytesIO(body)}
        response = []
        result = b''.join(app.application(env, lambda status, headers: response.append((status, headers))))
        return int(response[0][0].split()[0]), result, response[0][1]

    def last(self, uid=UID):
        return app.query('SELECT last_counter FROM nfc_sdm_counters WHERE tag_uid = ?', (uid.hex().upper(),), True)

    def test_original_response_bytes_and_headers_preserved(self):
        image_id, video_id = '1'*32, '2'*32
        with app.database() as conn:
            app.execute(conn, 'INSERT INTO media (id, kind, content_type, payload, created_at) VALUES (?, ?, ?, ?, ?)', (image_id,'image','image/png',b'original image',0))
            app.execute(conn, 'INSERT INTO media (id, kind, content_type, payload, created_at) VALUES (?, ?, ?, ?, ?)', (video_id,'video','video/mp4',b'original video',0))
            app.execute(conn, 'UPDATE record_assets SET image_id = ?, video_id = ? WHERE record_id = ?', (image_id,video_id,'test-id'))
        scan = sample_scan()
        with patch.object(nfc, 'verify_and_accept'):
            baseline = self.request({'id':'test-id'})
        verified = self.request(scan)
        self.assertEqual(verified, baseline)
        self.assertEqual(self.last(), (1,))
        product = json.loads(verified[1])
        self.assertEqual(product['text'], 'Existing product text')
        self.assertTrue(product['image_url'].endswith('/media/'+image_id))
        self.assertTrue(product['video_url'].endswith('/media/'+video_id))

    def test_missing_proof_is_not_a_bypass(self):
        code, _, _ = self.request({'id':'test-id'})
        self.assertEqual(code, 400)
        self.assertIsNone(self.last())

    def test_invalid_proof_does_not_query_product_or_store_counter(self):
        good = sample_scan()
        bad_scans = [dict(good,c='00'*8), dict(good,e='00'*16), dict(good,uid='04'+'00'*6), sample_scan(picc_uid=bytes.fromhex('04000000000001')), sample_scan(header=0x00)]
        for bad in bad_scans:
            with patch.object(app, 'enrich_record') as lookup:
                self.assertEqual(self.request(bad)[0],403)
                lookup.assert_not_called()
            self.assertIsNone(self.last())
        self.assertEqual(self.request(good)[0],200)

    def test_malformed_scan_rejected_without_advancing(self):
        for key in ('uid','e','c'):
            for value in (None, 1, '', 'GG', '00'*128):
                payload=dict(sample_scan(), **{key:value})
                self.assertEqual(self.request(payload)[0],400)
        self.assertIsNone(self.last())

    def test_replay_lower_counter_and_independent_tags(self):
        self.assertEqual(self.request(sample_scan(8))[0],200)
        self.assertEqual(self.request(sample_scan(8))[0],409)
        self.assertEqual(self.request(sample_scan(7))[0],409)
        self.assertEqual(self.request(sample_scan(9))[0],200)
        self.assertEqual(self.last(),(9,))
        other = bytes.fromhex('04C767F2066180')
        self.assertEqual(self.request(sample_scan(1,uid=other))[0],200)
        self.assertEqual(self.last(other),(1,))

    def test_bad_high_counter_cannot_poison_replay_state(self):
        self.request(sample_scan(10))
        bad = dict(sample_scan(0xFFFFFF),c='00'*8)
        self.assertEqual(self.request(bad)[0],403)
        self.assertEqual(self.last(),(10,))
        self.assertEqual(self.request(sample_scan(11))[0],200)

    def test_max_counter_no_wraparound_reset(self):
        self.assertEqual(self.request(sample_scan(0xFFFFFF))[0],200)
        self.assertEqual(self.request(sample_scan(0))[0],409)

    def test_original_missing_and_inactive_responses_preserved(self):
        payload = sample_scan(1,text='missing')
        with patch.object(nfc,'verify_and_accept'):
            baseline=self.request({'id':'missing'})
        self.assertEqual(self.request(payload), baseline)
        with app.database() as conn:
            app.save_record(conn,'abo_liath',dict(self.item,active=False),update=True)
        with patch.object(nfc,'verify_and_accept'):
            baseline=self.request({'id':'test-id'})
        self.assertEqual(self.request(sample_scan(2)),baseline)

    def test_config_errors_fail_closed_before_product_lookup(self):
        with patch.dict(os.environ,{'NFC_MASTER_KEY_HEX':''}), patch.object(app,'enrich_record') as lookup:
            self.assertEqual(self.request(sample_scan())[0],503)
            lookup.assert_not_called()
        self.assertIsNone(self.last())

    def test_counter_persisted_across_schema_init(self):
        self.request(sample_scan(4))
        app.init_db()
        self.assertEqual(self.request(sample_scan(4))[0],409)
        self.assertEqual(self.request(sample_scan(5))[0],200)

    def test_counter_commits_before_existing_lookup(self):
        with patch.object(app,'enrich_record',side_effect=RuntimeError('test product lookup unavailable')):
            with self.assertLogs(level=logging.ERROR):
                self.assertEqual(self.request(sample_scan(2))[0],503)
        self.assertEqual(self.last(),(2,))
        self.assertEqual(self.request(sample_scan(2))[0],409)

    def test_parallel_duplicate_requests_only_one_succeeds(self):
        barrier=threading.Barrier(12)
        def call(_):
            barrier.wait()
            return self.request(sample_scan(42))[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            results=list(executor.map(call,range(12)))
        self.assertEqual(results.count(200),1,results)
        self.assertEqual(results.count(409),11,results)
        self.assertEqual(self.last(),(42,))

    def test_database_only_contains_uid_counter_timestamp(self):
        self.request(sample_scan(1))
        with app.database() as conn:
            columns=conn.execute('PRAGMA table_info(nfc_sdm_counters)').fetchall()
            dump='\n'.join(conn.iterdump())
        self.assertEqual([r[1] for r in columns],['tag_uid','last_counter','accepted_at'])
        self.assertNotIn(TEST_KEY_HEX.lower(),dump.lower())
        for key in nfc.derive_tag_keys(TEST_KEY,UID):
            self.assertNotIn(key.hex(),dump.lower())


if __name__=='__main__':
    unittest.main()
