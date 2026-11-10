"""NTAG 424 DNA AES-SDM gate. No secrets are persisted or returned.

References: NXP AN10922 section 2.2, AN12196 sections 3.3 and 3.4.
The MAC input must be explicitly configured to match tag personalization.
"""
import hmac
import json
import os
import re
import string
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class VerificationError(Exception):
    """Expected, public-safe rejection; never includes input values or keys."""
    def __init__(self, status, message):
        self.status = status
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class VerificationConfig:
    # Exclude secret material from repr and any incidental diagnostic output.
    master_key: bytes = field(repr=False)
    mac_input_template: str


@dataclass(frozen=True)
class VerifiedScan:
    uid: str
    counter: int


def _hex(value, length):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{%d}' % (length * 2), value):
        raise VerificationError(400, 'Invalid NFC scan fields')
    return bytes.fromhex(value)


def load_config():
    """Load the master only from process environment; no default or DB access."""
    raw_key = os.environ.get('NFC_MASTER_KEY_HEX')
    if not isinstance(raw_key, str) or not re.fullmatch(r'[0-9a-fA-F]{32}', raw_key):
        raise VerificationError(503, 'NFC verification is not configured')
    # JSON permits an explicit empty string (""), distinct from a missing setting.
    encoded = os.environ.get('NFC_SDM_MAC_INPUT_JSON')
    try:
        template = json.loads(encoded) if encoded is not None else None
    except (ValueError, TypeError):
        template = None
    if not isinstance(template, str) or len(template) > 2048:
        raise VerificationError(503, 'NFC verification is not configured')
    try:
        template.encode('ascii')
        for _, name, spec, conversion in string.Formatter().parse(template):
            if name is not None and (name not in ('e', 'uid', 'id') or spec or conversion):
                raise ValueError()
    except (ValueError, UnicodeError):
        raise VerificationError(503, 'NFC verification is not configured') from None
    return VerificationConfig(bytes.fromhex(raw_key), template)


def aes_cmac(key, message):
    mac = cmac.CMAC(algorithms.AES(key))
    mac.update(message)
    return mac.finalize()


def _aes_cbc(key, data, decrypt=False):
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16)))
    operation = cipher.decryptor() if decrypt else cipher.encryptor()
    return operation.update(data) + operation.finalize()


def _double(block):
    number = int.from_bytes(block, 'big')
    return (((number << 1) & ((1 << 128) - 1)) ^ (0x87 if number >> 127 else 0)).to_bytes(16, 'big')


def an10922_aes128(master_key, diversification_input):
    """NXP's two-block CMAC diversification, including its pre-padding flag.

    This is NOT ordinary CMAC(0x01 || M) for short M such as UID || key-number.
    AN10922 externally pads to 32 bytes and selects CMAC subkey K2 when padded.
    """
    if len(master_key) != 16 or not 1 <= len(diversification_input) <= 31:
        raise ValueError('Invalid AN10922 input lengths')
    data = b'\x01' + diversification_input
    padded = len(data) < 32
    if padded:
        data += b'\x80' + bytes(31 - len(data))
    first_subkey = _double(_aes_cbc(master_key, bytes(16)))
    last_subkey = _double(first_subkey) if padded else first_subkey
    last_block = bytes(a ^ b for a, b in zip(data[16:], last_subkey))
    return _aes_cbc(master_key, data[:16] + last_block)[-16:]


def derive_tag_keys(master_key, uid):
    if len(uid) != 7:
        raise ValueError('A seven-byte UID is required')
    # The role byte is a suffix, as specified by this project's personalizer.
    return (an10922_aes128(master_key, uid + b'\x01'),
            an10922_aes128(master_key, uid + b'\x02'))


def decrypt_picc(meta_read_key, encrypted_picc):
    """AES-128-CBC with zero IV; PICC random padding is not PKCS#7 padding."""
    if len(meta_read_key) != 16 or len(encrypted_picc) != 16:
        raise VerificationError(403, 'NFC verification failed')
    try:
        plain = _aes_cbc(meta_read_key, encrypted_picc, decrypt=True)
    except ValueError:
        raise VerificationError(403, 'NFC verification failed') from None
    # C7: UID + counter mirrored, 7-byte UID; this POC supports AES mode only.
    if plain[0] != 0xC7:
        raise VerificationError(403, 'NFC verification failed')
    uid, counter_bytes = plain[1:8], plain[8:11]
    return uid, counter_bytes


def session_mac_key(file_read_key, uid, counter_bytes):
    if len(uid) != 7 or len(counter_bytes) != 3:
        raise ValueError('Invalid SDM session vector lengths')
    # Keep the exact three little-endian counter bytes from decrypted PICC data.
    sv2 = bytes.fromhex('3CC300010080') + uid + counter_bytes
    return aes_cmac(file_read_key, sv2)


def truncated_sdm_cmac(key, message):
    # NXP zero-based byte indices 1,3,...,15, not the first eight bytes.
    return aes_cmac(key, message)[1::2]


def verify_scan(payload, config):
    """Cryptographic verification only; no DB writes, lookup, logging or responses."""
    if not isinstance(payload, dict):
        raise VerificationError(400, 'Invalid NFC scan fields')
    physical_uid = _hex(payload.get('uid'), 7)
    encrypted_picc = _hex(payload.get('e'), 16)
    received_mac = _hex(payload.get('c'), 8)
    file_read_key, meta_read_key = derive_tag_keys(config.master_key, physical_uid)
    picc_uid, counter_bytes = decrypt_picc(meta_read_key, encrypted_picc)
    if not hmac.compare_digest(picc_uid, physical_uid):
        raise VerificationError(403, 'NFC verification failed')
    values = {'uid': payload['uid'], 'e': payload['e'], 'id': payload.get('id', '')}
    if not isinstance(values['id'], str) or len(values['id']) > 64:
        raise VerificationError(400, 'Invalid NFC scan fields')
    try:
        # Preserve mirrored ASCII case and delimiters. Do not decode/re-encode e.
        mac_input = config.mac_input_template.format_map(values).encode('ascii')
    except (KeyError, ValueError, UnicodeError):
        raise VerificationError(400, 'Invalid NFC scan fields') from None
    expected = truncated_sdm_cmac(session_mac_key(file_read_key, picc_uid, counter_bytes), mac_input)
    if not hmac.compare_digest(received_mac, expected):
        raise VerificationError(403, 'NFC verification failed')
    return VerifiedScan(picc_uid.hex().upper(), int.from_bytes(counter_bytes, 'little'))


def init_counter_schema(conn, execute):
    execute(conn, '''CREATE TABLE IF NOT EXISTS nfc_sdm_counters (
        tag_uid VARCHAR(14) PRIMARY KEY,
        last_counter INTEGER NOT NULL CHECK (last_counter BETWEEN 0 AND 16777215),
        accepted_at BIGINT NOT NULL
    )''')


def accept_counter(conn, execute, scan):
    """One conditional UPSERT, shared across processes/instances by the database.

    No SELECT-then-UPDATE race. PostgreSQL and SQLite serialize conflicting writes.
    A failed crypto check never gets here. Equal/lower counters change nothing.
    """
    cursor = execute(conn, '''INSERT INTO nfc_sdm_counters
        (tag_uid, last_counter, accepted_at) VALUES (?, ?, ?)
        ON CONFLICT (tag_uid) DO UPDATE SET
            last_counter = excluded.last_counter,
            accepted_at = excluded.accepted_at
        WHERE nfc_sdm_counters.last_counter < excluded.last_counter''',
        (scan.uid, scan.counter, int(time.time())))
    if cursor.rowcount != 1:
        raise VerificationError(409, 'NFC scan has already been used or is out of order')


def verify_and_accept(payload, database, execute):
    # Config errors and failures do not produce any product query or counter write.
    scan = verify_scan(payload, load_config())
    with database() as conn:
        accept_counter(conn, execute, scan)
    # Commit before entering the existing application flow, per the requested order.
    return scan
