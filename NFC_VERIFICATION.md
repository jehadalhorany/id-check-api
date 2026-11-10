# NFC verification update

Prepared against repository commit ff2722e17b68dd307476aa4129fecc58db9b68d2.

## Scope

The existing POST /api/check product query and returned response are unchanged.
A mandatory AES-SDM verifier runs after the existing request/ID validation and
before any product lookup. It does not create a second product flow.

Production changes are limited to

- nfc_verification.py, a separate verifier and conditional counter update.
- app.py, an import, counter-schema initialization, and the gate before lookup.
- requirements.txt, adding cryptography.
- render.yaml, declaring two environment variable names with sync: false.

No frontend, media delivery, product schema, upload logic, product response,
admin authentication, or existing record-management handler was edited.
The old standalone ID-only call now needs scan proof; there is no unsigned or
admin bypass to the public NFC endpoint. The existing browser ID-only preview
therefore needs a genuine NFC scan payload to call this protected endpoint.
Other admin functions and media URLs retain their existing behavior.

## Request

Keep the current product id and add the NFC fields to the same JSON request.

```http
POST /api/check
Content-Type: application/json
```

```json
{
  "id": "the-existing-product-id",
  "uid": "14-hex-characters",
  "e": "32-hex-characters",
  "c": "16-hex-characters"
}
```

These length descriptions are placeholders, not a working test vector.
uid is the physical seven-byte UID from the NFC API in byte order, without
colons, spaces, reversal, or an 0x prefix. e is the encrypted 16-byte PICC data.
c is the eight-byte truncated SDM CMAC, encoded as 16 hex characters.
Do not reverse counter bytes or calculate keys in the mobile application.
Keep the exact mirrored ASCII spelling/case of e when it is covered by the MAC.
No account, master key, per-tag key, or session key belongs in the app.

On successful verification, the existing response is returned byte-for-byte,
including the current available/text/image_url/video_url structure and the
current unavailable response when the existing lookup finds no active record.
No UID, counter, verification flag, or key is added to the response.

The id field still follows the existing product lookup logic. This update does
not reinterpret UID as a product id or invent a UID-to-product mapping. The scan
proof authenticates the tag and its counter. If the product id also needs to be
cryptographically bound, it must already be included in the tag's MAC-covered
personalized data (and represented by {id} in the exact input template), or an
explicit UID/product binding must be agreed separately. No such mapping was
provided, so none was added or assumed.

## Key handling on Render

NFC_MASTER_KEY_HEX is the only source of the master key. Set it to the exact
32-hex-character POC master key supplied by the owner, in the Render web-service
environment settings. The actual key value is deliberately absent from this
package, its tests, the Blueprint, and database records.

Use Render's environment editor. Do not paste the key into GitHub, a source file,
a YAML value, a test fixture, the database, the mobile app, or a command that
prints it. Set the variable before deploying the guard. This package does not
claim that a live Render variable has already been saved.

The Blueprint declares NFC_MASTER_KEY_HEX with sync: false. Existing services
still need the variable value supplied through Render's environment settings.

## Required personalization setting

Set NFC_SDM_MAC_INPUT_JSON to a JSON string containing the exact ASCII range
from SDMMACInputOffset through the byte preceding SDMMACOffset. Substitute only
the mirrored fields that occur in that range using {e}, {uid}, or {id}. Static
bytes and delimiters must match personalization exactly. This is a server
setting, not a client-selected algorithm.

Examples only; choose the one confirmed by the actual tag settings

| Actual tag MAC input | Render variable value |
| --- | --- |
| Empty range, input offset equals MAC offset | "" |
| e value followed by literal &c= | "{e}&c=" |
| Literal e=, e value, and &c= | "e={e}&c=" |
| Product id and e are both in the covered range | "id={id}&e={e}&c=" |

The double quotes are part of the Render variable value. Thus an empty MAC
input is represented by two quote characters, not an unset/blank variable.
These are example profiles, not fallback options. The verifier does not try
several layouts or accept a weaker layout when another fails.

The supplied request fields do not reveal which offset layout was used. Before
live rollout, get the exact NDEF template/file settings and a known-good scan
(uid, e, c, existing id) from the tag personalization tool. If the covered
range includes other dynamic data not supplied to this backend, that data must
be added to the agreed request/profile before enabling that tag layout.

Missing/malformed master key or MAC input configuration causes HTTP 503 for NFC
requests. It never falls back to an all-zero key or to ID-only verification.

## Cryptography

Supported POC profile is NTAG 424 DNA AES mode, seven-byte UID, UID and SDM read
counter mirrored in encrypted PICC data, eight-byte truncated CMAC. LRP mode
and different UID/PICC layouts are intentionally not guessed.

1. AN10922 AES-128 diversification input M is UID || 01 for key 1 and UID || 02
   for key 2. The AN10922 AES diversification prefix 01 is added separately.
2. AN10922 uses a two-block, 32-byte input and its explicit pre-padding/subkey
   selection. Ordinary CMAC(01 || UID || key-number) is not equivalent for this
   short input and is not used.
3. Key 2 decrypts e using AES-128-CBC and a zero IV. No PKCS#7 unpadding is used;
   the final five bytes are PICC random padding.
4. The C7 PICC header is required. UID is bytes 1..7, read counter bytes 8..10.
   The decrypted UID is compared with the physical UID in constant time.
5. Session MAC key is AES-CMAC(Key1, 3CC300010080 || UID || counter-bytes).
6. Expected SDM CMAC is AES-CMAC(session-key, configured-MAC-input), taking
   zero-based bytes 1,3,5,7,9,11,13,15. c comparison is constant-time.
7. Only after all checks pass, a single conditional database UPSERT accepts a
   counter strictly higher than the stored one. Then the existing lookup runs.

Derived keys exist only in process memory for the request. They are not logged,
returned, cached in the database, or sent to the app. No HSM/KMS is used.

## Counter persistence and concurrency

The only new table is nfc_sdm_counters, with tag_uid, last_counter, accepted_at.
UID is canonical uppercase hex. Counter is a 24-bit little-endian value decoded
to an integer. A new UID can accept any first valid counter, including zero.
Counters do not need to be consecutive, but must increase. Wraparound/reset
never clears the saved state automatically.

The UPSERT condition is last_counter < excluded.last_counter. It is not a
SELECT-then-UPDATE sequence. The UID primary key plus database write locking
prevents two simultaneous uses of the same scan from both succeeding across
Gunicorn workers or service instances sharing the same PostgreSQL database.

State commits before the existing lookup, matching the requested sequence.
Consequently, a valid proof is consumed even if the product is unavailable or
the subsequent lookup encounters an outage. A retry needs a new NFC read with
a higher counter, not the same saved URL/proof. Do not delete or reset this
table during ordinary redeploys, record deletion, or product edits.

## Rejections

| HTTP status | Meaning |
| --- | --- |
| 400 | Missing/malformed uid, e, c, or original invalid request/ID |
| 403 | PICC/decryption format, physical UID match, or CMAC failed |
| 409 | Counter equal to or below the accepted counter |
| 503 | Verification configuration or database unavailable |

Failures use the existing application's error envelope. Detailed crypto
failure reasons, expected MACs, decrypted PICC contents, and keys are never
returned. Configuration and DB failure cannot grant product access.

## Validation

Run

```bash
pip install -r requirements.txt
python3 -m unittest discover -v
```

Tests include NXP AN10922 and AN12196 published vectors, a NIST empty-CMAC
vector, UID mismatch, malformed data, MAC corruption, counter byte order,
replay/order rejection, independent tags, boundary counters, invalid-high-counter
state poisoning, configuration fail-closed behavior, persistence after init,
and 12 simultaneous duplicate requests with exactly one acceptance on SQLite.

Endpoint tests compare successful response bytes and HTTP headers against the
original business handler. Original business tests mock only the new guard to
continue isolating the existing product/media/admin behavior. Separate guard
integration tests exercise the full cryptographic gate without mocking it.
Test keys are public vectors, never the owner's POC master key.

Optional real PostgreSQL concurrency test

```bash
# Supply a dedicated test DB using your normal secure environment management.
python3 -m unittest -v test_nfc_postgres
```

It runs only when NFC_TEST_DATABASE_URL is present. It uses a random disposable
schema and removes only that schema. It is not intended for production. This
runtime could not run the PostgreSQL server because local sockets are blocked,
so that test is included but not represented as executed.

## Deployment state

The code is prepared and locally tested. It has not been pushed, deployed, or
configured in the owner's Render account. A Render connection and confirmed
personalization/MAC-input settings are still required for live configuration
and a real-tag end-to-end acceptance test.

## Primary references

- https://www.nxp.com/docs/en/application-note/AN10922.pdf — section 2.2
- https://www.nxp.com/docs/en/application-note/AN12196.pdf — sections 3.3, 3.4
