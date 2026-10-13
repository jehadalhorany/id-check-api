# Mobile API — Wathiq

Base URL after deploying this version

https://id-check-api-borw.onrender.com

## Public lookup — no authentication

POST /api/check
Content-Type: application/json

```json
{"id":"00123"}
```

No username, password, token or Authorization header is required.
The ID is a string. Preserve leading zeroes. It must match [A-Za-z0-9_-]{1,64}.

HTTP 200 — active ID found

```json
{
  "available": true,
  "message": "متاح",
  "id": "00123",
  "text": "النص المرتبط بالرقم",
  "image_url": "https://id-check-api-borw.onrender.com/media/IMAGE_ID",
  "video_url": "https://id-check-api-borw.onrender.com/media/VIDEO_ID"
}
```

image_url and video_url are null if the admin has not attached that file. text may be empty. URLs are absolute and retrieved with public GET requests. Images and videos are not encoded inside the JSON response.

HTTP 200 — missing or inactive ID

```json
{"available":false,"message":"غير متاح"}
```

No record text or media is returned. Disabled or deleted records make their otherwise unshared media unavailable too. Treat available as the result field, not the HTTP status alone.

Invalid ID or JSON: HTTP 400. Database/service failure: HTTP 503. Do not interpret a service failure as an unavailable ID. Free Render instances may take time to start after inactivity; use an appropriate network timeout and provide a retry action.

## JavaScript example

```javascript
const response = await fetch('https://id-check-api-borw.onrender.com/api/check', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ id: '00123' })
});
if (!response.ok) throw new Error(`API error: ${response.status}`);
const result = await response.json();
if (result.available) {
  // Display result.text.
  // Load result.image_url if it is not null.
  // Play result.video_url if it is not null.
} else {
  // Display result.message: غير متاح.
}
```

CORS is enabled for this public lookup endpoint. Native Android/iOS clients do not require browser CORS. The public media endpoint supports Accept-Ranges: bytes and HTTP 206 partial responses for video seeking. Use Range: bytes=START-END when supported by the player. Unsupported ranges return HTTP 416.

MP4/WebM uploads are accepted without transcoding. Use browser/device-compatible video encoding, preferably H.264/AAC inside MP4 for typical mobile playback. The app can accept manual typing or scan a QR/barcode containing only the ID. Do not request camera permission until the user chooses to scan.

## Administrator interface

The web interface is for admins only. The existing admin username is abo_liath. Admin login, editing, uploads, CSV and audit APIs remain protected. Do not put administrator credentials in the mobile application. Public registration is disabled; there is no mobile-user registration or email activation requirement.

This contract describes the attached version. Deploy the update to the existing Render service before testing the deployed URL against this contract.
