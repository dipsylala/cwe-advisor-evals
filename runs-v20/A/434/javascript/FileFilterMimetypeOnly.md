## Verdict

Confirmed. `fileFilter` accepts or rejects the upload based solely on `file.mimetype`, which is the `Content-Type` the client wrote into the multipart part for that field. This value is fully attacker-controlled and has no relationship to the actual bytes of the uploaded file — a request can attach an HTML, SVG, or script payload while declaring `Content-Type: image/png` and the filter lets it through. The saved filename's extension is also taken directly from `file.originalname` (`path.extname(file.originalname)`), which is likewise attacker-controlled, so the file lands on disk with whatever dangerous extension the client chose (e.g. `.html`, `.svg`, `.php`) alongside a spoofed mimetype. Together this is a classic unrestricted-upload gap: nothing about the accepted or rejected outcome depends on the file's real content.

## Source

`req.file` from `upload.single('photo')` (line 33) — specifically `file.mimetype` and `file.originalname`, both populated from client-supplied multipart headers and never validated against the actual file bytes.

## Fix

### File: FileFilterMimetypeOnly.js

```javascript
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs/promises');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, 'uploads', 'profile-photos');

const ALLOWED_MIMETYPES = ['image/png', 'image/jpeg'];

// Magic-byte signatures for the allowed image types, used to verify the
// actual file content on disk. The client-supplied mimetype and filename
// extension are just labels the caller chose and cannot be trusted alone.
const SIGNATURES = {
  'image/png': [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
  'image/jpeg': [0xff, 0xd8, 0xff],
};

const EXTENSION_BY_MIMETYPE = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // The real extension is assigned after the content is verified below;
    // give the file a neutral, non-executable temporary name for now.
    cb(null, `${crypto.randomUUID()}.tmp`);
  },
});

function fileFilter(req, file, cb) {
  // The mimetype here is the Content-Type the client put in the multipart
  // body - an attacker fully controls it and can label any file
  // "image/png". This only rejects obviously wrong uploads early; the
  // route handler below verifies the actual bytes before the file is
  // treated as accepted.
  cb(null, ALLOWED_MIMETYPES.includes(file.mimetype));
}

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter,
});

async function detectImageMimetype(filePath) {
  const handle = await fs.open(filePath, 'r');
  try {
    const header = Buffer.alloc(8);
    await handle.read(header, 0, header.length, 0);
    for (const [mimetype, signature] of Object.entries(SIGNATURES)) {
      if (signature.every((byte, i) => header[i] === byte)) {
        return mimetype;
      }
    }
    return null;
  } finally {
    await handle.close();
  }
}

router.post('/profile/photo', upload.single('photo'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'photo rejected or missing' });
  }

  const uploadedPath = req.file.path;

  try {
    const detectedMimetype = await detectImageMimetype(uploadedPath);

    if (!detectedMimetype || !ALLOWED_MIMETYPES.includes(detectedMimetype)) {
      await fs.unlink(uploadedPath).catch(() => {});
      return res.status(400).json({ error: 'photo rejected or missing' });
    }

    // Name the file from the verified type, not the client-supplied
    // originalname/mimetype, so a spoofed upload can't land on disk with
    // a dangerous extension (e.g. .html, .svg, .php).
    const finalName = `${path.basename(uploadedPath, path.extname(uploadedPath))}${EXTENSION_BY_MIMETYPE[detectedMimetype]}`;
    const finalPath = path.join(UPLOAD_DIR, finalName);
    await fs.rename(uploadedPath, finalPath);

    const photoUrl = `/uploads/profile-photos/${finalName}`;
    return res.status(201).json({ url: photoUrl });
  } catch (err) {
    await fs.unlink(uploadedPath).catch(() => {});
    return res.status(500).json({ error: 'upload failed' });
  }
});

module.exports = router;
```

## Explanation

The original code had two related gaps that both trace back to trusting client-supplied labels instead of the file's real content:

1. `fileFilter` only checked `file.mimetype`, a header the client sets on the multipart part. It carries no guarantee about the bytes that follow, so an attacker can send any payload with a forged `Content-Type: image/png` and pass the check.
2. The saved filename's extension came from `path.extname(file.originalname)` — also attacker-controlled — so even if the mimetype check were tightened, the file could still be written to disk as `payload.html` or `payload.svg`, which some web servers or browsers will interpret as active content rather than an inert image.

The fix keeps `fileFilter` as a cheap first-pass rejection (it's harmless as a fast-fail, not a security boundary) but adds a second, authoritative check after the bytes are actually on disk: `detectImageMimetype` reads the file's leading bytes and matches them against the known magic-number signatures for PNG (`89 50 4E 47 0D 0A 1A 0A`) and JPEG (`FF D8 FF`). Only a file whose real content matches an allowed signature is accepted; anything else is deleted and rejected with the same response the filter would have produced, so behavior for legitimate images is unchanged.

The output filename's extension is now derived exclusively from the verified real mimetype via `EXTENSION_BY_MIMETYPE`, never from `file.originalname`. This closes the second half of the issue: even a file that somehow satisfied the placeholder `fileFilter` cannot be persisted with an attacker-chosen extension, because the extension is a function of content that was independently checked, not of anything the client sent. The temporary on-disk name during the verification window (`*.tmp`) is also non-executable, so a request that fails verification never has a dangerous extension at any point during processing.

This uses only Node's built-in `fs/promises`, so no new dependency or version tracking is introduced.
