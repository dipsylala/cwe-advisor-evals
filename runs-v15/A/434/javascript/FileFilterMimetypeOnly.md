## Verdict

This code is vulnerable to CWE-434 because it relies solely on the client-supplied MIME type to validate uploaded files. MIME types can be trivially spoofed by an attacker, allowing them to upload malicious executables or scripts with a fake image MIME type. Additionally, the file extension is extracted directly from the user-controlled originalname without validation, creating a secondary path for file type confusion.

## Source

```javascript
const ALLOWED_MIMETYPES = ['image/png', 'image/jpeg'];

function fileFilter(req, file, cb) {
  // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
  cb(null, ALLOWED_MIMETYPES.includes(file.mimetype));
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${crypto.randomUUID()}${ext}`);
  },
});
```

## Fix

Install the `file-type` package (`npm install file-type`) and validate the actual file content against allowed file signatures. Additionally, enforce allowed file extensions:

```javascript
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const FileType = require('file-type');

const router = express.Router();
const UPLOAD_DIR = path.join(__dirname, 'uploads', 'profile-photos');

// Map of allowed MIME types to their valid file extensions
const ALLOWED_TYPES = {
  'image/png': ['.png'],
  'image/jpeg': ['.jpg', '.jpeg'],
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const randomName = crypto.randomUUID();
    // Always use .bin initially; rename only after validation
    cb(null, `${randomName}.bin`);
  },
});

async function fileFilter(req, file, cb) {
  try {
    // Get the buffer from the request
    const buffer = file.buffer;
    
    // Detect the actual file type from magic bytes
    const detectedType = await FileType.fromBuffer(buffer);
    
    if (!detectedType) {
      return cb(new Error('Unable to detect file type'));
    }

    // Check if the detected MIME type is in allowed list
    if (!Object.keys(ALLOWED_TYPES).includes(detectedType.mime)) {
      return cb(new Error('File type not allowed'));
    }

    // Verify the file extension matches (optional but recommended)
    const userExt = path.extname(file.originalname).toLowerCase();
    const allowedExts = ALLOWED_TYPES[detectedType.mime];
    if (userExt && !allowedExts.includes(userExt)) {
      return cb(new Error('File extension does not match file type'));
    }

    // Validation passed; store detected type on file object for later use
    file.validatedMimetype = detectedType.mime;
    file.detectedExtension = detectedType.ext;
    
    cb(null, true);
  } catch (err) {
    cb(err);
  }
}

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter,
});

router.post('/profile/photo', upload.single('photo'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'photo rejected or missing' });
  }

  // Rename the temporary .bin file to the correct extension based on validation
  const validatedExt = req.file.detectedExtension ? `.${req.file.detectedExtension}` : '.bin';
  const finalFilename = req.file.filename.replace('.bin', validatedExt);
  
  const fs = require('fs');
  const oldPath = path.join(UPLOAD_DIR, req.file.filename);
  const newPath = path.join(UPLOAD_DIR, finalFilename);
  
  fs.renameSync(oldPath, newPath);

  const photoUrl = `/uploads/profile-photos/${finalFilename}`;
  return res.status(201).json({ url: photoUrl });
});

module.exports = router;
```

## Explanation

The vulnerability stems from two sources:

1. **Client-Supplied MIME Type**: The original code trusts `file.mimetype`, which is provided by the client's browser or HTTP request. An attacker can easily forge this header to claim a malicious executable is an image file.

2. **Unvalidated File Extension**: The extension is extracted from `file.originalname` without verification, allowing an attacker to preserve dangerous extensions.

The remediation:

- **Magic Bytes Detection** (`file-type` library): Validates the actual file content against known binary signatures (magic bytes) that identify the true file type. This cannot be spoofed because it reads the actual file content, not client-supplied metadata.

- **MIME Type Allowlist**: Checks the detected MIME type against an explicit allowlist of safe types, rejecting anything not explicitly approved.

- **Extension Validation**: Optionally verifies that the user-supplied extension matches the detected file type to catch mismatches.

- **Safe Renaming**: Initially saves the file with a neutral `.bin` extension, then renames it to the correct extension only after validation succeeds. This prevents direct access to potentially dangerous file types before validation is complete.

The `file-type` library is well-maintained and used widely for this purpose. For production use, also consider additional defenses: storing uploads outside the web root, disabling script execution in the upload directory (via web server configuration), and implementing anti-virus scanning for high-security applications.
