## Verdict

Confirmed. The denylist approach is a classic CWE-434 bypass vector. Restricting only a small set of known-dangerous extensions allows files with other executable types (`.jsp`, `.aspx`, `.phar`, etc.) to be uploaded and potentially executed.

## Source

Lines 9, 16-23: The `BLOCKED_EXTENSIONS` denylist contains only 4 extensions, and the `rejectKnownDangerousExtensions` filter accepts any file whose extension is not in that list.

## Fix

### File: FileFilterDenylistDangerousExtensions.js

```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');

const router = express.Router();

// Whitelist of safe extensions allowed for upload.
// Only these file types are permitted.
const ALLOWED_EXTENSIONS = ['.pdf', '.txt', '.jpg', '.jpeg', '.png', '.gif'];

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, file.originalname),
});

function allowOnlyWhitelistedExtensions(req, file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return cb(new Error(`File type ${ext} is not allowed`));
  }
  return cb(null, true);
}

const upload = multer({
  storage,
  fileFilter: allowOnlyWhitelistedExtensions,
});

router.post('/attachments', upload.single('attachment'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const savedPath = path.join(__dirname, 'uploads', req.file.filename);

  return res.status(201).json({
    message: 'Attachment uploaded',
    path: savedPath,
  });
});

module.exports = router;
```

## Explanation

**Root cause:** Denylist-based filtering fails because there are many executable extensions beyond the 4 blocked (`.jsp`, `.aspx`, `.phtml`, `.phar`, `.jspx`, etc.), and new executable formats emerge. An attacker only needs to find one unblocked dangerous extension to bypass the control.

**Fix approach:** Replace the denylist with an allowlist of known-safe file extensions. The filter now rejects any file *not* in `ALLOWED_EXTENSIONS`, inverting the logic. An uploaded file must be explicitly approved rather than implicitly allowed by absence from a blocklist.

**Defense in depth:** The list includes only common document and image types (PDF, text, common image formats) that are unlikely to be executed by a web server. File uploads should ideally also be stored outside the web-accessible directory or delivered with `Content-Disposition: attachment` to prevent execution.
