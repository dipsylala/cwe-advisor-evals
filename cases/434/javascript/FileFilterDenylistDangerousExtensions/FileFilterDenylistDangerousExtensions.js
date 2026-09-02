const express = require('express');
const multer = require('multer');
const path = require('path');

const router = express.Router();

// Extensions considered dangerous enough to block. Anything not in this
// list is assumed to be safe and is allowed through.
const BLOCKED_EXTENSIONS = ['.exe', '.php', '.sh', '.bat'];

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, file.originalname),
});

function rejectKnownDangerousExtensions(req, file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();
  if (BLOCKED_EXTENSIONS.includes(ext)) {
    return cb(new Error(`File type ${ext} is not allowed`));
  }
  // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
  return cb(null, true);
}

const upload = multer({
  storage,
  fileFilter: rejectKnownDangerousExtensions,
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
