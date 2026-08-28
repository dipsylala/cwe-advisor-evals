const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');

const app = express();
const upload = multer({ dest: '/tmp/incoming' });

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

const ALLOWED = ['image/png', 'image/jpeg', 'image/svg+xml'];

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(req.file.path);

  if (!detected || !ALLOWED.includes(detected.mime)) {
    return res.status(400).json({ error: 'unsupported image type' });
  }

  // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
  const destination = path.join(PUBLIC_DIR, 'avatars', req.file.originalname);

  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(req.file.path, destination);

  res.json({ url: '/avatars/' + path.basename(destination) });
});

module.exports = app;
