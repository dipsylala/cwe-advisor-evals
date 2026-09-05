## Verdict

Exploitable. The `filename` parameter from the URL and the `geometry` parameter from the request body are concatenated into a shell command string without escaping or parameterization, allowing arbitrary command injection.

## Source

- `req.params.filename` (line 13) — untrusted URL parameter
- `req.body.geometry` (line 14) — untrusted request body parameter

Both are incorporated into the shell command via string concatenation in the template literal at line 20.

## Fix

**Vulnerable code:**

```javascript
const express = require("express");
const path = require("path");
const { execSync } = require("child_process");

const router = express.Router();
const UPLOAD_DIR = "/var/data/uploads";
const THUMB_DIR = "/var/data/thumbnails";

router.post("/api/images/:filename/thumbnail", (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
  execSync(`convert ${sourcePath} -resize ${geometry} ${thumbPath}`);

  res.json({ thumbnail: `thumb-${filename}` });
});

module.exports = router;
```

**Fixed code:**

```javascript
const express = require("express");
const path = require("path");
const sharp = require("sharp");

const router = express.Router();
const UPLOAD_DIR = "/var/data/uploads";
const THUMB_DIR = "/var/data/thumbnails";

// Generates a thumbnail for a previously uploaded image using sharp (Node.js native image library).
// The caller supplies the source filename and the desired output geometry (e.g. "200x200").
router.post("/api/images/:filename/thumbnail", async (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  // Parse geometry string (format: "WxH" e.g. "200x200")
  const geometryMatch = geometry.match(/^(\d+)x(\d+)$/);
  if (!geometryMatch) {
    return res.status(400).json({ error: "Invalid geometry format" });
  }

  const width = parseInt(geometryMatch[1], 10);
  const height = parseInt(geometryMatch[2], 10);

  if (width <= 0 || height <= 0 || width > 10000 || height > 10000) {
    return res.status(400).json({ error: "Geometry dimensions out of range" });
  }

  await sharp(sourcePath)
    .resize(width, height, { fit: 'cover' })
    .toFile(thumbPath);

  res.json({ thumbnail: `thumb-${filename}` });
});

module.exports = router;
```

## Explanation

The fix eliminates OS command execution entirely by replacing `child_process.execSync()` with the `sharp` library, a Node.js native image manipulation package. This removes the injection surface completely—there is no shell command to inject into.

The geometry parameter is now validated against a strict regex pattern (`/^(\d+)x(\d+)$/`) that ensures it contains only digits and the `x` separator, then parsed into integer width and height values. Those parsed integers are passed to `sharp.resize()` where they cannot be reinterpreted as commands. Input bounds are also enforced (1–10000 pixels) to prevent unreasonable requests. The handler is made `async` to accommodate sharp's asynchronous API, which is the idiomatic pattern for Node.js I/O operations and maintains the same contract as the original—returning JSON with the thumbnail filename upon success and an error response if geometry parsing or resizing fails.

## Behaviour changes

- Handler is now `async` (originally synchronous) — required because sharp's operations are asynchronous; callers expecting a synchronous endpoint must be updated or this can be wrapped with a helper to manage promise handling.
- Geometry parsing adds validation that rejects malformed input (anything not matching `\d+x\d+`), returning HTTP 400 instead of attempting the operation and likely failing with a different error.
- Geometry bounds enforce a maximum of 10000×10000 pixels to prevent denial-of-service through extremely large resize operations.
- Error responses for invalid geometry now return structured JSON with `{ error: "..." }` instead of allowing sharp to throw an unhandled error; the original code would have thrown an exception from execSync, which the Express handler would propagate as a 500 error.
- The resize algorithm uses `{ fit: 'cover' }` mode, which scales to fill the requested dimensions and crops excess. ImageMagick's `-resize` flag behavior differs: `200x200!` forces exact dimensions, while `200x200` may preserve aspect ratio. This may alter the output image dimensions or appearance; callers expecting exact ImageMagick behavior should adjust the fit mode (`contain`, `inside`, etc.) or provide explicit fit instructions in the geometry parameter if needed.
