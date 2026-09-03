## Verdict

exploitable

## Source

User-supplied input from:
- `req.params.filename` - attacker-controlled filename parameter (line 13)
- `req.body.geometry` - attacker-controlled geometry from request body (line 14)

Both values are incorporated into the command string without validation or sanitization.

## Sink

`execSync()` at line 20

```javascript
execSync(`convert ${sourcePath} -resize ${geometry} ${thumbPath}`);
```

The command string is constructed via template literal interpolation, allowing shell metacharacters in the user-supplied values to be interpreted as commands.

## Fix

**Vulnerable Code:**
```javascript
const { execSync } = require("child_process");
// ...
router.post("/api/images/:filename/thumbnail", (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";
  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  execSync(`convert ${sourcePath} -resize ${geometry} ${thumbPath}`);
  res.json({ thumbnail: `thumb-${filename}` });
});
```

**Fixed Code:**
```javascript
const express = require("express");
const path = require("path");
const sharp = require("sharp");

const router = express.Router();
const UPLOAD_DIR = "/var/data/uploads";
const THUMB_DIR = "/var/data/thumbnails";

router.post("/api/images/:filename/thumbnail", async (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  try {
    // Parse and validate geometry format (e.g. "200x200")
    const parts = geometry.split('x');
    const width = parseInt(parts[0], 10);
    const height = parseInt(parts[1], 10);
    
    if (!width || !height || width <= 0 || height <= 0) {
      return res.status(400).json({ error: 'Invalid geometry format' });
    }

    // Use sharp library to resize image - eliminates OS command execution
    await sharp(sourcePath)
      .resize(width, height, { fit: 'inside', withoutEnlargement: true })
      .toFile(thumbPath);

    res.json({ thumbnail: `thumb-${filename}` });
  } catch (err) {
    res.status(500).json({ error: 'Image processing failed' });
  }
});

module.exports = router;
```

**Library Recommendation:** `sharp` - A high-performance Node.js image processing library that eliminates the need for external ImageMagick commands. No specific version minimum required; use the latest stable version from npm. Confirm against your SCA tooling before deployment.

## Explanation

The original code uses `execSync()` with a template literal to construct a shell command, passing unsanitized user input (`geometry` parameter and filesystem paths constructed from `filename`) directly into the command string. This allows an attacker to inject shell metacharacters (e.g., `;`, `|`, `&`, backticks) to execute arbitrary commands on the host.

The remediation eliminates OS command execution entirely by replacing the ImageMagick CLI call with the `sharp` library, a native Node.js image processing module. The geometry parameter is parsed and validated against an allowlist pattern (numeric dimensions), rejecting malformed input. By removing the shell command execution layer, there is no vector for command injection regardless of what characters appear in the input. The fix maintains the same functionality—resizing images—while closing the injection point entirely.

## Behaviour changes

1. **Route handler now async** - Changed from synchronous to async function to accommodate `sharp`'s promise-based API. Callers that don't await the response will not wait for processing to complete; ensure downstream code expects this.

2. **Geometry validation added** - The fixed code parses `geometry` as `WIDTHxHEIGHT` format and rejects non-numeric or zero/negative values with a 400 status. The original code passed any value to ImageMagick without validation; invalid input now returns an error instead of failing during processing.

3. **Error handling changed** - Original code threw synchronously on command failure; fixed code catches errors and returns a 500 status with a generic error message. Callers that depended on synchronous exception propagation will need to handle HTTP error responses instead.

4. **New dependency** - Requires `sharp` npm package. Ensure it is added to `package.json` and installed in the deployment environment.

5. **Resize behavior** - `sharp`'s `fit: 'inside'` with `withoutEnlargement: true` maintains aspect ratio and does not upscale images smaller than the target geometry. The original ImageMagick `-resize` with geometry alone may scale differently; test that thumbnail output matches expected dimensions and quality.

6. **Output discarded behavior preserved** - The original `execSync` return value (stdout) was discarded; the fixed code also discards `sharp`'s return value (file write confirmation), maintaining the same level of output verification. Both versions should confirm file existence after processing if error detection is critical.
