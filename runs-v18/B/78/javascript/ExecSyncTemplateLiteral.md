## Verdict

The finding is legitimate. The code uses `execSync()` with a template literal that interpolates untrusted user input (`filename` from `req.params` and `geometry` from `req.body`) directly into a shell command, enabling OS command injection.

## Source

- **Filename input**: `req.params.filename` (line 13)
- **Geometry input**: `req.body.geometry` (line 14)
- **Path construction**: Both values are used in path joins (lines 16-17) and then interpolated into the shell command string
- **Sink**: `execSync()` on line 20, which by default invokes the shell and processes metacharacters in its argument

An attacker can supply values like `image.jpg; rm -rf /` as the filename parameter, which when interpolated into the command becomes `convert /var/data/uploads/image.jpg; rm -rf / -resize ...`, allowing arbitrary command execution.

## Fix

### File: ExecSyncTemplateLiteral.js

```javascript
const express = require("express");
const path = require("path");
const sharp = require("sharp");

const router = express.Router();
const UPLOAD_DIR = "/var/data/uploads";
const THUMB_DIR = "/var/data/thumbnails";

// Generates a thumbnail for a previously uploaded image using the sharp image
// processing library. The caller supplies the source filename and the desired
// output geometry (e.g. "200x200").
router.post("/api/images/:filename/thumbnail", async (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";

  // Validate geometry format: must be "WIDTHxHEIGHT" with positive integers
  const geometryMatch = geometry.match(/^(\d+)x(\d+)$/);
  if (!geometryMatch) {
    return res.status(400).json({ error: "Invalid geometry format" });
  }

  const width = parseInt(geometryMatch[1], 10);
  const height = parseInt(geometryMatch[2], 10);

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  try {
    await sharp(sourcePath)
      .resize(width, height)
      .toFile(thumbPath);

    res.json({ thumbnail: `thumb-${filename}` });
  } catch (err) {
    res.status(500).json({ error: "Failed to create thumbnail" });
  }
});

module.exports = router;
```

## Explanation

The fix eliminates OS command execution entirely by replacing ImageMagick's `convert` command with the `sharp` Node.js library, which provides native image processing without invoking external programs. This closes the injection sink completely.

The key changes:
1. **Removed `execSync()` entirely** — eliminates the command execution sink that enabled shell injection
2. **Replaced with `sharp` library** — provides native image resizing without forking a process
3. **Added geometry validation** — the `geometry` input is parsed with a strict regex (`/^(\d+)x(\d+)$/`) to extract only valid width and height values; non-matching inputs are rejected with a 400 error
4. **Converted to async handling** — the endpoint now uses `async/await` to handle the asynchronous I/O that sharp provides; Express supports async route handlers natively
5. **Added error handling** — failures in image processing are caught and returned as 500 errors instead of crashing

The geometry validation transforms the untrusted string into validated integer values (width and height), which are then passed to sharp as discrete parameters rather than interpolating the raw string anywhere.

## Behaviour changes

1. **Async route handler**: The endpoint is now asynchronous (using `async/await`). Express handles this transparently; existing clients will see no difference in behavior.
2. **Resize algorithm**: Sharp's default resize behavior (aspect-ratio-preserving resize fitting within the specified dimensions) is equivalent to ImageMagick's `-resize WIDTHxHEIGHT` behavior, so thumbnails will have the same dimensions and appearance.
3. **Error responses**: Image processing errors now return a generic 500 error message instead of propagating the exception; this is safer than leaking error details that could aid attackers.
4. **Input validation**: Invalid geometry formats (anything not matching `WIDTHxHEIGHT` with positive integers) now return a 400 error with a descriptive message. The original code would have passed invalid formats to ImageMagick and returned whatever error it produced.
5. **Dependency change**: The code now requires the `sharp` npm package. This must be added to `package.json` with `npm install sharp` (or `yarn add sharp`).
