## Verdict

Exploitable. The code concatenates untrusted user input directly into a shell command string executed via `execSync()`. Both `filename` (from `req.params.filename`, line 13) and `geometry` (from `req.body.geometry`, line 14) flow into a template literal at line 20 without validation or escaping, enabling arbitrary command execution.

## Source

- `req.params.filename` (line 13): untrusted URL parameter, directly used in shell command
- `req.body.geometry` (line 14): untrusted request body property, directly used in shell command

## Fix

### File: ExecSyncTemplateLiteral.js

```javascript
const express = require("express");
const path = require("path");
const sharp = require("sharp");

const router = express.Router();
const UPLOAD_DIR = "/var/data/uploads";
const THUMB_DIR = "/var/data/thumbnails";

// Generates a thumbnail for a previously uploaded image using sharp.
// The caller supplies the source filename and the desired
// output geometry (e.g. "200x200").
router.post("/api/images/:filename/thumbnail", async (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  try {
    // Parse geometry string (e.g., "200x200" -> { width: 200, height: 200 })
    const [widthStr, heightStr] = geometry.split('x');
    const width = parseInt(widthStr, 10);
    const height = parseInt(heightStr, 10);

    if (!width || !height || width <= 0 || height <= 0) {
      return res.status(400).json({ error: "Invalid geometry format" });
    }

    // Use sharp to resize the image without shell execution
    await sharp(sourcePath)
      .resize(width, height, { fit: 'inside', withoutEnlargement: true })
      .toFile(thumbPath);

    res.json({ thumbnail: `thumb-${filename}` });
  } catch (error) {
    res.status(500).json({ error: "Failed to generate thumbnail" });
  }
});

module.exports = router;
```

## Explanation

The original code executes a shell command by concatenating untrusted user input into a template literal passed to `execSync()`, allowing arbitrary command injection. The fix eliminates OS command execution entirely by replacing ImageMagick's `convert` CLI with the `sharp` library, which is the Node.js standard for image manipulation and requires no shell interaction.

The geometry string is parsed and validated to ensure it contains two positive integers separated by 'x'; invalid formats return a 400 error instead of reaching the image processor. The `sharp` API takes width and height as separate numeric parameters, preventing them from being interpreted as shell metacharacters. All user input is now confined to structured data operations with no shell parsing layer.

## Behaviour changes

- **Handler is now async**: The route handler is declared `async` and uses `await` with `sharp().toFile()`. Callers must handle this as a Promise. Express supports async handlers natively, but any manual invocation must await the returned Promise.
- **Geometry validation added**: Invalid geometry strings (non-numeric, missing 'x' separator, zero or negative dimensions) now return a 400 error instead of being passed to the command executor. This is a breaking change for clients sending malformed geometry, but aligns with HTTP semantics.
- **Error handling changed**: The original code would throw on command failure. The fixed code wraps all operations in a try-catch block and returns a 500 error with a generic message, concealing implementation details from the client. The original may have leaked command output or system paths; the new code does not.
- **No execution output returned**: The original code did not use or return the output of `execSync()`, so this fix introduces no information loss. The response is unchanged: `{ thumbnail: "thumb-<filename>" }`.
- **`sharp` library dependency added**: Requires `sharp` (npm package). This is the standard Node.js image manipulation library and is widely maintained.

