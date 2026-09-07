## Verdict
CONFIRMED. The code constructs an OS command string using template literals with unsanitized variables from user input, enabling OS command injection through shell metacharacters in the filename or geometry parameter.

## Source
Line 20 uses `execSync()` with a template literal that interpolates user-controlled data directly into a shell command:
```
execSync(`convert ${sourcePath} -resize ${geometry} ${thumbPath}`);
```

The `sourcePath` is derived from `req.params.filename` (line 13) and `geometry` from `req.body.geometry` (line 14). Both reach the command string without escaping, allowing an attacker to inject shell metacharacters (e.g., `$(...)`, `;`, `|`) to execute arbitrary commands.

## Fix
### File: ExecSyncTemplateLiteral.js

```javascript
const express = require("express");
const path = require("path");
const { spawnSync } = require("child_process");

const router = express.Router();
const UPLOAD_DIR = "/var/data/uploads";
const THUMB_DIR = "/var/data/thumbnails";

// Generates a thumbnail for a previously uploaded image using ImageMagick's
// `convert` CLI. The caller supplies the source filename and the desired
// output geometry (e.g. "200x200").
router.post("/api/images/:filename/thumbnail", (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  // Use argument array to prevent shell interpretation of user input
  const result = spawnSync("convert", [sourcePath, "-resize", geometry, thumbPath]);
  
  if (result.error) {
    res.status(500).json({ error: "Thumbnail generation failed" });
    return;
  }

  res.json({ thumbnail: `thumb-${filename}` });
});

module.exports = router;
```

## Explanation
The vulnerability occurs because `execSync()` with a shell command string interprets metacharacters. Replace `execSync()` with `spawnSync()`, passing the command and its arguments as an array. This prevents the shell from interpreting user-supplied values: each argument is passed directly to the `convert` executable without shell processing, eliminating the injection vector.

The fix also adds error handling to check the spawn result, returning a 500 error if the thumbnail generation fails rather than silently propagating an uncaught exception.
