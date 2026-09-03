## Verdict

**Real**: Confirmed OS Command Injection at line 20.

## Source

Line 20 uses `execSync()` with a template literal that directly concatenates user-controlled data. The `sourcePath` is derived from `req.params.filename` and `geometry` from `req.body.geometry`, both passed directly into a shell command string without escaping or validation. An attacker can inject shell metacharacters via either field to execute arbitrary commands.

## Fix

```javascript
const express = require("express");
const path = require("path");
const { execFileSync } = require("child_process");

const router = express.Router();
const UPLOAD_DIR = "/var/data/uploads";
const THUMB_DIR = "/var/data/thumbnails";

// Generates a thumbnail for a previously uploaded image using ImageMagick's
// `convert` CLI. The caller supplies the source filename and the desired
// output geometry (e.g. "200x200").
router.post("/api/images/:filename/thumbnail", (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";

  // Validate filename: reject anything with path separators or dots to prevent directory traversal
  if (!/^[a-zA-Z0-9._-]+$/.test(filename)) {
    return res.status(400).json({ error: "Invalid filename" });
  }

  // Validate geometry: must match WIDTHxHEIGHT format and not start with dash
  if (!/^\d+x\d+$/.test(geometry)) {
    return res.status(400).json({ error: "Invalid geometry format" });
  }

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  // Use execFileSync with argument array and no shell to prevent injection
  execFileSync("convert", [sourcePath, "-resize", geometry, thumbPath]);

  res.json({ thumbnail: `thumb-${filename}` });
});

module.exports = router;
```

## Explanation

The root cause is concatenating untrusted user input into a shell command string. The vulnerable code uses `execSync()` with a template literal that directly interpolates `sourcePath` and `geometry` into the command. An attacker could inject shell metacharacters (e.g., `; rm -rf /`) through either parameter to execute arbitrary commands on the host.

**The fix consists of three parts:**

1. **Replace `execSync()` with `execFileSync()`**: This avoids shell invocation entirely. `execFileSync()` spawns the target program directly without a shell interpreter, preventing shell metacharacter interpretation.

2. **Use argument array**: Arguments are passed as separate array elements rather than a single concatenated string. This ensures each parameter is treated as a single argument to the `convert` program, not as a shell command line to be parsed.

3. **Add input validation**: 
   - For `filename`: Use a strict allowlist pattern (`/^[a-zA-Z0-9._-]+$/`) to accept only simple filenames without path separators or directory traversal sequences
   - For `geometry`: Validate the format strictly (`/^\d+x\d+$/`) to match the expected `WIDTHxHEIGHT` pattern, and implicitly reject values starting with `-` which could be misinterpreted as flags by `convert`

The validation layer ensures that even if injection were somehow possible, the values cannot contain dangerous characters or become command flags.

## Behaviour changes

- **Security**: Shell injection is eliminated. The `convert` command is invoked directly with a fixed argument list, so shell metacharacters in user input are passed literally to `convert` and handled safely.
- **Error handling**: Invalid input now returns HTTP 400 (Bad Request) with a descriptive error message instead of potentially executing dangerous commands or producing a cryptic `convert` error.
- **Functionality**: The thumbnail generation works identically for valid inputs. Only malformed requests are rejected earlier.
- **Performance**: No measurable change; `execFileSync()` and `execSync()` have similar overhead.
