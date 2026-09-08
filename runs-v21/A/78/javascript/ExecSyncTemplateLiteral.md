## Verdict

VULNERABLE. The code uses `execSync()` with a template literal to construct an OS command, interpolating unsanitized user input directly into the shell command string. An attacker who controls `req.params.filename` or `req.body.geometry` can inject shell metacharacters to break out of the intended command and execute arbitrary OS commands.

## Source

**File:** `ExecSyncTemplateLiteral.js`  
**Line:** 20  
**Vulnerable Code:**
```javascript
execSync(`convert ${sourcePath} -resize ${geometry} ${thumbPath}`);
```

The vulnerability chain:
- Line 13: `filename` is read from `req.params.filename` (attacker-controlled)
- Line 14: `geometry` is read from `req.body.geometry` (attacker-controlled)
- Line 16-17: These values are joined into paths via `path.join()`, which does not escape for shell use
- Line 20: The paths are interpolated into a shell command string and passed to `execSync()`, which spawns a shell to interpret the string

**Attack Example:**  
If `req.params.filename` is `image.jpg; rm -rf /var/data`, the executed shell command becomes:
```
convert /var/data/uploads/image.jpg; rm -rf /var/data -resize 200x200 /var/data/thumbnails/thumb-image.jpg; rm -rf /var/data
```

## Fix

### File: ExecSyncTemplateLiteral.js

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

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  // Use execFileSync with an argument array to avoid shell interpretation
  execFileSync("convert", [sourcePath, "-resize", geometry, thumbPath]);

  res.json({ thumbnail: `thumb-${filename}` });
});

module.exports = router;
```

## Explanation

The fix replaces `execSync()` with `execFileSync()` and passes arguments as an array instead of a concatenated shell command string.

**Why this closes the vulnerability:**

1. **No shell spawning:** `execFileSync(file, args)` does not spawn a shell to interpret the command. It directly executes the program with the supplied arguments.

2. **Argument array prevents metacharacter injection:** When arguments are passed as array elements, the operating system passes them directly to the child process without shell parsing. Metacharacters like `;`, `|`, `$()`, backticks, and others are treated as literal characters, not as shell operators.

3. **Preserves existing error handling:** `execFileSync()` maintains the same synchronous behavior and error-throwing semantics as `execSync()`, so existing error handling continues to work.

**Changes made:**
- Line 3: Change destructuring from `{ execSync }` to `{ execFileSync }`
- Line 20: Replace `execSync(`` `convert ${sourcePath} -resize ${geometry} ${thumbPath}` ``)` with `execFileSync("convert", [sourcePath, "-resize", geometry, thumbPath])`

With this fix, even if an attacker supplies `image.jpg; rm -rf /var/data` as the filename, the array element is passed literally to the `convert` program, which treats it as a filename, not as a shell injection point.
