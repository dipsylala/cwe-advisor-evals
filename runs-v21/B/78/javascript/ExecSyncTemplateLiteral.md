## Verdict

Exploitable. Untrusted user input from `req.params.filename` and `req.body.geometry` is directly interpolated into a shell command string passed to `execSync()`, allowing OS command injection.

## Source

- `req.params.filename` (line 13) - untrusted filename from URL parameter
- `req.body.geometry` (line 14) - untrusted geometry parameter from request body
- Both values flow to the shell command on line 20 via template literal interpolation

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

  // Fixed: Use execFileSync with argument array to prevent shell injection
  execFileSync("convert", [sourcePath, "-resize", geometry, thumbPath]);

  res.json({ thumbnail: `thumb-${filename}` });
});

module.exports = router;
```

## Explanation

The vulnerability stems from using `execSync()` with a shell command constructed via template literal interpolation. When untrusted input like `geometry` is embedded directly into the command string, an attacker can inject shell metacharacters (`;`, `|`, `&&`, etc.) to execute arbitrary commands.

The fix replaces `execSync()` with `execFileSync()`, which executes the command directly without invoking a shell. Arguments are passed as an array (`[sourcePath, "-resize", geometry, thumbPath]`) rather than concatenated into a single string. This prevents the shell from interpreting special characters in the arguments—they are treated as literal argument values to the `convert` command, not as shell syntax. The array-based approach is the standard Node.js pattern for safe command execution when shell invocation is unavoidable.

## Behaviour changes

None. `execFileSync()` produces the same output and return behavior as `execSync()` when both are invoked without the `shell: true` option. The arguments are passed in the same order and have the same semantics to the `convert` program. Error handling remains identical: both throw on non-zero exit.
