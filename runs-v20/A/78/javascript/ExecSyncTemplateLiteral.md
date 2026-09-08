## Verdict

Confirmed. `req.params.filename` and `req.body.geometry` reach `execSync` through an interpolated shell command string, letting an attacker inject shell metacharacters (e.g. `; rm -rf /`, backticks, `$()`) that run arbitrary commands with the server's privileges.

## Source

- `req.params.filename` (line 13) - attacker-controlled URL path segment.
- `req.body.geometry` (line 14) - attacker-controlled request body field, defaults to `"200x200"` only when absent.

Both values flow, via `sourcePath`/`thumbPath` (built with `path.join`) and `geometry` directly, into the template literal passed to `execSync` on line 20, which spawns `/bin/sh -c` and interprets shell metacharacters in the whole string.

## Fix

### File: ExecSyncTemplateLiteral.js
```javascript
const express = require("express");
const path = require("path");
const { execFileSync } = require("child_process");

const router = express.Router();
const UPLOAD_DIR = "/var/data/uploads";
const THUMB_DIR = "/var/data/thumbnails";

// Only accept geometry in ImageMagick's "<width>x<height>" form. This also
// rules out a value that starts with "-", which would otherwise let
// user input be parsed as an extra convert flag even without a shell.
const GEOMETRY_PATTERN = /^\d{1,5}x\d{1,5}$/;

// Generates a thumbnail for a previously uploaded image using ImageMagick's
// `convert` CLI. The caller supplies the source filename and the desired
// output geometry (e.g. "200x200").
router.post("/api/images/:filename/thumbnail", (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";

  if (!GEOMETRY_PATTERN.test(geometry)) {
    return res.status(400).json({ error: "Invalid geometry format" });
  }

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  // Fixed: execFileSync runs the `convert` binary directly with an argument
  // array instead of handing a shell an interpolated string, so shell
  // metacharacters in sourcePath, geometry, or thumbPath are passed through
  // as literal argv values rather than being parsed by /bin/sh.
  execFileSync("convert", [sourcePath, "-resize", geometry, thumbPath]);

  res.json({ thumbnail: `thumb-${filename}` });
});

module.exports = router;
```

## Explanation

`execSync` always runs its argument through a shell, so any characters in `sourcePath`, `geometry`, or `thumbPath` that the shell treats specially (`;`, `|`, `&&`, backticks, `$()`, whitespace-separated extra tokens, etc.) are interpreted rather than passed to `convert` as data. Because `geometry` comes straight from `req.body.geometry` with no validation, and `filename` reaches the command by way of `path.join`, an attacker can terminate the intended `convert` invocation and run any command the Node process's user can run.

The fix swaps `execSync` for `execFileSync("convert", [...])`. `execFileSync` (and its async sibling `execFile`) launches the named executable directly - by default with no shell in between - and passes each array element to it as a single, literal argument. There is no command-line string for a shell to re-parse, so metacharacters in any of the three values no longer have any special meaning; they are just bytes in an argv entry.

A second, narrower gap remains even without a shell: because `geometry` becomes a standalone argv element passed to `convert`, a value that itself begins with `-` (e.g. `-execute...`) could be parsed by `convert` as an option rather than a size, which is a form of argument injection distinct from shell injection. Adding the `GEOMETRY_PATTERN` check (`^\d{1,5}x\d{1,5}$`) constrains the value to ImageMagick's documented "`widthxheight`" geometry syntax, which structurally cannot start with `-`, closing that residual gap without weakening the primary fix.
