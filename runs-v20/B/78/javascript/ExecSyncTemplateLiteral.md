## Verdict

Exploitable. CWE-78, OS Command Injection.

## Source

- `req.params.filename` (URL path segment `:filename` on `POST /api/images/:filename/thumbnail`)
- `req.body.geometry` (JSON/form body field, defaults to `"200x200"` if absent)

Both reach the sink through `sourcePath`/`thumbPath` (built with `path.join`, which does not neutralize shell metacharacters) and the raw `geometry` variable.

## Fix

### File: ExecSyncTemplateLiteral.js

```javascript
const express = require("express");
const path = require("path");
const { execFileSync } = require("child_process");

const router = express.Router();
const UPLOAD_DIR = "/var/data/uploads";
const THUMB_DIR = "/var/data/thumbnails";
const CONVERT_BIN = "/usr/bin/convert";
// ImageMagick resize geometry the app accepts: WIDTHxHEIGHT, digits only.
const GEOMETRY_PATTERN = /^\d{1,4}x\d{1,4}$/;

// Generates a thumbnail for a previously uploaded image using ImageMagick's
// `convert` CLI. The caller supplies the source filename and the desired
// output geometry (e.g. "200x200").
router.post("/api/images/:filename/thumbnail", (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";

  if (!GEOMETRY_PATTERN.test(geometry)) {
    return res.status(400).json({ error: "geometry must be in WIDTHxHEIGHT format, e.g. 200x200" });
  }

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  execFileSync(CONVERT_BIN, [sourcePath, "-resize", geometry, thumbPath]);

  res.json({ thumbnail: `thumb-${filename}` });
});

module.exports = router;
```

## Explanation

The sink invoked `convert` through a shell (`execSync` with a template-literal command string), so any shell metacharacter in `filename` or `geometry` (backticks, `;`, `|`, `$()`, etc.) was interpreted by `/bin/sh` and let an attacker run arbitrary commands. `execFileSync` invokes the `convert` binary directly with an argument array and no shell, so the arguments are passed to the process as literal strings and can no longer be parsed as shell syntax - this closes the injection regardless of what characters `filename` contains. `geometry` is additionally constrained to the `WIDTHxHEIGHT` digit format the application actually expects, since that is a format the application owns; this is a secondary defence, not a substitute for removing the shell. `convert` is invoked by its absolute path (`/usr/bin/convert`) so a writable `PATH` entry cannot substitute a different binary. Running `convert` itself was kept rather than replaced with an image-processing library: generating the thumbnail via ImageMagick's CLI is the endpoint's stated purpose, and no built-in Node module performs image resizing, so removing the command would be a rewrite, not a fix. Argument injection (CWE-88) was checked separately: `sourcePath` and `thumbPath` are always absolute (`path.join` against the fixed `UPLOAD_DIR`/`THUMB_DIR` constants), so neither can begin with `-` and be read as a flag by `convert`, and the geometry regex likewise cannot produce a leading `-`; no `--` marker or extra rejection was needed for these two arguments.

## Behaviour changes

- Added a 400 response when `geometry` does not match `WIDTHxHEIGHT` (digits only). The original code passed any string straight to the shell; a value like `50%` or `200x200!` (valid ImageMagick geometry modifiers) that a legitimate caller might have sent will now be rejected. This is a narrowing of accepted input, traded for closing the injection - the application's own doc comment only shows the `WIDTHxHEIGHT` form, but any caller relying on ImageMagick's fuller geometry syntax (`%`, `^`, `!`, `<`, `>`, offsets) would see a behaviour change.
- `execFileSync` vs `execSync`: both are synchronous, both throw on a non-zero exit status, and neither's stdout/stderr was captured or used before or after the change - the caller-visible failure behaviour (an uncaught throw inside the route handler) is unchanged.
- `filename` (and therefore `sourcePath`/`thumbPath`) is unchanged and unvalidated by this fix; path traversal in `filename` is a separate weakness (CWE-22) outside this finding's scope and was not touched.
- Invoking `convert` by absolute path (`/usr/bin/convert`) assumes that is where ImageMagick is installed on the target host; this is the standard Linux package location but was not confirmed against the deployment environment - if `convert` lives elsewhere, this path needs adjusting.

## Verification

Ran `node --check` against the fixed file in a scratch location (not the shared fixture) - no syntax errors. Confirmed `execFileSync` is exported by Node's `child_process` module via `node -e "require('child_process').execFileSync"` (resolved to a function on Node v24.3.0, the environment's installed Node). No other new identifiers were introduced; `express`, `path`, and `child_process` usage otherwise match the original file.

Assumptions: `convert`'s install path was assumed to be `/usr/bin/convert` (not verifiable from the code alone); the accepted geometry format was narrowed to `WIDTHxHEIGHT` digits, matching the example in the code's own comment, rather than ImageMagick's full geometry grammar.
