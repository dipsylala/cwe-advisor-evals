## Verdict

Exploitable. Confidence: high. Location: ExecSyncTemplateLiteral.js:20

## Source

- **Primary source**: `req.params.filename` (line 13) - attacker-controlled URL parameter
- **Secondary source**: `req.body.geometry` (line 14) - attacker-controlled request body

Both are interpolated into the shell command string on line 20 without escaping.

Data flow:
1. `filename` from URL parameter → `path.join(UPLOAD_DIR, filename)` (line 16) → `sourcePath`
2. `geometry` from request body → direct interpolation (line 14)
3. Both interpolated into template literal on line 20: `execSync(\`convert ${sourcePath} -resize ${geometry} ${thumbPath}\`)`

## Fix

**Vulnerable code (line 20):**
```javascript
execSync(`convert ${sourcePath} -resize ${geometry} ${thumbPath}`);
```

**Fixed code:**
```javascript
const GEOMETRY_PATTERN = /^\d+x\d+$/;

if (!GEOMETRY_PATTERN.test(geometry)) {
  return res.status(400).json({ error: "Invalid geometry format" });
}

execFileSync("convert", [sourcePath, "-resize", geometry, thumbPath]);
```

## Explanation

The vulnerability exists because `execSync()` with a template literal string invokes a shell interpreter, which treats shell metacharacters (`;`, `|`, `&`, `$()`, backticks) as command separators. Even though `path.join()` normalizes path separators, it does not escape shell metacharacters, so an attacker could inject commands by including shell syntax in the filename or geometry parameters.

The fix replaces `execSync()` with `execFileSync()`, which passes the program name and arguments as separate array elements. This bypasses the shell entirely, preventing shell metacharacter injection. Additionally, input validation on the geometry parameter ensures it matches a safe format (digits, x character, digits) before reaching the command execution.

## Behaviour changes

- Changed from `execSync()` to `execFileSync()`: `execFileSync` does not invoke a shell and requires arguments as an array. Returns the same output as before (the stdout of the convert command), so caller behavior is unchanged.
- Arguments now passed as array instead of shell string: Same effect on the `convert` command; the binary receives identical individual arguments.
- Added geometry validation: Input validation is applied before command execution as a secondary defence layer. Invalid geometry values now return a 400 error response instead of being passed to the convert command, which could fail with a generic error or potentially have unexpected behavior.
- Import change: Requires `execFileSync` to be destructured from `child_process` module (already imported on line 3, just update the destructuring).
