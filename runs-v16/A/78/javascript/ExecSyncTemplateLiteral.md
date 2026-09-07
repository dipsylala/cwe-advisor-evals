## Verdict
Confirmed OS command injection via user-controlled template literal interpolation into shell command string.

## Source
- `req.params.filename` → line 13, used to construct `sourcePath` (line 16) and `thumbPath` (line 17)
- `req.body.geometry` → line 14, used in command string (line 20)
- Both user-supplied values are interpolated into the shell command at line 20 without escaping

Attack example: filename `image.jpg; rm -rf /` produces the command `convert /var/data/uploads/image.jpg; rm -rf / -resize 200x200 /var/data/thumbnails/thumb-image.jpg; rm -rf /`, executing arbitrary commands via shell metacharacter injection.

## Fix
Replace the template-literal shell string with an argument array. Instead of `execSync(`convert ${sourcePath} -resize ${geometry} ${thumbPath}`)`, use `execSync("convert", [sourcePath, "-resize", geometry, thumbPath])`.

The key change: pass the command and arguments separately as an array to `execSync()`. The array form passes arguments directly to the `convert` process without shell interpretation, preventing metacharacter injection.

## Explanation
When `execSync` receives a shell string (template literal), the operating system's shell interprets special characters (`; | & $ ( ) \`` etc.) as control operators. By passing arguments as an array, each argument is passed directly to the `convert` process without shell interpretation, neutralizing command injection.

The fix maintains the same behavior (calling ImageMagick's `convert` command) while eliminating the injection sink. Path traversal via `filename` (e.g., `../../../etc/passwd`) is a separate concern not addressed by this fix; that requires additional validation of `filename` against directory escape (e.g., `path.normalize()` + checking that the result stays within `UPLOAD_DIR`).
