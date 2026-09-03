## Verdict
The vulnerability is confirmed. Line 20 passes unsanitized user-controlled input directly into a shell command via template literal.

## Source
Line 20: `execSync(\`convert ${sourcePath} -resize ${geometry} ${thumbPath}\`);`

- `sourcePath` is derived from `req.params.filename` at line 13 (user-controlled)
- `geometry` is derived from `req.body.geometry` at line 14 (user-controlled)
- Both are interpolated directly into the command string without escaping or validation
- An attacker can inject shell metacharacters or shell commands through either parameter

## Fix
Replace `execSync` with `spawnSync` and pass the command and arguments as an array instead of a shell string:

```javascript
const { spawnSync } = require("child_process");

// Replace line 20 with:
spawnSync("convert", [sourcePath, "-resize", geometry, thumbPath], {
  stdio: "inherit"
});
```

This approach:
1. Uses `spawnSync` instead of `execSync` to avoid shell interpretation
2. Passes the convert command and all arguments as an array, preventing the shell from parsing metacharacters or command separators in the user-controlled values
3. Sets `stdio: "inherit"` to maintain similar output behavior to the original `execSync` call

## Explanation
OS command injection occurs when user input is concatenated into a shell command and executed. The template literal at line 20 constructs a string that the shell parses; special characters in `filename` or `geometry` (e.g., semicolons, pipes, backticks) become shell operators rather than literal characters.

By using `spawnSync` with arguments passed as an array and without shell interpretation, each argument—including `sourcePath` and `geometry`—is passed directly to the `convert` process as operands. The shell does not re-parse them, so a value like `image.jpg; rm -rf /` is treated as a single argument to convert, not as two separate commands.
