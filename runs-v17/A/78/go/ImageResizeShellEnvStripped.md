## Verdict

**VULNERABLE**: The code constructs a shell command with unescaped user-supplied arguments and passes it to a shell interpreter via `exec.Command("sh", "-c", shellCmd)`. An attacker controlling `inputPath` or `outputPath` can inject arbitrary shell commands.

## Source

Line 12 executes a shell command built from unescaped user input:
```
cmd := exec.Command("sh", "-c", shellCmd)
```

The command string (line 9) includes `inputPath` and `outputPath` without escaping:
```
shellCmd := fmt.Sprintf("convert %s -resize 800x600 %s", inputPath, outputPath)
```

An input like `"; rm -rf /; echo "` would result in execution of the rm command.

## Fix

### File: resize.go

```go
package imaging

import (
	"os/exec"
)

func ResizeImage(inputPath, outputPath string) error {
	// Invoke convert directly with arguments, avoiding shell interpretation
	cmd := exec.Command("convert", inputPath, "-resize", "800x600", outputPath)
	return cmd.Run()
}
```

## Explanation

The fix eliminates the shell interpreter entirely by invoking the `convert` tool directly with separate arguments. When `exec.Command` is called with the program name followed by individual arguments (not a shell command string), the operating system passes those arguments directly to the target process without any shell metacharacter expansion or interpretation. Each argument becomes a literal value to the convert tool, making it impossible to inject shell commands through the input paths.

This is the primary defence against OS command injection in Go: avoid the shell when possible by using `exec.Command` with separate arguments instead of `exec.Command("sh", "-c", ...)`.
