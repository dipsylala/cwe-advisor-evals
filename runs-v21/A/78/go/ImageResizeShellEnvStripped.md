## Verdict

CONFIRMED - OS Command Injection via shell string interpolation at line 12.

## Source

The vulnerability occurs because `inputPath` and `outputPath` parameters are interpolated directly into a shell command string that is passed to `exec.Command("sh", "-c", shellCmd)`. An attacker controlling either parameter can inject shell metacharacters to execute arbitrary commands.

Example attack: if `inputPath` is `"; rm -rf / #"`, the command executed becomes `sh -c "convert ; rm -rf / # -resize 800x600 ..."`, which interprets the semicolon as a command separator and executes the injected `rm` command.

## Fix

### File: resize.go

```go
package imaging

import (
	"os/exec"
)

func ResizeImage(inputPath, outputPath string) error {
	cmd := exec.Command("convert", inputPath, "-resize", "800x600", outputPath)
	return cmd.Run()
}
```

## Explanation

The fix eliminates the shell interpreter by passing arguments directly to `exec.Command()` as separate parameters instead of building a shell command string. When `exec.Command("convert", inputPath, "-resize", "800x600", outputPath)` is invoked, each argument is passed to the `convert` program without shell processing. Special characters in `inputPath` and `outputPath` are treated as literal argument values, not shell syntax. This is the idiomatic Go approach to prevent command injection: use an argument array, not a shell string.

The `fmt.Sprintf` and the `"sh", "-c"` pattern are both removed because they are the injection vector. The tool's argument parsing happens at the program level, not the shell level, preventing interpretation of metacharacters.
