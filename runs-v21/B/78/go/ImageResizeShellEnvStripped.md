## Verdict

CONFIRMED. OS command injection via shell string concatenation.

## Source

Function parameters `inputPath` and `outputPath` reach the shell command string via `fmt.Sprintf` at line 9, then to `exec.Command("sh", "-c", shellCmd)` at line 12. An attacker controlling either parameter can inject shell metacharacters and arbitrary commands.

Example: passing `inputPath = "image.jpg; rm -rf /"` causes the shell to execute the deletion command.

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

The fix eliminates the shell invocation entirely. Instead of building a single command string and passing it to `sh -c`, the arguments are passed separately as individual parameters to `exec.Command`. This prevents the shell from interpreting metacharacters in the input paths—they are treated as literal argument data, not command syntax. The fix preserves the same functionality (same `convert` command with the same arguments) and the same return type and error behavior.

## Behaviour changes

None. The command line executed is identical; only the execution mechanism changes from shell string interpretation to direct argument passing. This is a pure security fix that closes the injection point without altering what the code does.
