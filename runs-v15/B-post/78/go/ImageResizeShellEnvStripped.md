## Verdict

Confirmed true positive. The code passes untrusted filepath arguments into a shell-invoked command string, enabling OS command injection.

## Source

```go
// Vulnerable code at evals/cases/78/go/ImageResizeShellEnvStripped/resize.go:8-13
func ResizeImage(inputPath, outputPath string) error {
	shellCmd := fmt.Sprintf("convert %s -resize 800x600 %s", inputPath, outputPath)

	// SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
	cmd := exec.Command("sh", "-c", shellCmd)
	return cmd.Run()
}
```

Untrusted `inputPath` and `outputPath` parameters are concatenated into a shell command string via `fmt.Sprintf`, then executed by invoking `sh -c`. An attacker controlling either filepath can inject shell metacharacters to execute arbitrary commands.

## Fix

```go
package imaging

import (
	"os/exec"
)

func ResizeImage(inputPath, outputPath string) error {
	// Pass each argument as a separate parameter; eliminate shell invocation
	cmd := exec.Command("convert", inputPath, "-resize", "800x600", outputPath)
	return cmd.Run()
}
```

## Explanation

The fix removes the shell invocation entirely. Instead of building a single concatenated command string and passing it to `sh -c`, the arguments are passed as separate parameters to `exec.Command`. When invoked without a shell (`sh`, `-c`), `exec.Command` treats each argument literally — shell metacharacters in `inputPath` or `outputPath` are passed as literal argument data to the `convert` process, not interpreted as command syntax. This prevents injection while preserving the original behaviour: the same `convert` command runs with the same four arguments (`inputPath`, `"-resize"`, `"800x600"`, `outputPath`), and `cmd.Run()` returns the same error or nil result to the caller.

## Behaviour changes

None. The fixed code invokes the same external command (`convert`) with the same arguments. Output handling, error returns, and program flow are identical.
