## Verdict

exploitable

## Source

Parameters `inputPath` and `outputPath` to `ResizeImage()` function are untrusted strings controlled by the caller.

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

The original code builds a command string using `fmt.Sprintf` with untrusted `inputPath` and `outputPath` parameters, then executes it through a shell with `exec.Command("sh", "-c", shellCmd)`. This allows shell metacharacter injection: a path like `input.jpg; rm -rf /` would cause the shell to execute arbitrary commands after the image conversion.

The fix removes the shell invocation entirely by passing arguments directly to the `convert` command. When `exec.Command` receives a program name and separate arguments without a shell, it executes the program directly and passes the arguments as-is without any shell interpretation. The `inputPath` and `outputPath` are now treated as literal data, not as shell syntax, eliminating the injection point. The fix preserves the original behavior: it still calls ImageMagick's convert tool with the same arguments and returns the same error code.

## Behaviour changes

none
