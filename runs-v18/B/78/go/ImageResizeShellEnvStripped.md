## Verdict

Exploitable.

## Source

The `inputPath` and `outputPath` parameters passed to `ResizeImage()` at line 8 are attacker-controlled.

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

The original code invoked a shell (`sh -c`) with a concatenated command string built from user-supplied file paths. This allows attackers to inject arbitrary shell metacharacters and commands. For example, passing `inputPath = "image.jpg; rm -rf /"` would execute destructive commands. The fix removes the shell invocation entirely and passes each argument—the command name, input path, resize parameters, and output path—as separate arguments to `exec.Command()`. Without shell interpretation, metacharacters in the file paths are treated as literal data, not command syntax. The fix preserves the function's original behavior: executing the `convert` utility with the specified arguments.

## Behaviour changes

None. The command executed, its arguments, and its return value remain unchanged. The only difference is the removal of shell interpretation, which eliminates the injection point without altering the sink contract.
