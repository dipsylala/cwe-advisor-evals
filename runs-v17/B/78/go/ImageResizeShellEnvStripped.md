## Verdict

**VULNERABLE** - OS Command Injection via shell invocation with concatenated user input.

**Finding confirmed**: File paths passed as function arguments are concatenated into a shell command string and executed via `sh -c`. An attacker controlling `inputPath` or `outputPath` can inject shell metacharacters to execute arbitrary commands.

## Source

**File**: `resize.go`  
**Function**: `ResizeImage(inputPath, outputPath string)`  
**Data origin**: Function parameters (untrusted)

The `inputPath` and `outputPath` parameters are incorporated directly into a shell command string via `fmt.Sprintf` on line 9, then passed to a shell interpreter on line 12.

**Example attack**: 
- `ResizeImage("image.jpg; rm -rf /", "output.jpg")` → shell executes both the resize and the deletion

## Fix

### File: resize.go

```go
package imaging

import (
	"os/exec"
)

func ResizeImage(inputPath, outputPath string) error {
	// Pass arguments separately to exec.Command, eliminating shell invocation.
	// This treats inputPath and outputPath as literal arguments to convert,
	// not as shell syntax. Shell metacharacters in the paths are now safe.
	cmd := exec.Command("convert", inputPath, "-resize", "800x600", outputPath)
	return cmd.Run()
}
```

## Explanation

The fix eliminates shell invocation entirely by:

1. **Removing the shell interpreter**: Changed from `exec.Command("sh", "-c", shellCmd)` to `exec.Command("convert", ...)` directly. Go's `exec.Command` does not invoke a shell when given a command name and separate arguments.

2. **Passing arguments separately**: Split the command string into discrete arguments: `"convert"`, `inputPath`, `"-resize"`, `"800x600"`, `outputPath`. Each argument is passed as-is to the `convert` binary without reinterpretation by a shell.

3. **No concatenation**: Removed `fmt.Sprintf` string concatenation, eliminating the injection point entirely.

The fix follows the Go guidance which states: "Pass each argument as a separate `exec.Command` parameter; never build a single command string with `+` or `fmt.Sprintf`" and "Eliminate command execution first: replace with... or avoid shell invocation entirely."

**Sink contract preserved**: The fixed code still executes the `convert` command and returns the exit code via `cmd.Run()`, matching the original behavior. No output was being captured or returned originally, so no information is lost.

## Behaviour changes

**External behavior**: None. The `convert` command still executes with the same arguments and produces the same resized image file.

**Security behavior**: Shell metacharacters in file paths (e.g., `;`, `|`, `&&`, `$()`, backticks) are now treated as literal filename characters instead of shell syntax, blocking command injection.

**Implementation detail**: Removed the dependency on `fmt` package; `os/exec` is now the only import required.

**Verification**: The fix can be tested by passing paths with shell metacharacters:
- `ResizeImage("image.jpg;ls", "output.jpg")` → treated as literal filename `image.jpg;ls`, not executed as a command
- The `convert` command will either resize a file with that literal name or fail if the file doesn't exist, but will not execute `ls`
