## Verdict

Confirmed. Line 12 constructs an OS command by concatenating untrusted parameters `inputPath` and `outputPath` into a shell command string via `fmt.Sprintf`, then invokes a shell interpreter (`sh -c`) to execute it. An attacker controlling either parameter can inject shell metacharacters and execute arbitrary commands.

## Source

User-supplied `inputPath` and `outputPath` parameters reach the sink via `fmt.Sprintf` at line 9 and are embedded into a shell command string passed to `exec.Command("sh", "-c", ...)` at line 12.

## Fix

**Vulnerable code:**
```go
func ResizeImage(inputPath, outputPath string) error {
	shellCmd := fmt.Sprintf("convert %s -resize 800x600 %s", inputPath, outputPath)
	
	// SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
	cmd := exec.Command("sh", "-c", shellCmd)
	return cmd.Run()
}
```

**Fixed code:**
```go
func ResizeImage(inputPath, outputPath string) error {
	cmd := exec.Command("convert", inputPath, "-resize", "800x600", outputPath)
	return cmd.Run()
}
```

## Explanation

The fix eliminates the shell interpreter entirely and passes each argument as a separate parameter to `exec.Command`. The `convert` command from ImageMagick no longer runs through `sh -c`, so shell metacharacters in `inputPath` or `outputPath` are treated as literal data, not command syntax. This removes the injection point while preserving the original command's behavior and return value. The `os/exec` package does not invoke a shell when given a command and separate arguments, and separate argument arrays prevent shell-level metacharacter interpretation.

## Behaviour changes

None. The command line passed to the `convert` executable is semantically identical to the shell-evaluated version; only the execution method changes. File I/O, exit codes, and stdout/stderr routing remain unchanged. The absence of a shell means environment variable expansion and globbing no longer occur on the arguments—this is the intended security improvement and reflects how the tool is meant to be invoked when arguments come from untrusted sources.
