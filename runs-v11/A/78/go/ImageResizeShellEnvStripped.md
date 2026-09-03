## Verdict

Real vulnerability confirmed. The code passes unsanitized user input to a shell command, enabling OS command injection.

## Source

```go
func ResizeImage(inputPath, outputPath string) error {
	shellCmd := fmt.Sprintf("convert %s -resize 800x600 %s", inputPath, outputPath)
	cmd := exec.Command("sh", "-c", shellCmd)
	return cmd.Run()
}
```

`inputPath` and `outputPath` are attacker-controlled strings passed to `fmt.Sprintf()` and then executed via `sh -c`. An attacker can inject shell metacharacters (`;`, `|`, `$()`, backticks, `&&`, etc.) through either parameter to execute arbitrary commands on the system.

## Fix

```go
func ResizeImage(inputPath, outputPath string) error {
	cmd := exec.Command("convert", inputPath, "-resize", "800x600", outputPath)
	return cmd.Run()
}
```

Invoke the program directly using `exec.Command()` with arguments passed as separate parameters. Do not use `sh -c` to invoke a shell. This way, shell metacharacters in the input strings are treated as literal filename characters, not interpreted as shell syntax.

## Explanation

The vulnerability arises because `exec.Command("sh", "-c", shellCmd)` spawns a shell that parses and interprets the `shellCmd` string. If `inputPath` is `"image.jpg; rm -rf /"` or `"image.jpg$(malicious)"`, the shell will execute those embedded commands.

The fix avoids the shell entirely by passing `convert` and its arguments directly to `exec.Command()`. When `exec.Command()` is invoked without `-c`, it does not spawn an intermediate shell; arguments are passed directly to the target binary. This means shell metacharacters in filenames (like spaces, quotes, or semicolons) are preserved as literal characters and cannot be interpreted as commands.

This pattern applies broadly: whenever you need to invoke an external program with user-supplied arguments, pass the program name and arguments as separate items to `exec.Command()` rather than building a single string and passing it to a shell.
