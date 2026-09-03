## Verdict

**Vulnerable.** The code constructs a shell command string by interpolating unsanitized filepath arguments into a format string, then passes it to `sh -c`. An attacker controlling either `inputPath` or `outputPath` can inject shell metacharacters and arbitrary commands.

## Source

Line 12 in `resize.go`:
```go
cmd := exec.Command("sh", "-c", shellCmd)
```

Where `shellCmd` is built at line 9 from user-supplied paths without escaping:
```go
shellCmd := fmt.Sprintf("convert %s -resize 800x600 %s", inputPath, outputPath)
```

## Fix

Replace the shell-based invocation with a direct argument array:

```go
func ResizeImage(inputPath, outputPath string) error {
	cmd := exec.Command("convert", inputPath, "-resize", "800x600", outputPath)
	return cmd.Run()
}
```

## Explanation

Passing arguments directly to `exec.Command` as separate string arguments prevents shell interpretation entirely. The operating system passes each argument to the `convert` program unchanged, without parsing for metacharacters like `;`, `|`, `$()`, or backticks. Even if `inputPath` contains `image.jpg; rm -rf /`, it reaches `convert` as a single literal filename argument, not as two separate commands.

The original code's use of `sh -c` forces the shell to parse the command string, treating special characters as operators. This is the core problem: once user input enters a shell command string via string interpolation, the attacker controls the shell grammar.

The fix eliminates the parser entirely—no shell is invoked, only the `convert` binary with the arguments passed safely at the OS level.
