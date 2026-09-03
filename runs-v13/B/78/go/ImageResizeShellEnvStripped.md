## Verdict

Exploitable

## Source

Function parameters `inputPath` and `outputPath` are unsanitized. They are passed to line 9's `fmt.Sprintf` call that constructs a shell command string, then to the shell interpreter via `exec.Command("sh", "-c", ...)` at line 12.

## Fix

**Vulnerable code:**
```go
shellCmd := fmt.Sprintf("convert %s -resize 800x600 %s", inputPath, outputPath)
cmd := exec.Command("sh", "-c", shellCmd)
```

**Fixed code:**
```go
cmd := exec.Command("convert", inputPath, "-resize", "800x600", outputPath)
```

## Explanation

The vulnerability exists because `exec.Command("sh", "-c", ...)` invokes a shell interpreter that parses the concatenated command string as shell syntax. Shell metacharacters in `inputPath` or `outputPath` (such as `;`, `|`, `$()`, or backticks) are interpreted as command operators rather than literal argument data, allowing arbitrary command execution. The fix eliminates the shell invocation by passing the external program name and each argument as separate `exec.Command` parameters. This prevents the shell parser from ever seeing or interpreting the user-controlled input values.

## Behaviour changes

The function's return value, error handling, and command output behavior are unchanged. The fix only removes the intermediate shell invocation and switches from a single concatenated command string to separate arguments. The `convert` program receives its arguments directly, which is the intended behavior for the original code.
