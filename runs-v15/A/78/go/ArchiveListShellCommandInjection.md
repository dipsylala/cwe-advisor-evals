## Verdict

**Confirmed OS Command Injection (CWE-78)**. The `archiveName` parameter originates from untrusted user input (HTTP query parameter) and is concatenated directly into a shell command string without escaping or validation.

## Source

**Data Flow:**

1. `archive_handler.go:7` — User input enters via `r.URL.Query().Get("archive")`
2. `archive_handler.go:13` — Untrusted `archiveName` passed to `runner.ListArchive()`
3. `archive_runner.go:11` — Concatenated directly into shell command: `"sh", "-c", "tar -tf "+archiveName`

The shell interpreter (`sh -c`) will expand metacharacters like `;`, `|`, `$()`, and backticks in `archiveName`, allowing command injection.

## Fix

```go
func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "tar", "-tf", archiveName)
	return cmd.CombinedOutput()
}
```

**Key changes:**
- Remove `"sh", "-c"` shell invocation
- Pass `tar` and its arguments as separate strings to `exec.CommandContext()`
- The shell is bypassed entirely; `archiveName` is treated as a literal argument value, not shell syntax

## Explanation

The original code invokes a shell and concatenates user input into the command string. The shell parser interprets special characters in `archiveName` as operators (e.g., `archive.tar; rm -rf /` would execute two commands).

The fixed code uses an argument array. `exec.CommandContext()` passes arguments directly to `tar` without shell parsing. Special characters in `archiveName` are treated as literal parts of the filename argument, preventing injection.

This pattern—passing program arguments as separate array elements rather than concatenating them into a shell command—is the standard defense against command injection in Go and all other languages.
