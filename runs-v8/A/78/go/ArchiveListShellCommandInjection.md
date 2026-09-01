## Verdict
Confirmed OS Command Injection (CWE-78) at archive_runner.go line 11.

## Source
The `archiveName` parameter originates from untrusted user input in archive_handler.go via the HTTP query parameter `r.URL.Query().Get("archive")` (line 7) and flows directly to the vulnerable sink without validation or sanitization.

## Fix
Replace the shell-invoked command construction with direct argument passing to avoid shell interpretation:

```go
func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "tar", "-tf", archiveName)
	return cmd.CombinedOutput()
}
```

Change from `exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)` to `exec.CommandContext(ctx, "tar", "-tf", archiveName)`. This passes tar and the archive name as separate arguments, eliminating shell parsing entirely and preventing metacharacter injection.

## Explanation
The original code invokes `/bin/sh -c` with a concatenated string containing user-supplied input, which allows shell metacharacter injection. An attacker can inject commands by providing input like `archive.tar; malicious-command`. By passing the archive name as a direct argument to `tar` rather than through shell concatenation, the argument is treated as a literal filename regardless of special characters. The tar command interprets it as a filename operand, not as shell syntax. This is the standard Go pattern for executing external commands safely: separate trusted program paths from untrusted data using argument arrays rather than shell strings.
