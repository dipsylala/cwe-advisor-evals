## Verdict
True Positive: OS Command Injection via shell command string concatenation.

## Source
`ArchiveListHandler` receives untrusted user input (`archiveName`) from HTTP query parameters on line 7 of `archive_handler.go` and passes it to `ListArchive()` without validation.

## Fix
Replace the shell-command string concatenation with an argument array:

```go
func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "tar", "-tf", archiveName)
	return cmd.CombinedOutput()
}
```

## Explanation
The vulnerable code constructs a shell command by concatenating `archiveName` directly into a string: `"tar -tf "+archiveName`. When passed to `exec.CommandContext` with `"sh"` and `"-c"`, the shell interprets metacharacters in `archiveName` (e.g., `; rm -rf /`), allowing arbitrary command injection.

The fix removes the shell invocation and passes `tar` and its arguments separately via the argument array. Go's `exec` package treats each array element as a literal argument to `tar`, preventing the shell from interpreting metacharacters in `archiveName`.
