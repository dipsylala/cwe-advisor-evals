## Verdict

OS command injection via shell metacharacter interpretation in the archive name parameter.

## Source

`ListArchive()` concatenates the user-supplied `archiveName` parameter directly into a shell command string passed to `sh -c`. An attacker can inject shell metacharacters or command substitution syntax to execute arbitrary commands.

Vulnerable line:
```go
cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)
```

## Fix

Remove the shell invocation and pass arguments directly to `tar`:

```go
func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "tar", "-tf", archiveName)
	return cmd.CombinedOutput()
}
```

## Explanation

The vulnerability exists because `exec.CommandContext(ctx, "sh", "-c", ...)` spawns a shell that interprets the third argument as shell code. String concatenation (`"tar -tf "+archiveName`) embeds the attacker-controlled value directly into that code, allowing shell metacharacters, command substitution (`$()`), and other shell syntax to execute.

The fix invokes `tar` directly without a shell. The `-tf` flag and archive name are passed as separate arguments to `exec.CommandContext()`, which passes them to the OS as literal strings without shell parsing. This prevents metacharacter interpretation entirely — an `archiveName` value of `"; rm -rf /"` is treated as a literal filename, not as shell syntax.
