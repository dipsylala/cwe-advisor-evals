## Verdict

The vulnerability is confirmed. The `archiveName` parameter from the HTTP query string is directly concatenated into a shell command without any escaping or validation, enabling OS command injection.

## Source

**Call chain:**
1. `ArchiveListHandler` (archive_handler.go:7): Receives user input via `r.URL.Query().Get("archive")`
2. Passes `archiveName` to `runner.ListArchive()` (archive_handler.go:13)
3. `ListArchive` (archive_runner.go:11): Concatenates `archiveName` into shell command string: `"tar -tf "+archiveName`

**Vulnerable code (archive_runner.go:11):**
```
cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)
```

An attacker can inject shell metacharacters (e.g., `test.tar; rm -rf /`) to execute arbitrary OS commands.

## Fix

### File: archive_runner.go

```go
package archivelist

import (
	"context"
	"os/exec"
)

type ArchiveRunner struct{}

func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "tar", "-tf", archiveName)
	return cmd.CombinedOutput()
}
```

## Explanation

The fix removes the shell invocation entirely. Instead of using `exec.CommandContext(ctx, "sh", "-c", ...)` with a concatenated command string, the corrected code passes the tar command and archive name as separate arguments:

```
cmd := exec.CommandContext(ctx, "tar", "-tf", archiveName)
```

This uses the argument array form of `exec.CommandContext`, where each argument is treated literally and not interpreted as shell code. The `archiveName` parameter is now passed as a direct argument to `tar`, preventing shell metacharacter injection. An attacker can no longer inject commands via special characters like `;`, `|`, `&`, or others—the value is treated as a filename literal that tar receives.

This is the primary and preferred defense for command injection in Go: invoke the target program directly without a shell interpreter, eliminating the shell parsing attack surface entirely.
