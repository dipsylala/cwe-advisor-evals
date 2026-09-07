## Verdict

VULNERABLE - OS Command Injection via unescaped string concatenation in shell command.

## Source

The vulnerability exists in `archive_runner.go` line 11, where the `archiveName` parameter is directly concatenated into a shell command string without escaping or validation:

```go
cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)
```

The untrusted `archiveName` input comes from the HTTP query parameter via `archive_handler.go` line 7. Since the command is executed via `sh -c`, shell metacharacters in `archiveName` are interpreted, allowing an attacker to inject arbitrary commands. For example, an attacker could provide `archive.tar; rm -rf /` to execute deletion commands after the tar listing.

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

The fix eliminates shell invocation entirely. Instead of using `sh -c` with string concatenation, the `tar` command is invoked directly with `exec.CommandContext(ctx, "tar", "-tf", archiveName)`. 

By passing `archiveName` as a separate argument to `tar` (not through a shell), it is treated as a file path operand rather than being subject to shell parsing. Shell metacharacters and special characters in the archive name are no longer interpreted—they are passed literally to tar, which treats them as part of the filename. This prevents command injection while maintaining the intended functionality.

The `CombinedOutput()` method call remains unchanged and continues to return both stdout and stderr output.
