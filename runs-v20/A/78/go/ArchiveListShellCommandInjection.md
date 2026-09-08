## Verdict

Confirmed. `ArchiveRunner.ListArchive` builds a shell command line by string-concatenating an attacker-controlled value and executes it via `sh -c`, allowing arbitrary command execution through shell metacharacters (e.g. `; rm -rf /`, backticks, `$(...)`).

## Source

`archive_handler.go`, `ArchiveListHandler`: `archiveName := r.URL.Query().Get("archive")` reads the untrusted value directly from the HTTP request query string with no validation, then passes it to `runner.ListArchive(r.Context(), archiveName)`.

## Fix

### File: archive_runner.go
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
	cleaned := filepath.Clean(archiveName)
	if cleaned != archiveName || strings.HasPrefix(cleaned, "..") || strings.HasPrefix(cleaned, "-") {
		return nil, errors.New("invalid archive name")
	}

	cmd := exec.CommandContext(ctx, "tar", "-tf", cleaned)
	return cmd.CombinedOutput()
}
```

## Explanation

The sink at line 11 of the original file interpolated `archiveName` straight into a shell command string executed by `sh -c`, so any shell metacharacter in the request's `archive` query parameter (`;`, `|`, `` ` ``, `$()`, `&&`, etc.) is interpreted by the shell rather than treated as part of a filename. This gives a remote, unauthenticated caller arbitrary command execution with the privileges of the server process.

The fix removes the shell entirely: `exec.CommandContext` now invokes the `tar` binary directly with `-tf` and the archive name passed as a separate argument in the argument array (`cmd.Args`), so the OS executes `tar` with literal argv entries and no shell ever parses the string for metacharacters, `;`, backticks, or subshells. This closes the injection at its root rather than trying to escape or blocklist characters.

An argument array alone does not stop the value being read as a command-line flag or a path-traversal target once it reaches `tar`, since `archiveName` is still attacker-controlled input reaching a system utility. As defense in depth, the fix rejects any value that is not already in canonical form via `filepath.Clean` (blocking `..` traversal segments and redundant path elements) and rejects any value beginning with `-` (blocking flag/option injection into `tar`), returning an error instead of invoking the command. Legitimate archive names and relative sub-paths are unaffected since `filepath.Clean` is a no-op on an already-clean relative path.

To verify: a request with `archive=test.tar` (a real archive on disk) should list its contents unchanged; a request with `archive=test.tar; id` or `archive=$(id)` should now be passed to `tar` as a single, nonexistent filename (producing a tar error, not command execution) instead of running `id`; a request with `archive=--checkpoint=1` or `archive=../../etc/passwd` should be rejected with "invalid archive name" before `exec.CommandContext` is ever called.
