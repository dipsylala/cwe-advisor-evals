## Verdict

CWE-78 (OS Command Injection) - **exploitable**. Confidence: high.

`ArchiveListHandler` reads the `archive` query parameter directly from an incoming HTTP request and passes it, unvalidated, into `ArchiveRunner.ListArchive`, which concatenates it into a shell command string executed via `sh -c`. Nothing on this path constrains, escapes, or allowlists the value before it reaches the shell.

## Source

- **Source**: `r.URL.Query().Get("archive")` in `ArchiveListHandler` (archive_handler.go:7) - fully attacker-controlled via the HTTP query string, checked only for emptiness (archive_handler.go:8) before use.
- **Flow**: `archiveName` is passed unmodified into `runner.ListArchive(r.Context(), archiveName)` (archive_handler.go:13).
- **Sink**: `exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)` in `ArchiveRunner.ListArchive` (archive_runner.go:11). The value is string-concatenated into a shell command line executed via `sh -c`, so shell metacharacters in `archiveName` (e.g. `; rm -rf /`, `$(...)`, backticks, `|`) are interpreted by the shell rather than treated as a literal filename.

## Fix

Vulnerable code (archive_runner.go):

```go
package archivelist

import (
	"context"
	"os/exec"
)

type ArchiveRunner struct{}

func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)
	return cmd.CombinedOutput()
}
```

Fixed code (archive_runner.go):

```go
package archivelist

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
)

type ArchiveRunner struct{}

func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	f, err := os.Open(archiveName)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out bytes.Buffer
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		out.WriteString(hdr.Name)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}
```

`ArchiveListHandler` (archive_handler.go) is unchanged - `ListArchive`'s signature and error-handling contract are preserved, so the caller needs no edit.

## Explanation

Listing the contents of a tar archive is incidental to the endpoint's purpose: Go's standard library reads tar archives natively, so shelling out to `tar -tf` was never necessary. The fix follows the CWE-78 Go guidance's primary remediation - eliminate command execution entirely rather than trying to sanitize or allowlist the filename - by opening the archive with `os.Open` and enumerating its entries with `archive/tar.Reader`, writing each entry name followed by a newline into a buffer that is returned exactly as `cmd.CombinedOutput()` was before. Because no shell is invoked and `archiveName` is used only as a filesystem path passed to `os.Open` (not concatenated into any interpreted command string), shell metacharacters in the value no longer have any special meaning - the injection sink is removed rather than defended.

## Behaviour changes

- **Output composition**: the original used `CombinedOutput()`, which interleaves the external `tar` process's stdout and stderr into the returned bytes; on a partially-corrupt or warning-producing archive this could mix diagnostic text from `tar` in with entry names. The fixed version returns only entry names (or an error) - it can no longer produce that mixed/garbled output. This is a byproduct of removing the external process, not an independent change.
- **Concurrency/timeout semantics**: the original used `exec.CommandContext(ctx, ...)`, so cancelling `ctx` (e.g. client disconnect) would terminate the running `tar` process. The fixed version performs in-process reads and does not check `ctx` for cancellation, so an in-flight read of a very large or slow-to-read archive will not be interrupted by context cancellation the way the shelled-out version was. If bounding read time under cancellation matters for this endpoint, wrap the loop with a `ctx.Done()` check.
- **Error granularity**: both versions return a non-nil `error` on failure, which the handler already maps to a generic 500 ("archive listing failed") without inspecting the error - so this does not change caller-visible behaviour, only the internal error type (`*fs.PathError` / `tar` parse errors vs. an `exec.ExitError`-style failure).
- Everything else - the function signature, the `[]byte, error` return contract, and the handler's use of it - is unchanged.

**Assumption**: `archiveName` refers to an uncompressed tar file (the original invoked plain `tar -tf`, not `tar -tzf`), so `archive/tar.NewReader` is used directly without a gzip decompression layer. If archives may also be gzip-compressed in practice, wrap `f` with `compress/gzip` before passing it to `tar.NewReader`. This fix addresses CWE-78 only; the archive path is still taken directly from user input and used as a filesystem path, which is a path-traversal (CWE-22) concern outside this finding's scope and unchanged in risk from the original code.
