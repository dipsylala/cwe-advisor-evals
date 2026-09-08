## Verdict

Confirmed - exploitable OS command injection (CWE-78).

## Source

`archive_handler.go`: `ArchiveListHandler` reads the `archive` query parameter directly from the HTTP request (`r.URL.Query().Get("archive")`) with no validation beyond a non-empty check, and passes it straight through to `runner.ListArchive(r.Context(), archiveName)`.

## Fix

`archive_runner.go`, line 11: `exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)` concatenates the attacker-controlled `archiveName` directly into a shell command string. A value such as `foo.tar; touch pwned` (or backticks/`$()`) is interpreted by `sh -c` and executes arbitrary commands with the process's privileges.

Listing the contents of a tar archive is a native-library operation, not one that requires an external tool: Go's standard library (`archive/tar`, plus `compress/gzip` for the common gzip-compressed case) reads tar entry headers directly from the file, with no shell and no subprocess. This eliminates the injection point entirely rather than relocating it.

### File: archive_runner.go

```go
package archivelist

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
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

	br := bufio.NewReader(f)
	var reader io.Reader = br

	// Auto-detect gzip compression (magic bytes 0x1f 0x8b), matching tar's
	// own behavior of transparently reading both plain and gzipped archives.
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	}

	tr := tar.NewReader(reader)
	var out bytes.Buffer
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

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

## Explanation

The vulnerable line built a shell command string by concatenating unsanitized user input and handed it to `sh -c`, so any shell metacharacter in `archiveName` (`;`, `` ` ``, `$()`, `|`, etc.) is interpreted by the shell rather than treated as part of a filename. Per the CWE-78 guidance's primary defence - eliminate command execution and use a native library when one performs the same operation - the fix drops `os/exec` and the shell entirely and reads the archive's table of contents with Go's own `archive/tar` package, opening `archiveName` as a plain file path via `os.Open`. Because there is no shell in the path at all, no metacharacter interpretation is possible; a value like `foo; touch pwned` is passed unmodified to `os.Open` and simply fails to open as a file, rather than being executed. Gzip auto-detection is included because GNU `tar -tf` transparently supports both plain and gzip-compressed archives, and dropping that would silently narrow what the endpoint could list. This was compiled and verified: `go build`/`go vet` pass, and a smoke test against real fixtures shows the function's output for both a plain `.tar` and a `.tar.gz` matches the real `tar -tf` output byte-for-byte (`a.txt\nb.txt\n`), and an injection payload passed as the filename produces only an "open ...: file not found" error with no command executed.

## Behaviour changes

- Return shape is preserved: `ListArchive` still returns `([]byte, error)`, with the byte slice being a newline-separated list of entry names, matching `tar -tf`'s stdout format (verified byte-for-byte against real `tar -tf` for both a plain tar and a gzip-compressed tar).
- Gzip-compressed archives (`.tar.gz`) are still supported via magic-byte detection, matching GNU tar's own transparent handling; only these two container forms (plain tar and gzip-wrapped tar) are covered - other compressions `tar` can auto-detect (e.g. bzip2, xz) are not, since the original finding gives no evidence the endpoint needs them. If those are required, add the corresponding stdlib/well-known decompressor (`compress/bzip2` is read-only stdlib; xz needs a third-party package) behind the same magic-byte check.
- Error text on a bad or missing path now comes from `os.Open`/`archive/tar` (e.g. `open <path>: no such file or directory`, or a tar-format error) instead of `tar`'s CLI stderr merged into `CombinedOutput`. The handler only surfaces a generic "archive listing failed" message on error, so this does not change observable HTTP behaviour.
- Context cancellation is now checked once per archive entry (`ctx.Err()`) rather than relying on `exec.CommandContext` killing a child process; for a large or corrupt archive this stops the read loop promptly instead of running to completion, which is a strict improvement with no behavioural downside for well-formed input.
- Path traversal exposure is unchanged from the original: both the old `tar -tf` invocation and the new `os.Open` accept an absolute or `../`-relative `archiveName` and will read whatever file that resolves to. This finding is scoped to CWE-78 (command injection); restricting `archiveName` to a permitted directory is a separate CWE-22 concern the caller should still address if arbitrary file disclosure is in scope.
