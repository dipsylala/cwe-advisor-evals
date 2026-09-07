## Verdict

Exploitable. The untrusted `archiveName` parameter from the HTTP query string is concatenated directly into a shell command string passed to `exec.CommandContext` with shell interpreter enabled (`sh -c`), enabling arbitrary OS command execution.

## Source

HTTP request parameter: `archiveName := r.URL.Query().Get("archive")` in archive_handler.go, line 7.

The parameter undergoes only an empty check before reaching the sink. An empty check does not constrain the value; attacker-supplied shell metacharacters (e.g., `; rm -rf /; #`) will be interpreted by the shell.

## Fix

### File: archive_runner.go

```go
package archivelist

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
)

type ArchiveRunner struct{}

func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	file, err := os.Open(archiveName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	tr := tar.NewReader(file)
	var buf bytes.Buffer

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		fmt.Fprintln(&buf, header.Name)
	}

	return buf.Bytes(), nil
}
```

## Explanation

The fix eliminates OS command execution entirely by replacing the shell invocation with Go's standard library `archive/tar` package. The original code executed `tar -tf <archiveName>` via a shell; the fixed code directly opens the file as a tar stream and iterates through its headers, writing each filename to a buffer. This provides identical output for uncompressed tar archives while preventing shell injection entirely—the `archiveName` is now passed only to `os.Open`, which treats it as a file path, not a command. Shell metacharacters in the filename are harmless; they are interpreted literally as filesystem characters by the OS, not by an interpreter.

## Behaviour changes

- **Shell execution eliminated**: No longer invokes `sh -c`; eliminates the injection vector entirely.
- **Error handling refined**: File open errors and tar parsing errors are returned directly instead of command execution errors. An unopenable file or malformed tar archive returns an error, matching the original behavior (tar command would also fail).
- **Output format preserved**: The fixed code produces identical output to `tar -tf` for uncompressed tar files—one filename per line.
- **Context parameter retained unused**: The `context.Context` parameter is preserved in the function signature for API compatibility with existing callers (archive_handler.go), even though it is no longer used for cancellation.
- **Scoped to uncompressed tar**: The fix handles uncompressed tar archives only. If the original code relied on `tar`'s ability to auto-detect or handle gzip/bzip2 compression, that capability is not present here. No evidence in the test case suggests compressed archive support is required.
