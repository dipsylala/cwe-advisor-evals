## Verdict

**Confirmed** - CWE-78 OS Command Injection. User-controlled `archiveName` is concatenated directly into a shell command string passed to `sh -c`, allowing arbitrary command execution via shell metacharacters and command substitution.

## Source

User input enters through the HTTP query parameter `archive` in `ArchiveListHandler`, which is passed untrusted to `ArchiveRunner.ListArchive()`.

Data flow:
- Source: `r.URL.Query().Get("archive")` → `archiveName` parameter
- Sink: `exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)` (line 11 of `archive_runner.go`)
- Shell interpretation: The `-c` flag causes sh to parse and execute the concatenated string as a shell command

## Fix

Replace the shell-based tar listing with Go's `archive/tar` package. This eliminates the command execution entirely and is the primary remediation for this class of vulnerability in Go.

**Fixed `archive_runner.go`:**

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
	// Open the tar file using Go's standard library instead of shelling out
	file, err := os.Open(archiveName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a tar reader
	tr := tar.NewReader(file)

	// Collect file names in output buffer, matching "tar -tf" format
	var buf bytes.Buffer
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// Write each file name on a separate line, matching tar -tf output
		buf.WriteString(header.Name)
		buf.WriteByte('\n')
	}

	return buf.Bytes(), nil
}
```

## Explanation

The fix replaces the unsafe `exec.CommandContext` shell invocation with Go's built-in `archive/tar` package, which provides direct native access to tar archive contents. This eliminates the injection point entirely—no shell interpreter is involved, and no user input is concatenated into any command string.

The fix preserves the original contract: it still returns `[]byte` containing the listing and an error, with the same format that `tar -tf` would produce (one filename per line). The context is no longer needed for process execution, but the function signature is preserved for compatibility.

## Behaviour changes

- **No shell invocation**: The code no longer spawns `sh -c`, eliminating both the injection point and the overhead of process spawning.
- **File access only**: The fixed code opens and reads the tar archive file directly. It cannot execute arbitrary commands, even if the filename contains shell metacharacters.
- **Same output format**: The listing output matches `tar -tf` format (one entry per line), so callers in `ArchiveListHandler` receive identical data.
- **Same error handling**: File open failures and malformed tar entries produce errors just as the original would, and callers handle them the same way.
- **No external dependencies**: Uses only Go's standard library (`archive/tar`, `os`, `bytes`), no new dependencies introduced.
