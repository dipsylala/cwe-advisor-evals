## Verdict

Exploitable. The `archiveName` parameter from the HTTP query string flows directly into a shell command via string concatenation, allowing arbitrary OS command injection. An attacker can inject shell metacharacters (`;`, `|`, `$()`, etc.) to execute arbitrary commands on the host.

## Source

HTTP query parameter `archive` (via `r.URL.Query().Get("archive")` in `archive_handler.go`), passed unsanitized to `ListArchive()` and used in shell command construction at line 11 of `archive_runner.go`.

## Fix

**Vulnerable code:**

```go
func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName) // ← shell injection point
	return cmd.CombinedOutput()
}
```

**Fixed code:**

```go
import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
)

func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	file, err := os.Open(archiveName)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}
	defer file.Close()

	tr := tar.NewReader(file)
	var buf bytes.Buffer
	
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read archive: %w", err)
		}
		buf.WriteString(hdr.Name + "\n")
	}
	
	return buf.Bytes(), nil
}
```

## Explanation

The primary remediation for OS command injection where the command is incidental is to eliminate system command execution entirely by using language-native library alternatives. Go's `archive/tar` standard library package provides native tar file reading without invoking the shell. This replacement removes the shell invocation and injection point entirely: the archive name is now used only as a file path argument to `os.Open()`, which does not interpret shell metacharacters. The output format remains the same as `tar -tf` (newline-separated file paths), preserving the contract expected by the handler.

## Behaviour changes

Error handling changes: the original code returned combined stdout/stderr from the `tar` command; the fixed code returns errors from Go library calls with `fmt.Errorf` wrapping. File open errors are now distinguishable from tar read errors. Return values are the same (bytes and error), and the output data format (one filename per line) remains identical.
