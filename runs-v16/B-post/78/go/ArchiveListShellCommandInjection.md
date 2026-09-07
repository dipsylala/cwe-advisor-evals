## Verdict

exploitable

## Source

`archiveName` parameter from HTTP query string (`archive_handler.go`, line 7: `r.URL.Query().Get("archive")`)

## Fix

**Vulnerable code:**
```go
func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)  // Injection point: archiveName concatenated into shell command
	return cmd.CombinedOutput()
}
```

**Fixed code:**
```go
import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
)

func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	f, err := os.Open(archiveName)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	var buf bytes.Buffer

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		buf.WriteString(hdr.Name)
		buf.WriteByte('\n')
	}

	return buf.Bytes(), nil
}
```

## Explanation

The vulnerability stems from passing untrusted `archiveName` directly into a shell command string via `"tar -tf "+archiveName`. An attacker can inject shell metacharacters (`;`, `|`, `&&`, backticks, `$()`) to execute arbitrary commands. The fix eliminates the shell invocation entirely by using Go's standard library `archive/tar` package to read and list tar archive contents directly. This preserves the method's contract—returning a byte slice of filenames, one per line, matching `tar -tf` output format—while closing the injection point. No external command execution occurs, removing the attack surface.

## Behaviour changes

- **Timeout via context**: The original code used `exec.CommandContext` to enforce a timeout. The fixed code preserves context cancellation checks inside the read loop (`ctx.Done()`), honoring the timeout but through manual polling rather than OS-level process termination.
- **Output format preserved**: Both produce the same output—file names from the archive, one per line.
- **Error handling**: The original returned combined stderr and stdout on success or an exec error on failure. The fixed code returns `tar.Reader` errors directly (file open, header read, etc.), which represent the same conditions (invalid archive, truncated file, etc.).
