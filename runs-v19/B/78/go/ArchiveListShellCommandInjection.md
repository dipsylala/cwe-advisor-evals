## Verdict

Confirmed exploitable. The `archiveName` parameter from an HTTP query string is concatenated directly into a shell command without escaping.

## Source

**archive_handler.go:7** — untrusted filename from HTTP request query parameter:
```
archiveName := r.URL.Query().Get("archive")
```

**archive_runner.go:11** — shell invocation with concatenated string:
```
cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)
```

An attacker can inject shell metacharacters in the `archive` query parameter (e.g., `?archive=file.tar;rm+-rf+/` or `?archive=file.tar$(malicious)`) to execute arbitrary commands.

## Fix

### File: archive_runner.go

```go
package archivelist

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
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
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}
		fmt.Fprintln(&buf, header.Name)
	}

	return buf.Bytes(), nil
}
```

## Explanation

Replaced the shell invocation (`sh -c tar -tf`) with Go's built-in `archive/tar` library. The fix:

1. Opens the tar file using `os.Open()`, which does not interpret shell metacharacters
2. Creates a `tar.Reader` to parse the tar archive structure
3. Iterates through tar headers and writes each filename to a buffer, producing the same format as `tar -tf` (one filename per line)
4. Returns the buffer contents as bytes, matching the original contract

This eliminates the shell injection point entirely. The filename is now treated as a literal file path, not a shell command component. Shell metacharacters in the filename are no longer interpreted—they become literal characters in the filename to open, which fails gracefully if the file doesn't exist.

## Behaviour changes

- **Output format preserved**: The fixed code produces the same output as `tar -tf` (filenames, one per line)
- **Error handling**: File-not-found errors are now from `os.Open()` instead of `tar` command exit codes, but both return an error to the caller consistently
- **Return type unchanged**: Still returns `[]byte` with combined stdout/stderr-equivalent
- **Context handling**: The context parameter is no longer used directly by `exec.CommandContext` but remains in the function signature for future deadline/cancellation support
- **No shell dependencies**: The fixed code requires only Go standard library (`archive/tar`, `os`, `bytes`, `fmt`)
