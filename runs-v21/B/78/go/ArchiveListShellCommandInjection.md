## Verdict
Confirmed. Untrusted `archiveName` from HTTP query parameter is concatenated into a shell command executed via `sh -c`, allowing arbitrary command injection.

## Source
`archiveName` parameter from HTTP query string in `archive_handler.go` line 7:
```
archiveName := r.URL.Query().Get("archive")
```
Passed unsanitized to `ListArchive()` at line 13.

## Fix
Replace OS command execution with Go's native `archive/tar` library. The `tar -tf` command lists tar file contents; this operation is performed natively by the `archive/tar` package without invoking a shell.

### File: archive_runner.go
```go
package archivelist

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
)

type ArchiveRunner struct{}

func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	file, err := os.Open(archiveName)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}
	defer file.Close()

	var output []byte
	tr := tar.NewReader(file)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read archive: %w", err)
		}
		output = append(output, []byte(header.Name+"\n")...)
	}

	return output, nil
}
```

## Explanation
The fix eliminates the shell command execution entirely by using Go's `archive/tar` package to read the tar file directly. Instead of invoking `tar -tf` via shell, the code opens the archive file and iterates through its headers, collecting the file names (which is what `tar -tf` outputs). This removes the injection point completely—the untrusted `archiveName` is now passed only to `os.Open()`, which treats it as a file path, not as a shell command string. The output format matches the original command's behavior (one filename per line).

## Behaviour changes
The fixed code behaves identically to the original for valid archive files. Differences:
- Error messages are more structured (wrapped with context rather than generic command output)
- If `archiveName` contains shell metacharacters (e.g., `archive=test.tar; rm -rf /`), it is now treated as a literal file path and will fail to open, rather than executing the injected command
- The context parameter is no longer used for process timeouts but can be used in future enhancements (e.g., to cancel file I/O operations)
