## Verdict

Exploitable

## Source

The `archiveName` parameter originates from the HTTP query string (`r.URL.Query().Get("archive")` in archive_handler.go), which is attacker-controlled.

## Fix

**Vulnerable code** (archive_runner.go, line 11):

```go
func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)  // INJECTION POINT
	return cmd.CombinedOutput()
}
```

**Fixed code** (archive_runner.go):

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
	file, err := os.Open(archiveName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var output bytes.Buffer
	tr := tar.NewReader(file)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		output.WriteString(header.Name + "\n")
	}

	return output.Bytes(), nil
}
```

## Explanation

The original code invokes a shell interpreter (`sh -c`) with a concatenated command string built from untrusted user input. This is the canonical OS command injection pattern. The fix eliminates shell execution entirely by replacing it with Go's native `archive/tar` standard library, which reads tar archive headers directly without spawning any external process. The function now opens the file, iterates through tar headers, and builds the same output (filename listing) that `tar -tf` would produce, but as native Go code that cannot be exploited for command injection. This approach follows the primary remediation guidance: eliminate OS command execution completely by using language-native library alternatives.

## Behaviour changes

The fixed code opens and reads the file directly instead of spawning a process. The original behavior of combining stdout and stderr is replaced by either returning the file listing successfully or returning an error separately (cleaner error handling). For uncompressed tar archives, the output format is identical to `tar -tf`. If the original code was required to handle gzip-compressed archives (`.tar.gz`), additional decompression logic using Go's `compress/gzip` would need to be added, but this is not evident from the current code path.
