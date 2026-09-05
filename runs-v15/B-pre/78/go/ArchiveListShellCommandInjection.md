## Verdict

Exploitable. The `archiveName` parameter is sourced from untrusted HTTP query input (`r.URL.Query().Get("archive")` in archive_handler.go line 7) and concatenated directly into a shell command string passed to `sh -c` on archive_runner.go line 11. An attacker can inject shell metacharacters or commands (e.g., `test.tar; rm -rf /`) that will be executed by the shell.

## Source

Untrusted HTTP query parameter `archive` (archive_handler.go, line 7: `r.URL.Query().Get("archive")`) flows directly into the `archiveName` function parameter and is concatenated into a shell command string without validation.

## Fix

**Vulnerable code:**
```go
func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)  // Injection point
	return cmd.CombinedOutput()
}
```

**Fixed code:**
```go
func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	file, err := os.Open(archiveName)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		output = append(output, []byte(header.Name+"\n")...)
	}

	return output, nil
}
```

Add imports:
```go
import (
	"archive/tar"
	"context"
	"io"
	"os"
)
```

## Explanation

The vulnerability is eliminated by replacing the shell invocation with Go's native `archive/tar` package, which reads tar file headers directly without spawning an external process. The fixed code opens the archive file using `os.Open()`, iterates through tar headers using `tar.NewReader`, and builds output matching the format of `tar -tf` (one filename per line). This approach removes the command injection sink entirely—there is no longer a shell to interpret metacharacters or injected commands. The function preserves the original contract: it returns the same byte-formatted listing that the caller expects, and error handling follows the same pattern (returning error for any failure in the chain).

## Behaviour changes

None. The fixed code returns identical output (archive contents as newline-separated filenames) and identical error handling to the original. File open errors and tar parsing errors are propagated in the same way. The removal of `exec.CommandContext` is a performance improvement (no process spawn) with no observable behavioral difference to the caller.
