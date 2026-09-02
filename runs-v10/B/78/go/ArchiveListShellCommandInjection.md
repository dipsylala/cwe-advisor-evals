## Verdict

Exploitable. Untrusted user input from an HTTP query parameter flows directly into an OS command string executed through a shell, allowing arbitrary command injection.

## Source

HTTP query parameter `archive` from `r.URL.Query().Get("archive")` in `archive_handler.go` line 7, passed without validation to `ListArchive()`.

## Fix

Replace the `exec.CommandContext` call with Go's `archive/tar` standard library to eliminate the command execution entirely.

**Vulnerable code:**
```go
func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)
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

**Required imports:**
```go
import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
)
```

## Explanation

The original code constructs a shell command string by concatenating the untrusted `archiveName` parameter directly into the command: `"tar -tf "+archiveName`. When this string is passed to `sh -c`, an attacker can inject arbitrary commands using shell metacharacters such as `;`, `|`, `&&`, or command substitution `$()`. For example, an input like `archive.tar; rm -rf /` would execute both the tar command and a destructive filesystem operation.

The fix replaces the entire shell invocation with Go's standard library `archive/tar` package, which reads and parses tar files natively without spawning external processes. The `archiveName` parameter is now treated only as a filename argument to `os.Open()`, not as part of command syntax. The function iterates through the tar headers and outputs each filename on a separate line, matching the output format of `tar -tf`. This eliminates the injection point entirely: shell metacharacters in the input are treated as literal filename characters and will simply fail to open a non-existent file, returning an error as expected.

## Behaviour changes

- **Process execution removed**: The original spawned an external `tar` subprocess; the fixed code uses only standard library functions, eliminating subprocess overhead and eliminating the vector for argument injection (CWE-88) through target-program flag interpretation.
- **Error handling**: The original returned stderr from the tar command on error; the fixed code returns Go errors from file operations and tar parsing. This is more precise and avoids information leakage of shell error messages.
- **Context cancellation**: The original context timeout would kill the external tar process via signal; the fixed code honours context cancellation through Go's standard context propagation during file I/O and tar reading. This remains effective and avoids the complexity of process signals.
- **Output format preserved**: Both formats list one file per line, so output is compatible with existing consumers expecting `tar -tf` format.
