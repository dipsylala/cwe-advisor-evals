## Verdict

Exploitable

## Source

`header.Filename` from HTTP multipart upload in `UploadAvatar` handler (line 13)

## Fix

**Vulnerable code (line 27 in avatar_upload.go):**
```go
os.WriteFile(filepath.Join(storageDir, header.Filename), bytes, 0o600)
```

**Fixed code:**
```go
package avatars

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const storageDir = "/var/app-data/avatars"

// contentTypeMap maps detected content types to safe file extensions
var contentTypeMap = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func UploadAvatar(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read the first 512 bytes to detect the real content type
	sniffBuf := make([]byte, 512)
	n, err := file.Read(sniffBuf)
	if err != nil && err != io.EOF {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}

	// Detect the actual content type based on file content
	detectedType := http.DetectContentType(sniffBuf[:n])

	// Validate against allowlist of permitted types
	ext, allowed := contentTypeMap[detectedType]
	if !allowed {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Generate a random filename instead of using header.Filename
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	generatedName := hex.EncodeToString(randomBytes) + ext
	storagePath := filepath.Join(storageDir, generatedName)

	// Use os.OpenFile with os.O_EXCL to prevent race conditions
	outFile, err := os.OpenFile(storagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	// Rewind the file to start and write full content
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		os.Remove(storagePath)
		return
	}

	if _, err := io.Copy(outFile, file); err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
		os.Remove(storagePath)
		return
	}

	// Return the generated filename to the caller
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "%s", generatedName)
}
```

**Updated avatar_lookup.go:**
```go
package avatars

import (
	"os"
	"path/filepath"
	"strings"
)

func ReadAvatarBytes(generatedFilename string) ([]byte, error) {
	// Validate that the filename follows the generated name format (hex + extension)
	// to prevent path traversal attempts
	parts := strings.Split(generatedFilename, ".")
	if len(parts) != 2 {
		return nil, os.ErrNotExist
	}

	name := parts[0]
	ext := "." + parts[1]

	// Verify name is 32 hex characters (16 bytes as hex)
	if len(name) != 32 {
		return nil, os.ErrNotExist
	}

	// Verify name contains only valid hex characters
	for _, c := range name {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, os.ErrNotExist
		}
	}

	// Verify extension is in the allowlist
	if _, allowed := contentTypeMap[getContentTypeForExt(ext)]; !allowed {
		return nil, os.ErrNotExist
	}

	return os.ReadFile(filepath.Join(storageDir, generatedFilename))
}

func getContentTypeForExt(ext string) string {
	// Reverse lookup from extension to content type
	for ct, e := range contentTypeMap {
		if e == ext {
			return ct
		}
	}
	return ""
}
```

## Explanation

The vulnerability arose from using the client-supplied `header.Filename` directly in `filepath.Join(storageDir, header.Filename)`. An attacker could provide a filename containing path traversal sequences (e.g., `../../../etc/passwd`) to write files outside the intended storage directory. The coupled read function `ReadAvatarBytes` also accepted untrusted input, allowing retrieval from arbitrary locations.

The fix eliminates this by: (1) detecting the actual file content using `http.DetectContentType()` instead of trusting the client-supplied filename or Content-Type header; (2) validating the detected type against an allowlist of permitted image formats; (3) generating a cryptographically random hex-encoded filename with the extension derived from the allowlist, not the client input; (4) using `os.OpenFile()` with `os.O_EXCL` to atomically create the file and prevent race conditions; (5) returning the generated filename to the caller; and (6) updating `ReadAvatarBytes()` to accept only filenames matching the generated format (hex + extension from allowlist), rejecting any traversal sequences.

## Behaviour changes

- **New dependency**: `crypto/rand` and `encoding/hex` from the Go standard library are imported for random name generation (no external dependencies added)
- **API change to `UploadAvatar` response**: The handler now returns the generated filename in the response body (as plain text). Callers must update to store and use this returned filename for subsequent retrieval
- **Validation in `ReadAvatarBytes`**: Now rejects filenames that don't match the generated format; any code relying on direct access to original filenames must be updated to use the generated names returned by `UploadAvatar`
- **File storage behavior**: `os.OpenFile()` with `os.O_EXCL` creates the file atomically; if a collision occurs (extremely unlikely with 128-bit random names), the upload fails rather than overwriting. Existing code must handle this error condition
- **Memory usage**: The fix reads a 512-byte sniff buffer into memory; for typical avatars this adds negligible overhead. File I/O changes from `io.ReadAll()` to streaming via `io.Copy()`, improving memory efficiency for larger files
- **Error handling**: New error cases for unsupported content types, random number generation failures, and file creation conflicts; these must be handled appropriately by callers

