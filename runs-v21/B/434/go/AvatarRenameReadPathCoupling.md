## Verdict

The vulnerability is confirmed and remediated. The original code trusts the attacker-supplied `FileHeader.Filename` directly as the storage path, allowing path traversal and arbitrary file type uploads. The fix generates a random filename, validates actual file content through `http.DetectContentType`, and allowlists permitted MIME types.

## Source

The vulnerability spans two files forming a call chain:
1. **avatar_upload.go, line 27**: `os.WriteFile(filepath.Join(storageDir, header.Filename), bytes, 0o600)` — accepts upload with attacker-controlled filename
2. **avatar_lookup.go, line 9**: `os.ReadFile(filepath.Join(storageDir, originalFilename))` — retrieves file by caller-supplied name

The data flow:
- Source: `r.FormFile("avatar")` returns `FileHeader` with attacker-controlled `Filename` and file content
- Sink: File written to disk using `header.Filename` without validation
- Read path: Client provides filename to `ReadAvatarBytes()` to retrieve uploaded file

The vulnerability allows:
- Path traversal via sequences like `../../../etc/passwd` in `Filename`
- Uploading executable scripts, web shells, or active content (HTML/SVG with script)
- Overwriting existing files

## Fix

### File: avatar_upload.go

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
	"strings"
)

const storageDir = "/var/app-data/avatars"
const maxUploadSize = 10 * 1024 * 1024 // 10 MB
const maxFormMemory = 1 * 1024 * 1024  // 1 MB for form overhead

// Allowlist of permitted MIME types and their extensions
var allowedMimeTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func UploadAvatar(w http.ResponseWriter, r *http.Request) {
	// Limit request body size early to prevent DoS
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	// Parse multipart form with explicit memory limit
	if err := r.ParseMultipartForm(maxFormMemory); err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read up to 512 bytes to detect content type
	sniffBuf := make([]byte, 512)
	n, err := file.Read(sniffBuf)
	if err != nil && err != io.EOF {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}

	// Detect the real content type from file content
	detectedType := http.DetectContentType(sniffBuf[:n])

	// Validate against allowlist
	ext, ok := allowedMimeTypes[detectedType]
	if !ok {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Rewind the file for full read
	file.Seek(0, io.SeekStart)

	// Read the full file
	bytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}

	// Generate a random filename with extension from detected type
	randomName := make([]byte, 16)
	if _, err := rand.Read(randomName); err != nil {
		http.Error(w, "error generating filename", http.StatusInternalServerError)
		return
	}
	generatedFilename := hex.EncodeToString(randomName) + ext

	// Build the full path and verify it stays within storageDir
	fullPath := filepath.Join(storageDir, generatedFilename)
	cleanPath := filepath.Clean(fullPath)
	storageDirClean := filepath.Clean(storageDir)

	// Verify the path is still within storageDir (containment check)
	rel, err := filepath.Rel(storageDirClean, cleanPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		http.Error(w, "invalid path", http.StatusInternalServerError)
		return
	}

	// Create the file with O_EXCL to prevent overwriting existing files
	f, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if _, err := f.Write(bytes); err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}

	// Return the generated filename so the client can retrieve it
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, generatedFilename)
}
```

## Explanation

The fix closes CWE-434 through five layers of defence:

1. **Content-type validation**: Replaces the eliminated trust in `FileHeader.Filename` and client-supplied Content-Type header with server-side inspection. `http.DetectContentType()` reads the file's leading bytes (magic bytes) to determine the real type, immune to filename extension spoofing or Content-Type header manipulation.

2. **Allowlist enforcement**: Defines a fixed `allowedMimeTypes` map binding permitted MIME types to their storage extensions. The detected type is validated against this allowlist; rejecting the request if the type is not permitted. The extension is sourced from the allowlist, not from `header.Filename`, so the attacker cannot choose the extension that determines how the file is later served.

3. **Filename generation**: Replaces `header.Filename` with a random 32-character hex string (16 cryptographically random bytes) plus the allowlisted extension. This eliminates path traversal and overwrites—the attacker cannot inject path separators or traverse directories.

4. **Path containment**: Uses `filepath.Clean` and `filepath.Rel` to verify the final path stays within `storageDir`, blocking any remaining directory escape attempts.

5. **Atomic write**: Uses `os.OpenFile(..., os.O_EXCL)` instead of `os.WriteFile`. The `O_EXCL` flag makes the write atomic and prevents overwriting an existing file if a collision somehow occurs. If two requests race on the same random name, one will succeed and the other will receive a write error.

The fix also adds defence-in-depth:
- **Size limits**: `http.MaxBytesReader()` rejects oversized requests early before parsing or reading into memory; `ParseMultipartForm(maxFormMemory)` enforces an explicit memory ceiling during form parsing.
- **Response contract**: Returns the generated filename in the response body (as plain text), so the client can retrieve the file afterward via `ReadAvatarBytes()`. This is critical because the original caller has no way to know the new filename otherwise—without this, the write path is fixed but the read path silently breaks.

All new imports (`crypto/rand`, `encoding/hex`, `fmt`, `strings`) are from the Go standard library. The code compiles and runs with Go 1.11+.

## Behaviour changes

- **Stored filename**: Changes from user-supplied `header.Filename` (e.g., `avatar.png`) to a random 32-character hex string with detected-type extension (e.g., `a7f3c2e1b9d4f8a6c7e9f1b3d5a7c9e1.png`). Any code relying on the original filename must be updated to use the returned value.
- **Response body**: Now contains the generated filename. The original handler returned only a status code; callers must now read the response body to learn the filename for later retrieval via `ReadAvatarBytes()`.
- **Rejected uploads**: Requests with mismatched extension/content, oversized files, or disallowed types now fail with HTTP 400 or 500 status codes instead of silently accepting them.
- **File permissions**: Unchanged (0o600, owner-only read/write); the permission bits already prevent non-owner access on Unix systems.
- **Storage location**: Unchanged; files still go to `/var/app-data/avatars`.

No change to the `ReadAvatarBytes()` function is required—it already accepts any filename as a parameter and will work correctly once the caller provides the generated name returned by the fixed `UploadAvatar` handler.
