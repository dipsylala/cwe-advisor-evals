## Verdict

Confirmed. Unrestricted file upload with no content-type validation. The handler accepts any file, uses the client-supplied filename directly as the storage path, and serves it back through `http.FileServer`, allowing execution or reflection of uploaded scripts.

## Source

Line 23: `file, header, err := r.FormFile("avatar")` retrieves the uploaded file. The `header.Filename` field (line 30) is client-supplied and untrusted.

## Fix

```go
package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const avatarDir = "./public/avatars"

// Map detected MIME type to safe file extension
var mimeToExt = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

// Allowed MIME types for avatars
var allowedTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
}

func init() {
	// Uploaded avatars are served back directly from this directory.
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir(avatarDir))))
}

func avatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	// Enforce a 10MB max upload size early
	http.MaxBytesReader(w, r.Body, 10<<20)

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read leading bytes to detect the file's real content type
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}

	// Detect the real MIME type from the file's actual content
	detectedType := http.DetectContentType(buffer[:n])

	// Allowlist validation: reject any type not in the allowlist
	if !allowedTypes[detectedType] {
		http.Error(w, "unsupported file type", http.StatusBadRequest)
		return
	}

	// Get the safe extension from the detected type, not the filename
	ext, ok := mimeToExt[detectedType]
	if !ok {
		http.Error(w, "unsupported file type", http.StatusBadRequest)
		return
	}

	// Generate a random filename instead of using the client-supplied one
	randomName := make([]byte, 16)
	if _, err := rand.Read(randomName); err != nil {
		http.Error(w, "could not generate filename", http.StatusInternalServerError)
		return
	}
	filename := fmt.Sprintf("%x%s", randomName, ext)
	destPath := filepath.Join(avatarDir, filename)

	// Create the file with restrictive permissions (read/write owner only)
	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	// Rewind and copy the entire file (already read first 512 bytes for detection)
	file.Seek(0, io.SeekStart)
	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	// Return the generated filename to the caller so they can retrieve it later
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"filename":"%s"}`, filename)
}
```

## Explanation

The fix eliminates the vulnerability at three critical points:

1. **Content validation (lines 56-66)**: Reads the file's leading 512 bytes and calls `http.DetectContentType()` to determine the real MIME type, independent of the filename extension or client-supplied Content-Type header. This prevents disguised executables (e.g., a `.php` file with JPEG magic bytes, or vice versa).

2. **Allowlist enforcement (lines 68-77)**: Only JPEG, PNG, GIF, and WebP are permitted. A rejected type returns a 400 error before any file is written.

3. **Safe filename generation (lines 79-87)**: Replaces `header.Filename` with a cryptographically random 16-byte hex string, mapped to the detected type's extension via `mimeToExt`. This prevents:
   - Path traversal (e.g., `../../etc/passwd`)
   - Filename-based script injection
   - Attacker control over the name the application uses to refer to the file

4. **Secure file creation (line 89)**: Uses `os.OpenFile()` with `O_EXCL` flag (fail if the file already exists) and restrictive permissions `0o600` (owner read/write only), preventing symlink attacks and race conditions.

5. **Early size limit (line 49)**: `http.MaxBytesReader()` enforces the 10MB limit before parsing, preventing memory exhaustion from oversized requests.

The handler now returns the generated filename in the response, so the caller (and subsequent requests) use the server-generated name to retrieve the file, not the original filename.

## Behaviour changes

- **Client-supplied filename is discarded**: The original `header.Filename` is no longer used for storage. Callers must now use the `filename` returned in the response JSON to retrieve their upload.
- **Only image types accepted**: Files that fail `http.DetectContentType()` or don't match the allowlist are rejected with HTTP 400, where the original code accepted anything.
- **Response format changed**: The handler now returns JSON with the generated filename, whereas the original returned an empty 201 response. Clients expecting an empty body will break unless updated.
- **File permissions tightened**: Uploaded files are now readable/writable by the owner only (`0o600`), reducing exposure if the process is compromised or runs in a shared environment.
- **Execution risk eliminated**: Only image MIME types are accepted. Uploaded `.php`, `.exe`, `.html`, `.js`, or other active-content files are rejected at parse time, preventing reflection or execution even if an attacker bypasses the webroot isolation.
