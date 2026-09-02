## Verdict

The finding is confirmed. Line 32 writes an uploaded file to the webroot using the client-supplied filename without validating file type or content. An attacker can upload executable or script-bearing files (e.g., `.html`, `.js`) that will be served directly to browsers, enabling stored XSS or other attacks.

## Source

`header.Filename` from `r.FormFile("avatar")` (line 23) is client-supplied metadata in the multipart form. No validation of file type or content occurs before the file is written.

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

// allowedTypes maps detected content types to their safe file extensions
var allowedTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func init() {
	// Uploaded avatars are served back directly from this directory.
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir(avatarDir))))
}

func generateFilename(contentType string) (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	ext := allowedTypes[contentType]
	return fmt.Sprintf("%x%s", randomBytes, ext), nil
}

func avatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	// Guard against oversized requests before parsing
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB

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

	// Detect actual content type by reading leading bytes
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusInternalServerError)
		return
	}

	detectedType := http.DetectContentType(buffer[:n])

	// Validate against allowlist of permitted types
	if _, allowed := allowedTypes[detectedType]; !allowed {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Rewind file pointer to start before copying
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not process file", http.StatusInternalServerError)
		return
	}

	// Generate cryptographically random filename with safe extension
	filename, err := generateFilename(detectedType)
	if err != nil {
		http.Error(w, "could not generate filename", http.StatusInternalServerError)
		return
	}

	destPath := filepath.Join(avatarDir, filename)

	// Use O_EXCL to atomically create the file and prevent race conditions
	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
```

## Explanation

The fix applies three layers of protection:

1. **Content Type Detection**: `http.DetectContentType()` inspects the file's leading bytes (magic number / file signature) rather than trusting the client-supplied `Content-Type` header or filename extension. This detects actual content independent of what the attacker claims.

2. **Allowlist Validation**: A server-controlled map (`allowedTypes`) specifies which MIME types are permitted. Only files matching one of these types are accepted; all others are rejected with a 400 error.

3. **Safe Filename Generation**: The stored filename is generated cryptographically at random using `crypto/rand`, not derived from `header.Filename`. The extension is taken from the allowlist entry keyed by the detected type, ensuring the file's handler behavior (how it is served) depends on the detected content, not attacker input.

Additional hardening includes:
- `http.MaxBytesReader` gates oversized requests before parsing to prevent resource exhaustion
- `os.OpenFile(..., os.O_EXCL, 0o600)` atomically creates the file with restrictive permissions, preventing race conditions and information leakage
- The file pointer is rewound after sniffing so the full content is written to storage

## Behaviour changes

- **Breaking Change**: Clients can no longer retrieve uploaded files by their original filename. The response must return the generated filename (e.g., in the response body or Location header) so the client can later fetch it. If any existing route or database schema maps avatars by their original name, it must be updated to use the generated name instead.
- **File Type Enforcement**: Uploads of non-image files (`.html`, `.js`, `.php`, `.exe`, etc.) are now rejected with HTTP 400. Clients uploading in unsupported formats will receive an error.
- **Request Size Limit**: Requests exceeding 10 MB are rejected before parsing, whereas previously the limit was only checked during `ParseMultipartForm` and could consume more resources first.
- **Permissions**: Uploaded files are created with `0o600` (user read/write only), preventing other users on the system from accessing or modifying them.
