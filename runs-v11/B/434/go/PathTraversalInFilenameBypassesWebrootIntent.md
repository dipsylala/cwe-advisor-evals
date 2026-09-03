## Verdict

Exploitable. The handler uses `FileHeader.Filename` directly in `filepath.Join()` without sanitization, permitting path traversal. Even though Content-Type validation exists, it checks only the client-supplied header (not the actual file content) and does not address the filename-based attack vector.

## Source

Client-supplied multipart form data: `FileHeader.Filename` from `r.FormFile("attachment")` at line 36, and `Content-Type` header read at line 45.

## Fix

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/var/app/data/attachments"

var allowedContentTypes = map[string]bool{
	"application/pdf": true,
	"image/png":       true,
	"image/jpeg":      true,
}

// Map detected content types to safe file extensions.
var contentTypeToExt = map[string]string{
	"application/pdf": ".pdf",
	"image/png":       ".png",
	"image/jpeg":      ".jpg",
}

func init() {
	http.HandleFunc("/attachments/upload", uploadAttachmentHandler)
}

// uploadAttachmentHandler saves a ticket attachment uploaded by a support
// agent into the shared attachments directory.
func uploadAttachmentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Guard against oversized requests before parsing multipart form.
	r.Body = http.MaxBytesReader(w, r.Body, 20<<20)

	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	file, fileHeader, err := r.FormFile("attachment")
	if err != nil {
		http.Error(w, "missing attachment", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read leading bytes to detect actual file content type,
	// not the client-supplied Content-Type header.
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read attachment", http.StatusBadRequest)
		return
	}

	detectedType := http.DetectContentType(buf[:n])

	// Reject anything that isn't a recognized document or image type,
	// now based on actual content.
	if !allowedContentTypes[detectedType] {
		http.Error(w, "unsupported attachment type", http.StatusUnsupportedMediaType)
		return
	}

	// Rewind to beginning after sniffing.
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not process attachment", http.StatusInternalServerError)
		return
	}

	// Generate a random filename instead of trusting FileHeader.Filename,
	// which may contain path separators or traversal sequences.
	randomName := make([]byte, 16)
	if _, err := rand.Read(randomName); err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}

	// Extension comes from the detected content type, not the filename.
	ext := contentTypeToExt[detectedType]
	filename := hex.EncodeToString(randomName) + ext
	destPath := filepath.Join(uploadDir, filename)

	// Use os.O_EXCL to fail if file already exists.
	// This is a collision detection measure; collision is highly unlikely
	// with a 16-byte random value.
	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "attachment saved as %s", filename)
}
```

## Explanation

The fix eliminates three separate attack vectors. First, it detects the actual file content by reading the leading 512 bytes and calling `http.DetectContentType()`, replacing the check that trusted only the client-supplied `Content-Type` header. Second, it generates a random 16-byte filename encoded as hex, eliminating the path traversal risk from `FileHeader.Filename`, which may contain `../` or other path separators. Third, it assigns the file extension from a fixed map keyed by the detected content type, preventing an attacker from choosing the extension by providing a mismatched filename. The file is opened with `os.O_EXCL` to detect and reject unlikely collisions. Defence-in-depth: `http.MaxBytesReader()` is applied before parsing the multipart form, so an oversized request is rejected before consuming memory or disk.

## Behaviour changes

1. **Response body changed**: The response now returns the server-generated filename (e.g., `a1b2c3d4e5f6g7h8.pdf`) instead of the original filename (e.g., `invoice.pdf`). Callers that relied on echoing the original filename back to the user will need to be updated to display this generated name or store a mapping. This is intentional: the generated name is the only name that will retrieve the file from this endpoint in subsequent requests.

2. **File permissions changed**: Files are created with mode `0o600` (owner read-write only) instead of the default umask-derived permissions, reducing the attack surface.

3. **Request size validation timing changed**: `http.MaxBytesReader()` now guards the entire request body before multipart form parsing. Oversized requests are rejected earlier, preventing potential memory exhaustion.

4. **New import added**: `crypto/rand` and `encoding/hex` for secure random name generation.

5. **New global map added**: `contentTypeToExt` maps detected content types to extensions, decoupling extension from filename.

6. **File operation changed**: `os.OpenFile()` with `os.O_EXCL` replaces `os.Create()`. This prevents silently overwriting existing files (highly unlikely with random names, but fails safely if a collision occurs).

7. **Error handling unchanged for caller**: The handler still returns `StatusInternalServerError` for all write failures, so downstream error handling logic is not affected.
