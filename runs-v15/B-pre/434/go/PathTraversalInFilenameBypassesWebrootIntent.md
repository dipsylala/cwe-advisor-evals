## Verdict

CONFIRMED - Real vulnerability. The sink at line 53 (`os.Create(destPath)`) receives a path constructed from user-supplied filename (`fileHeader.Filename` at line 36) without validating that the filename doesn't contain path traversal sequences. An attacker can upload a file with filename `../../../etc/passwd` to escape the intended upload directory. Additionally, the content-type validation trusts the client-supplied `Content-Type` header rather than inspecting actual file content.

## Source

User-controlled data flow:
- **Line 36**: `file, fileHeader, err := r.FormFile("attachment")` — fileHeader is populated from the multipart request
- **Line 45**: `contentType := fileHeader.Header.Get("Content-Type")` — client-supplied, untrusted
- **Line 51**: `destPath := filepath.Join(uploadDir, fileHeader.Filename)` — fileHeader.Filename is client-supplied and may contain path traversal sequences like `../`
- **Line 53**: `dest, err := os.Create(destPath)` — **sink** writes to an unsafe path

Data flow: HTTP multipart request → fileHeader.Filename, fileHeader.Header → untrusted destPath → os.Create (file written outside intended directory).

## Fix

Replace the vulnerable upload handler with validation using `http.DetectContentType` to inspect actual file content, generate a random filename instead of using the client-supplied one, derive the extension from detected content type, and verify the final path stays within the upload directory:

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

const uploadDir = "/var/app/data/attachments"

var allowedContentTypes = map[string]bool{
	"application/pdf": true,
	"image/png":       true,
	"image/jpeg":      true,
}

// Map from detected content type to safe extension, server-controlled.
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

	// Read the first 512 bytes to detect the real content type.
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read attachment", http.StatusInternalServerError)
		return
	}

	// Detect the real content type from file content, not the client-supplied header.
	detectedType := http.DetectContentType(buf[:n])

	// Reject anything that isn't a recognized document or image type.
	if !allowedContentTypes[detectedType] {
		http.Error(w, "unsupported attachment type", http.StatusUnsupportedMediaType)
		return
	}

	// Reset file pointer after content sniffing.
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		http.Error(w, "could not process attachment", http.StatusInternalServerError)
		return
	}

	// Generate a safe filename instead of trusting the client-supplied one.
	randomName := make([]byte, 16)
	if _, err := rand.Read(randomName); err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}

	// Derive extension from detected content type, not from client filename.
	ext := contentTypeToExt[detectedType]
	generatedFilename := fmt.Sprintf("%x%s", randomName, ext)
	destPath := filepath.Join(uploadDir, generatedFilename)

	// Verify the path stays within uploadDir to prevent directory traversal.
	absDestPath, err := filepath.Abs(destPath)
	if err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}
	absUploadDir, err := filepath.Abs(uploadDir)
	if err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}
	if !filepath.HasPrefix(absDestPath, absUploadDir) {
		http.Error(w, "invalid attachment path", http.StatusInternalServerError)
		return
	}

	// Use OpenFile with O_EXCL to fail atomically if file exists, and set restrictive permissions.
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
	fmt.Fprintf(w, "attachment saved as %s", generatedFilename)
}
```

## Explanation

The original code had three separate weaknesses:

1. **Trusting client-supplied Content-Type header (line 45)**: The multipart part's `Content-Type` header is set by the client and can be forged. The fix calls `http.DetectContentType()` on the actual file content (the first 512 bytes) to determine the real type, then checks it against an allowlist. This prevents an attacker from claiming a malicious file is a PDF when it is actually an executable.

2. **Using client-supplied filename directly (line 51)**: `fileHeader.Filename` is supplied by the attacker and may contain path separal sequences (`../`, `..\\`) or absolute paths to escape the intended upload directory. The fix generates a random 16-byte hex filename, preventing any path traversal. The extension is derived from the detected content type via a server-controlled map, not from the client filename, so the extension cannot be manipulated.

3. **Weak path validation and file creation (line 53)**: The original code used `os.Create()` which truncates any existing file at that path. The fix uses `os.OpenFile()` with `O_EXCL` flag to atomically fail if the file exists, closing a time-of-check/time-of-use race. Permissions are set to `0o600` (readable/writable by owner only) as defence-in-depth.

The fixed code also adds a `filepath.HasPrefix()` check after normalizing both paths to their absolute forms, ensuring the generated path cannot be crafted to escape uploadDir even if the join operation behaves unexpectedly.

## Behaviour changes

- **Filename stored**: Changes from client-supplied (e.g., "proposal.pdf") to server-generated hex string (e.g., "a3f2b1c9e4d7f8a2.pdf"). Any existing code that retrieves files by their original filename will break; the fix returns the generated filename in the response body so clients can store and use it for future retrieval.
- **Content-Type validation**: Now inspects actual file bytes rather than trusting the multipart header. A file with `.pdf` extension but PNG content will now be rejected if the magic bytes are PNG.
- **File permissions**: Files are created with mode `0o600` (owner read/write only) instead of the default. This prevents other users on the system from reading uploaded files.
- **Atomic creation**: Using `O_EXCL` means the operation fails if a collision occurs, rather than silently overwriting an existing file.
