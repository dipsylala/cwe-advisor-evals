## Verdict

CONFIRMED. The original code trusts the client-supplied `fileHeader.Filename` without validation, allowing path traversal attacks. An attacker can inject sequences like `../` or `..\\` to write files outside the intended upload directory (CWE-434: Unrestricted Upload of File with Dangerous Type). Additionally, the Content-Type header validation is insufficient because it only checks the client-supplied header, not the actual file content.

## Source

`fileHeader.Filename` (from `r.FormFile("attachment")` at line 36) — client-supplied, untrusted multipart form metadata. An attacker can set this to include path traversal sequences like `../../../etc/passwd` or `..\..\..\windows\system32\cmd.exe`.

## Fix

Replace the unsafe use of `fileHeader.Filename` with a server-generated random filename. Validate actual file content using `http.DetectContentType()` instead of trusting the client-supplied Content-Type header. Map the detected type to a safe file extension from a server-controlled allowlist, and use `os.OpenFile()` with `O_EXCL` for atomic creation.

### File: attachment_upload.go

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

// Map detected content type to safe file extension
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

	file, _, err := r.FormFile("attachment")
	if err != nil {
		http.Error(w, "missing attachment", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Detect the real content type by inspecting the file's leading bytes
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read attachment", http.StatusBadRequest)
		return
	}

	detectedType := http.DetectContentType(buffer[:n])
	if !allowedContentTypes[detectedType] {
		http.Error(w, "unsupported attachment type", http.StatusUnsupportedMediaType)
		return
	}

	// Rewind the file to the beginning before writing
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not process attachment", http.StatusInternalServerError)
		return
	}

	// Generate a random filename using the detected content type's extension
	randomName, err := generateRandomName()
	if err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}

	ext := contentTypeToExt[detectedType]
	generatedFilename := randomName + ext
	destPath := filepath.Join(uploadDir, generatedFilename)

	// Use os.OpenFile with O_EXCL to prevent race conditions and ensure atomic creation
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

// generateRandomName generates a random filename component using crypto/rand
func generateRandomName() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
```

## Explanation

The original code accepted `fileHeader.Filename` directly from the client and passed it to `filepath.Join(uploadDir, fileHeader.Filename)`, creating a path that could escape the upload directory through path traversal sequences like `../`. The fix eliminates this vulnerability by:

1. **Content validation**: The code now reads the first 512 bytes of the uploaded file and uses `http.DetectContentType()` to determine the actual content type, rather than trusting the client-supplied Content-Type header. This prevents polyglot attacks where a file with a safe magic number is followed by executable content.

2. **Filename generation**: Instead of using the client-supplied `fileHeader.Filename`, the code generates a random 16-byte hex filename using `crypto/rand.Read()`. Since this filename is generated server-side, it cannot contain path traversal sequences or any other attacker-controlled data.

3. **Extension mapping**: The file extension is derived from a server-controlled allowlist (`contentTypeToExt` map) based on the detected content type, not from the original filename. This ensures the extension matches the actual file content and cannot be spoofed.

4. **Atomic creation**: The code uses `os.OpenFile()` with `os.O_WRONLY|os.O_CREATE|os.O_EXCL` flags instead of `os.Create()`. The `O_EXCL` flag ensures the file is created atomically and fails if the file already exists, preventing race conditions and ensuring uniqueness.

5. **File rewinding**: After reading the first 512 bytes for content detection, the code rewinds the file with `file.Seek(0, io.SeekStart)` before writing, ensuring the complete file content is written.

## Behaviour changes

**Response format**: The response body now returns the generated filename (e.g., `"attachment saved as a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.pdf"`) instead of the original client-supplied filename. If other code or clients depend on retrieving files by their original names, this change requires additional handling: either maintain a database mapping of generated names to original names, or always serve files through an application-controlled handler that performs the lookup.

**Error handling**: The addition of `file.Seek()` introduces a new failure point; if the file cannot be rewound (uncommon for HTTP multipart uploads), the request returns 500. This is appropriate since it indicates an unexpected condition.

**File permissions**: The created file now has mode `0o600` (read/write for owner only, no access for group or others), compared to the default from `os.Create()` which uses `0o666` masked by the process umask. This is a security improvement and typically desirable for uploaded files, but may require permission adjustments if other processes need to access these files.

