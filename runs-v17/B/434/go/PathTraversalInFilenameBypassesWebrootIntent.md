## Verdict

Exploitable. The vulnerability allows path traversal through the client-supplied filename in the multipart form, bypassing the intended webroot storage constraint. An attacker can upload a file with a traversal-laden name like `../../../../etc/passwd.pdf` and, combined with insufficient content-type validation (which checks only the client-supplied header, not actual file content), write arbitrary files outside the intended upload directory.

## Source

`r.FormFile("attachment")` returns a multipart file whose `Filename` field is attacker-controlled and passed directly to `filepath.Join(uploadDir, fileHeader.Filename)` at line 51. This is the untrusted source.

## Fix

### File: attachment_upload.go

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

// contentTypeToExt maps detected content types to their extensions
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

	// Read leading bytes to detect actual content type from file content,
	// not from client-supplied Content-Type header
	header := make([]byte, 512)
	n, err := file.Read(header)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read attachment", http.StatusBadRequest)
		return
	}

	// Use http.DetectContentType to verify actual file content
	detectedType := http.DetectContentType(header[:n])

	// Validate detected content type against allowlist
	if !allowedContentTypes[detectedType] {
		http.Error(w, "unsupported attachment type", http.StatusUnsupportedMediaType)
		return
	}

	// Generate a random filename instead of trusting client-supplied fileHeader.Filename
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}
	randomName := hex.EncodeToString(randomBytes)

	// Get extension from detected content type, not from client-supplied filename
	ext := contentTypeToExt[detectedType]
	generatedFilename := randomName + ext

	// Build destination path and verify it stays within uploadDir
	destPath := filepath.Join(uploadDir, generatedFilename)
	cleanedPath := filepath.Clean(destPath)

	// Verify the path is within uploadDir by checking it doesn't escape
	rel, err := filepath.Rel(uploadDir, cleanedPath)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || filepath.HasPrefix(rel, ".."+string(filepath.Separator)) {
		http.Error(w, "invalid file path", http.StatusBadRequest)
		return
	}

	// Create file with exclusive creation flag to prevent overwrites,
	// and restricted permissions (0o600)
	dest, err := os.OpenFile(cleanedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	// Rewind to start of file before copying (we read 512 bytes above)
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}

	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "attachment saved as %s", filepath.Base(cleanedPath))
}
```

## Explanation

The original code was vulnerable to path traversal because it directly joined the attacker-controlled `fileHeader.Filename` with `uploadDir`, allowing sequences like `../` to escape the intended directory. Additionally, it validated only the client-supplied Content-Type header instead of checking actual file content. The fix eliminates both weaknesses: it generates a random filename using `crypto/rand` and `encoding/hex` instead of trusting `fileHeader.Filename`, preventing path traversal entirely; it uses `http.DetectContentType` to inspect the actual file content's magic bytes and validates against the allowlist; it derives the file extension from a server-controlled map keyed by the detected type, never from the client-supplied name; it verifies the final path stays within `uploadDir` using `filepath.Clean` and `filepath.Rel`; and it uses `os.OpenFile` with `O_EXCL` flag and restrictive permissions (`0o600`) for safer file creation. The file is rewound after content-type detection so the full content is written to disk.

## Behaviour changes

- **Import changes**: Added `crypto/rand` and `encoding/hex` to generate random filenames server-side.
- **Global variable added**: `contentTypeToExt` map associates detected MIME types to extensions, replacing direct use of client-supplied `fileHeader.Filename` extension.
- **File detection**: Now reads up to 512 bytes from the uploaded file and calls `http.DetectContentType` instead of trusting the client-supplied Content-Type header. This prevents an attacker from disguising a malicious file by setting a false header.
- **Filename generation**: Replaces `fileHeader.Filename` with a random hex string plus an extension derived from `contentTypeToExt`, eliminating path-traversal attack surface.
- **Path validation**: Added `filepath.Clean` and `filepath.Rel` checks to verify the final destination path does not escape `uploadDir`.
- **File creation**: Changed from `os.Create` to `os.OpenFile` with flags `O_WRONLY|O_CREATE|O_EXCL` and mode `0o600`, providing atomic creation and preventing race conditions or accidental overwrites.
- **File rewinding**: After reading 512 bytes for content detection, the file is rewound with `file.Seek(0, io.SeekStart)` before copying the full content, ensuring no data is lost.
- **Response behavior**: Still returns HTTP 201 and echoes the stored filename (now the generated one), so the caller learns how to retrieve the file later. The new filename is server-controlled, not client-supplied, so the response is safe to include.
