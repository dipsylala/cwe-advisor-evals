## Verdict
CONFIRMED. The code validates Content-Type but uses the user-supplied filename directly in a path operation, allowing directory traversal. An attacker can supply a filename like `../../../etc/passwd` to write outside the intended upload directory.

## Source
Line 51-53 constructs `destPath` using `filepath.Join(uploadDir, fileHeader.Filename)` where `fileHeader.Filename` is attacker-controlled. Although `filepath.Join` is used, it does not strip directory traversal sequences in the filename component. The subsequent `os.Create(destPath)` on line 53 then writes to a path an attacker can manipulate via the filename.

## Fix
### File: attachment_upload.go
```go
package main

import (
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

	// Reject anything that isn't a recognized document or image type before
	// we ever touch the filesystem.
	contentType := fileHeader.Header.Get("Content-Type")
	if !allowedContentTypes[contentType] {
		http.Error(w, "unsupported attachment type", http.StatusUnsupportedMediaType)
		return
	}

	// Extract the base filename only, stripping any directory traversal attempts.
	// This prevents an attacker from using filenames like "../../../etc/passwd"
	// to write outside the upload directory.
	safeFilename := filepath.Base(fileHeader.Filename)
	destPath := filepath.Join(uploadDir, safeFilename)
	// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
	dest, err := os.Create(destPath)
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
	fmt.Fprintf(w, "attachment saved as %s", filepath.Base(destPath))
}
```

## Explanation
The vulnerability stems from trusting the user-supplied filename without sanitization. While the code validates Content-Type to restrict file types, it neglects to validate the filename itself. An attacker can provide a filename containing path traversal sequences (`..` components or absolute paths) to write files outside the intended `uploadDir`.

The fix applies `filepath.Base()` to the filename before constructing the destination path. `filepath.Base()` extracts only the final path component, discarding any directory traversal attempts:
- Input: `../../../etc/passwd` → Output: `passwd`
- Input: `/etc/passwd` → Output: `passwd`
- Input: `normal_file.pdf` → Output: `normal_file.pdf`

This ensures that regardless of the attacker's filename, the file is created only within the designated upload directory. The approach is minimal and maintains the intended behavior while closing the path traversal vector.
