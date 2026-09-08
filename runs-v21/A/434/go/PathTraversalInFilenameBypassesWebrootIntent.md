## Verdict

The vulnerability is confirmed. The code at line 51-53 accepts user-supplied filenames without sanitization, allowing path traversal attacks to write files outside the intended upload directory.

## Source

Line 51-53 in `attachment_upload.go`:
```
destPath := filepath.Join(uploadDir, fileHeader.Filename)
dest, err := os.Create(destPath)
```

The `fileHeader.Filename` value is read directly from the multipart form without validation. An attacker can include path traversal sequences like `../../../etc/passwd` to escape the upload directory.

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

	filename := filepath.Base(fileHeader.Filename)
	if filename == "" || filename == "." || filename == ".." {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	destPath := filepath.Join(uploadDir, filename)
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

The fix uses `filepath.Base()` to extract only the filename component, stripping any directory path separators. This prevents path traversal attacks where an attacker supplies `../../../etc/passwd` or similar sequences.

Additionally, validation rejects empty filenames or edge-case values that could result from attempted traversal (empty string, `.`, or `..`). This ensures that only legitimate filenames proceed to the file creation sink, and they are always saved within the intended `uploadDir`.

The content-type validation that precedes this fix continues to enforce allowed file types, providing defense-in-depth.
