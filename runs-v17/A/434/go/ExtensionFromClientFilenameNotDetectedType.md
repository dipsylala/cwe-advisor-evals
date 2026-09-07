## Verdict
Confirmed CWE-434: The file extension is derived from the untrusted client-supplied filename rather than the validated detected content type, allowing dangerous file types to be stored with unsafe extensions.

## Source
The vulnerability is at line 66 of `document_upload.go`:
```go
storedName += filepath.Ext(fileHeader.Filename)
```

The code correctly validates the file's actual content type via `http.DetectContentType()` (line 46) and checks it against an allowlist (line 47-50), but then appends an extension derived from `fileHeader.Filename`, which is completely under the attacker's control and bypasses all validation.

## Fix
### File: document_upload.go

```go
package uploads

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/var/data/document-uploads"

var allowedContentTypes = map[string]bool{
	"image/png":       true,
	"image/jpeg":      true,
	"application/pdf": true,
}

// Map detected content types to safe file extensions.
var extensionMap = map[string]string{
	"image/png":       ".png",
	"image/jpeg":      ".jpg",
	"application/pdf": ".pdf",
}

// UploadDocumentHandler receives a multipart document upload, verifies the
// real content type of the file body, and stores it under a randomly
// generated name.
func UploadDocumentHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "upload too large", http.StatusBadRequest)
		return
	}

	file, fileHeader, err := r.FormFile("document")
	if err != nil {
		http.Error(w, "missing document field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Sniff the real content type from the file body rather than trusting
	// the client-supplied Content-Type header.
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		http.Error(w, "unable to read upload", http.StatusInternalServerError)
		return
	}
	detectedType := http.DetectContentType(buf[:n])
	if !allowedContentTypes[detectedType] {
		http.Error(w, "unsupported file type", http.StatusUnprocessableEntity)
		return
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "unable to read upload", http.StatusInternalServerError)
		return
	}

	// Generate a random, unpredictable base name for the stored file.
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	storedName := hex.EncodeToString(randBytes)

	// Use the extension derived from the detected content type, not the client-supplied filename.
	storedName += extensionMap[detectedType]

	destPath := filepath.Join(uploadDir, storedName)
	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "unable to store file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "unable to store file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "%s", storedName)
}
```

## Explanation
The fix replaces the untrusted client-supplied filename extension with an extension map that is keyed by the validated detected content type. This ensures that:

1. The extension stored in the filename comes exclusively from the server's allowlist of content types, not the attacker-controlled filename.
2. The two defences work together: content type validation prevents the file's actual bytes from being a dangerous type, and the extension map ensures the filename itself is also safe.
3. An attacker cannot bypass the upload control by uploading a malicious file with a deceptive filename extension like `.png.exe` or by omitting an extension entirely—the stored filename will always have an extension that matches its validated content type.

The `extensionMap` variable maps each allowed MIME type to its corresponding safe file extension, and line 66 now uses this map instead of extracting the extension from the client-supplied `fileHeader.Filename`.
