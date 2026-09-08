## Verdict
CONFIRMED. CWE-434 at line 66: client-supplied filename extension is used despite content-type validation, allowing an attacker to upload `malicious.php` with allowed content (e.g., PDF magic bytes) and retain the executable extension.

## Source
The vulnerability is at line 66:
```
storedName += filepath.Ext(fileHeader.Filename)
```

The code validates the file's actual content type via `http.DetectContentType()` but then trusts the client-supplied filename extension. An attacker can craft a file with a dangerous extension (`.php`, `.jsp`, etc.) containing valid PDF/image magic bytes to bypass validation while retaining the malicious extension.

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

// Map detected content types to safe file extensions
var extensionByContentType = map[string]string{
	"image/png":       ".png",
	"image/jpeg":      ".jpg",
	"application/pdf": ".pdf",
}

// UploadDocumentHandler receives a multipart document upload, verifies the
// real content type of the file body, and stores it under a randomly
// generated name with an extension matching the detected content type.
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

	// Use extension matching the detected content type, not the client-supplied filename.
	ext := extensionByContentType[detectedType]
	storedName += ext

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
The fix removes the dependency on the client-supplied filename by introducing `extensionByContentType`, a map from allowed content types to safe extensions. After validating that the file's actual content matches an allowed type, the code now appends the extension from the map (derived from the detected type) instead of from `fileHeader.Filename`. This ensures the stored file's extension cannot be manipulated by the attacker and always matches its actual content, closing the CWE-434 vulnerability.
