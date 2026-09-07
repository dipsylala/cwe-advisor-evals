## Verdict

Confirmed exploitable. The handler validates actual file content via `http.DetectContentType()` against an allowlist but appends the client-supplied filename extension to the random storage name. An attacker can upload a PHP script with a `.php` extension; if the file's magic bytes match an allowed type header (e.g., a polyglot PNG/PHP), the content validation passes but the `.php` extension persists in the stored filename. When accessed, the server executes it as PHP code.

## Source

`r.FormFile("document")` returns a `multipart.FileHeader` with client-supplied `Filename` field (line 31).

## Fix

Replace the extension lookup from `filepath.Ext(fileHeader.Filename)` with a lookup from a fixed map keyed by the detected content type. This ensures the stored file extension matches only the validated content type, not the client's choice.

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

// Map detected content types to their safe file extensions.
var contentTypeToExt = map[string]string{
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

	file, _, err := r.FormFile("document")
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

	// Take the extension from the detected content type, not the client-supplied filename.
	ext := contentTypeToExt[detectedType]
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

The fix introduces a `contentTypeToExt` map that binds each allowed content type to a canonical file extension. After validating that the detected file content matches an allowlisted type, the code looks up the safe extension from this map and appends it to the random filename, rather than using the client-supplied extension from `fileHeader.Filename`. 

Changes:
1. Line 17-21: Added `contentTypeToExt` map to map detected MIME types to safe extensions.
2. Line 33: Changed from `file, fileHeader, err := r.FormFile("document")` to `file, _, err := r.FormFile("document")` since the `fileHeader` variable is no longer referenced.
3. Lines 63-64: Replaced `storedName += filepath.Ext(fileHeader.Filename)` with `ext := contentTypeToExt[detectedType]` and `storedName += ext` to derive the extension from the validated content type instead of the client-supplied filename.

The attacker can no longer control the file extension through the upload. The stored filename now always reflects the validated content type, preventing execution of scripts uploaded as polyglots or with spoofed headers.

## Behaviour changes

- Stored filenames now use extensions determined by the actual detected content type (`.png`, `.jpg`, `.pdf`), not the client-supplied filename extension.
- Files with mismatched or spoofed extensions that match an allowed content type signature are now stored with the canonical extension, preventing execution as a different file type.
- The handler no longer passes the multipart FileHeader to any function that would expose the client-supplied filename.
