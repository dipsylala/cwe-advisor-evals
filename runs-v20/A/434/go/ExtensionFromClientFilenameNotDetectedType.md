## Verdict

Confirmed. The handler validates the file's real content by sniffing its bytes with `http.DetectContentType`, but then discards that result when naming the stored file: the extension appended to the randomly generated `storedName` comes from `filepath.Ext(fileHeader.Filename)`, which is the client-supplied filename and fully attacker-controlled. An attacker can upload a file whose bytes pass the PNG/JPEG/PDF sniff check while naming the upload something like `payload.php`, `payload.phtml`, or `payload.aspx`. The stored file then lands in `uploadDir` with a dangerous, executable extension. If that directory is ever reachable through a web server configured to execute scripts by extension (or a future change makes it so), the content-type check provides no protection at all, because the extension that determines how the file is later interpreted was never checked against the detected type.

## Source

`fileHeader.Filename` from the multipart upload (`r.FormFile("document")`), consumed via `filepath.Ext(fileHeader.Filename)` at line 66 in `document_upload.go`.

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

// extensionForContentType maps a sniffed, allow-listed content type to the
// extension used for the stored file. The stored extension must be derived
// from the detected type, never from the client-supplied filename, so an
// attacker cannot smuggle an executable extension (.php, .phtml, .aspx,
// etc.) past the content-type check.
var extensionForContentType = map[string]string{
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

	// The stored extension is derived from the sniffed, allow-listed
	// content type, not from the client-supplied filename, so it always
	// matches what DetectContentType actually verified.
	storedName += extensionForContentType[detectedType]

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

`allowedContentTypes` and the new `extensionForContentType` map cover the same fixed set of three keys, so every request that passes the sniff check has a corresponding safe extension, and the client-supplied filename is no longer consulted for naming at all (the `FormFile` return value that used to be `fileHeader` is discarded with `_` since nothing about the client filename is needed anymore). This closes the gap without weakening the existing defenses: the random `storedName` base still prevents path traversal and overwrite/guessing attacks, `os.O_EXCL` still prevents clobbering an existing file, and the content-sniffing check is unchanged. The only change is that the extension written to disk now reflects what was actually verified about the file's bytes, so a file sniffed as `image/png` is always stored as `.png`, never as whatever extension the client happened to send in the multipart filename field.
