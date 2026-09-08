## Verdict

The vulnerability is confirmed. The code correctly detects the real file content type using `http.DetectContentType()` and validates it against an allowlist, but then undermines this validation by appending the file extension from the untrusted client-supplied `FileHeader.Filename` (line 66: `storedName += filepath.Ext(fileHeader.Filename)`). An attacker can upload a PNG file but supply a `.php` extension in the multipart filename, resulting in a file stored as `<randomhex>.php` that will execute as PHP if served from a location where PHP execution is enabled. The security decision (allowlist validation) is made on the real content type, but the storage decision (extension) is made on the client-supplied filename.

## Source

**File:** `document_upload.go`  
**Line:** 66  
**Vulnerable Code:**
```
storedName += filepath.Ext(fileHeader.Filename)
```

The data flow:
1. `fileHeader.Filename` originates from the client-supplied multipart part header (untrusted source)
2. `filepath.Ext()` extracts the extension from this untrusted filename
3. The extension is appended to a randomly-generated base name
4. The resulting path is used to store the file via `os.OpenFile()`

The root cause is that while the validation gate (line 47) uses the detected content type (`http.DetectContentType()`), the storage path construction (line 66) uses the client-controlled extension instead of a derived value based on the detected type.

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

	// Use the extension from the detected content type, not the client-supplied filename.
	storedName += contentTypeToExt[detectedType]

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

The fix introduces a server-controlled map `contentTypeToExt` that maps detected content types to safe file extensions. This map is keyed by the output of `http.DetectContentType()`, which inspects the file's actual binary content (magic bytes), not client-supplied metadata.

The vulnerable line 66 (`storedName += filepath.Ext(fileHeader.Filename)`) is replaced with `storedName += contentTypeToExt[detectedType]`, ensuring that the stored filename's extension is always derived from the detected content type, never from the client-supplied `FileHeader.Filename`.

This enforces a critical separation: the validation gate (line 47) checks the detected content type against an allowlist, and now the storage path construction uses only values from that same allowlist-controlled map. An attacker uploading a PNG file cannot cause it to be stored as `.php` or any other extension—the stored extension will always be `.png` because that is the only extension the detected type `image/png` maps to.

Additionally, the fileHeader variable is no longer used (replaced with `_` in the FormFile call), removing a potential confusion point about which filename should be trusted.

**Verification:** `go vet` confirms the fixed code has no issues. The changes are minimal and surgical: added the `contentTypeToExt` map at the package level, changed one line of storage path construction, and removed the now-unused fileHeader variable assignment.

## Behaviour changes

**Breaking changes:** None. The fix preserves all application behavior from the caller's perspective.

**Observable changes:**
- Uploaded files are now stored with extensions derived from their real content type. An upload with a real PNG body but `.txt` in the filename will be stored as `<randomhex>.png`, not `<randomhex>.txt`.
- Files can still be retrieved via the returned filename (the `storedName` response at line 82 remains unchanged), so any downstream code that stores and retrieves this name will continue to work.

**Security changes:**
- The extension used for storage can no longer be influenced by the attacker. This prevents extension-based attacks (e.g., uploading an executable disguised as an image by providing a `.php` extension in the multipart filename).
- Files containing executable content but with a misleading extension are now stored under the correct extension, preventing bypass of any downstream execution-prevention controls that rely on file extension checking.
