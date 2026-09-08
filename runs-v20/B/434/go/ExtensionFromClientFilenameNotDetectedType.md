## Verdict

Exploitable. CWE-434 (Unrestricted Upload of File with Dangerous Type).

## Source

`fileHeader.Filename` from the multipart part returned by `r.FormFile("document")` in `UploadDocumentHandler` (`document_upload.go`, line 31) - a client-controlled value, including its extension.

## Fix

The handler already sniffs the real content type with `http.DetectContentType` and checks it against `allowedContentTypes`, and it already generates a random base filename with `crypto/rand` instead of using the client's filename. But at the sink (line 66) it reattaches the *extension* from `filepath.Ext(fileHeader.Filename)` - the one part of the client-supplied name it never validated. An attacker can upload a file whose body passes the `image/png` (or other allowed) signature check while naming the part `payload.php`, `payload.html`, or similar; the server then stores `<random-hex>.php` under `uploadDir`. If that directory (or any location the file is later moved/served from) is reachable by a script-executing web server or served with browser-guessable content sniffing, the client chose the exploitable half of the stored name even though the body's type was verified.

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

// extensionsByDetectedType maps a server-detected content type to the file
// extension used for storage. Keys are kept in sync with allowedContentTypes:
// the stored extension is derived from the sniffed type, never from the
// client-supplied filename.
var extensionsByDetectedType = map[string]string{
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

	// Take the stored extension from the fixed allowlist map keyed by the
	// detected content type, not from the client-supplied filename.
	storedName += extensionsByDetectedType[detectedType]

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

Replaced `storedName += filepath.Ext(fileHeader.Filename)` with a lookup into `extensionsByDetectedType`, a fixed `map[string]string` keyed by the exact same content-type strings already used in `allowedContentTypes`, so the stored extension is derived from the value `http.DetectContentType` verified rather than from the untrusted client filename. Because the map only contains entries for the three allowed types and `detectedType` has already been checked against `allowedContentTypes` before this point, the lookup always succeeds and never yields an empty extension on the code path that reaches it. The declared-but-now-unused `fileHeader` return value from `r.FormFile` was changed to `_` since its only use (`fileHeader.Filename` for the extension) was removed; this is required for the code to compile, not an independent behavior change. `filepath` remains imported and used via `filepath.Join`.

## Behaviour changes

- The stored file's extension is now always one of `.png`, `.jpg`, or `.pdf` (matching the detected type) instead of whatever extension was present in the client-supplied filename. For a legitimate upload whose filename extension happened to already match its real type (the expected common case), the resulting stored extension is unchanged. For a mismatched or malicious filename (e.g. body is a valid PNG but named `x.php`), the stored extension now reflects the verified PNG type instead of `.php` - this is the intended closure of the weakness, not an unrelated behavior change.
- `fileHeader` (the second return value of `r.FormFile`) is no longer bound to a name and is discarded via `_`; it was not used anywhere else in this handler (no logging, no response field, no persisted mapping referencing the original filename), so no caller-visible behavior depends on it.
- The response body (`fmt.Fprintf(w, "%s", storedName)`) still returns the generated storage name to the caller, now with the corrected extension; nothing else about the response changed.

## Verification

Copied the fixed file into a standalone scratch Go module (outside the repository) and ran `go vet ./...` against it: no diagnostics were reported. The file also compiles cleanly as part of that module (`go vet` performs a full type-check as a prerequisite). All identifiers introduced by the fix (`extensionsByDetectedType`) are new package-level declarations defined in this same file; no new imports or external packages were added.
