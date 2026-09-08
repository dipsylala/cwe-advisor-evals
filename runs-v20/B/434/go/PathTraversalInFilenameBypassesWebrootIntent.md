## Verdict

exploitable (confidence: high)

- cwe_id: CWE-434
- location: attachment_upload.go, line 53 (`os.Create(destPath)`)

## Source

`fileHeader.Filename` from `r.FormFile("attachment")` (line 36) - the client-supplied original filename from the multipart part, and `fileHeader.Header.Get("Content-Type")` (line 45) - the client-supplied part header. Both are attacker-controlled and unverified by `net/http`.

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

// maxUploadBytes bounds both the total request body size and the in-memory
// portion of the parsed multipart form.
const maxUploadBytes = 20 << 20

// allowedUploadTypes maps a server-detected content type (from
// http.DetectContentType) to the extension used for the stored file. The
// extension is never taken from the client-supplied filename.
var allowedUploadTypes = map[string]string{
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

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)

	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("attachment")
	if err != nil {
		http.Error(w, "missing attachment", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Detect the real content type from the file's leading bytes rather than
	// trusting the client-supplied Content-Type header, and reject anything
	// not on the allowlist before we ever touch the filesystem.
	sniff := make([]byte, 512)
	n, err := file.Read(sniff)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read attachment", http.StatusBadRequest)
		return
	}
	detectedType := http.DetectContentType(sniff[:n])
	ext, ok := allowedUploadTypes[detectedType]
	if !ok {
		http.Error(w, "unsupported attachment type", http.StatusUnsupportedMediaType)
		return
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not read attachment", http.StatusInternalServerError)
		return
	}

	// Generate the storage filename server-side; the client-supplied
	// filename is never used to build a path, so it cannot carry path
	// separators or traversal sequences into destPath.
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}
	storedName := hex.EncodeToString(randBytes) + ext
	destPath := filepath.Join(uploadDir, storedName)

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
	fmt.Fprintf(w, "attachment saved as %s", storedName)
}
```

## Explanation

The handler built `destPath` with `filepath.Join(uploadDir, fileHeader.Filename)` and wrote to it with `os.Create`, using the attacker-supplied original filename directly as the storage path and gating only on the client-supplied `Content-Type` header. A filename containing `../` sequences survives `filepath.Join`'s cleaning and walks the resulting path outside `uploadDir` (e.g. `attachment` sent with filename `../../etc/cron.d/evil` resolves under `/var/app/`, two levels above the intended directory), and the content-type check is a bare header comparison the client fully controls, so a script or web shell can be uploaded by simply relabeling its `Content-Type` to `image/png`. The fix removes the client-supplied filename and header from the write path entirely: it sniffs the real content type from the file's leading bytes with `http.DetectContentType`, checks that against a fixed allowlist mapping detected type to extension, and derives the stored filename and extension purely from server-generated randomness (`crypto/rand`) plus the allowlist's own extension - so there is no attacker-controlled path component left to traverse with, and no client-controlled label left to spoof. `os.OpenFile` with `O_CREATE|O_EXCL` additionally refuses to overwrite an existing file, and `http.MaxBytesReader` plus the existing `ParseMultipartForm` limit bound the request size defense-in-depth per the loaded Go guidance.

## Behaviour changes

- The response body now returns the generated storage name (`storedName`) instead of `filepath.Base(destPath)` of the original filename - required because the file is no longer stored under any form of the client's name; any caller that later retrieves the file needs to read this response to know the real name (per the guidance's "preserve the caller's contract" step). This is the only externally visible change.
- Files are opened with `os.O_EXCL`, so a random-name collision fails the upload with a 500 instead of silently overwriting a prior file. Collision probability with a 16-byte random name is negligible; this only changes behaviour in that vanishingly unlikely case.
- `r.Body` is now wrapped in `http.MaxBytesReader` before parsing; a request whose body exceeds `maxUploadBytes` now fails at `ParseMultipartForm` with a 400 rather than being read in full. This is the "harden configuration" step from the loaded guidance and does not change behaviour for any request within the existing 20 MiB limit.
- A zero-byte upload (or one whose leading bytes don't match `http.DetectContentType`'s signatures for the three allowed types) is now rejected with 415 even if the client sends a matching `Content-Type` header, because the check is now based on sniffed content rather than the header. This is the intended effect of closing the weakness, not incidental.
- Removed `allowedContentTypes` (a `map[string]bool` keyed by client-supplied header value) and replaced it with `allowedUploadTypes` (a `map[string]string` keyed by server-detected type, valued by extension) - required by the guidance's allowlist-plus-extension-derivation pattern; the old map could not have supplied a safe extension even if retained.

## Verification

`go vet ./...` against the fixed file in an isolated module (own `go.mod`, package `main`, no other files) returned no diagnostics (exit 0). `go build` in that same isolated module fails only with "function main is undeclared in the main package" - expected and pre-existing, since this file is one handler file from a larger application and was never intended to build standalone; it is not a defect introduced by the fix. Every new identifier was checked against its source: `crypto/rand.Read`, `encoding/hex.EncodeToString`, and `http.MaxBytesReader` are Go standard library; `http.DetectContentType` and the `os.OpenFile`/`os.O_WRONLY|os.O_CREATE|os.O_EXCL` combination come from the loaded `cwe/434/go/INDEX.md` guidance; `multipart.File`'s `Seek` method (used via the `file` value returned by `r.FormFile`) is part of the standard `mime/multipart.File` interface (`io.Reader`, `io.ReaderAt`, `io.Seeker`, `io.Closer`).

## Assumptions

None - the finding's location, source, and sink were unambiguous from the provided code and SAST comment, and the fix follows the loaded root and Go-specific CWE-434 guidance directly without needing an unverified name or an unresolved ambiguity.
