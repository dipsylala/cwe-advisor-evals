## Verdict

Confirmed. `uploadAttachmentHandler` builds the on-disk save path with `filepath.Join(uploadDir, fileHeader.Filename)` using the client-supplied multipart filename verbatim, and it validates only the client-supplied `Content-Type` header, not the actual bytes uploaded. Both are attacker-controlled: a filename such as `../../../../etc/cron.d/evil` escapes `uploadDir` via `..` segments (and, depending on how the file is later served, could also traverse into a webroot the application intended to keep untouched), while a request can simply set `Content-Type: application/pdf` on a payload that is actually an executable or script, defeating the "recognized document or image type" check entirely.

## Source

- HTTP request to `POST /attachments/upload`, handled by `uploadAttachmentHandler` in `attachment_upload.go`.
- Tainted values:
  - `fileHeader.Filename` (line ~36, from `r.FormFile("attachment")`) — fully attacker-controlled, including path separators and `..` segments.
  - `fileHeader.Header.Get("Content-Type")` (line 45) — an attacker-supplied multipart part header, not derived from the actual file content.
- Sink: `destPath := filepath.Join(uploadDir, fileHeader.Filename)` (line 51) followed by `os.Create(destPath)` (line 53), which creates/overwrites a file at whatever path the attacker's filename resolves to, with content whose real type was never checked.

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
	"strings"
)

const uploadDir = "/var/app/data/attachments"

var allowedContentTypes = map[string]string{
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

	// Determine the file's real type by sniffing its content instead of
	// trusting the client-supplied Content-Type header, which an attacker
	// fully controls and can set to any allowed value regardless of the
	// bytes that follow.
	sniffBuf := make([]byte, 512)
	n, err := io.ReadFull(file, sniffBuf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		http.Error(w, "could not read attachment", http.StatusInternalServerError)
		return
	}
	sniffBuf = sniffBuf[:n]
	detectedType := http.DetectContentType(sniffBuf)

	ext, ok := allowedContentTypes[detectedType]
	if !ok {
		http.Error(w, "unsupported attachment type", http.StatusUnsupportedMediaType)
		return
	}

	// Ignore the client-supplied filename entirely for path construction.
	// Deriving the on-disk name from a fresh random value plus the
	// extension that matches the sniffed content type removes both the
	// path-traversal vector (no attacker-controlled path separators reach
	// filepath.Join) and the dangerous-type vector (the stored extension
	// always matches the verified content, never a spoofed one).
	name, err := randomFilename()
	if err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}
	destPath := filepath.Join(uploadDir, name+ext)

	// Defense in depth: confirm the resolved path still resides inside
	// uploadDir before creating anything on disk.
	cleanRoot := filepath.Clean(uploadDir) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(destPath), cleanRoot) {
		http.Error(w, "invalid attachment path", http.StatusBadRequest)
		return
	}

	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	if _, err := dest.Write(sniffBuf); err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "attachment saved as %s", filepath.Base(destPath))
}

// randomFilename returns a random hex-encoded identifier suitable for use
// as an on-disk filename, independent of any client-supplied input.
func randomFilename() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
```

## Explanation

The original code had two independent problems that combine into the reported finding:

1. **Path traversal via filename.** `filepath.Join(uploadDir, fileHeader.Filename)` does not strip `..` segments or reject absolute-style paths embedded in the filename; `filepath.Join` only lexically cleans the *result*, it does not sandbox it to `uploadDir`. A filename like `../../../../var/www/html/shell.php` (or an OS-specific absolute path) resolves outside the intended attachments directory, letting an attacker place a file wherever the process's write permissions allow, including a served webroot the application never intended to expose to uploads.

2. **Type check trusts an attacker-controlled label.** `fileHeader.Header.Get("Content-Type")` is a value the client sets in the multipart part and is not verified against the actual bytes. An attacker can label any payload (e.g., a script or HTML file that a misconfigured web server would execute or render) as `application/pdf` or `image/png` and sail through the `allowedContentTypes` check.

The fix removes both vectors instead of trying to patch around attacker-supplied strings:

- **Filename is no longer used for path construction at all.** A random 16-byte hex identifier (`randomFilename`) becomes the on-disk basename, so no attacker-controlled character — including path separators or `..` — ever reaches `filepath.Join`. This is stronger than sanitizing the original filename because there is no sanitizer to bypass; the original filename plays no role in the resulting path. Defense in depth is still applied: the resolved path is re-checked with `filepath.Clean` and a `strings.HasPrefix(..., uploadDir + separator)` guard before any filesystem call, so even a future refactor that reintroduces user input into the path cannot silently regress.
- **Type is determined from content, not from the header.** The first 512 bytes are read and passed to `http.DetectContentType` (Go's standard MIME sniffer, same algorithm the `net/http` server itself uses for automatic `Content-Type` detection), and the *detected* type — not the client's claimed type — is what is checked against `allowedContentTypes`. This also fixes the extension: the stored file's extension is derived from the verified detected type (`.pdf`, `.png`, `.jpg`), so the extension can never disagree with the actual content, which closes the "dangerous type" half of CWE-434 (e.g., an executable relabeled as an image can no longer be stored with a misleading benign-looking name or type).
- The originally-read sniff buffer (`sniffBuf`) is written first, followed by the remainder of the stream via `io.Copy`, so no bytes are lost by having consumed the first 512 bytes for detection.
- `os.OpenFile` with `O_CREATE|O_EXCL` additionally prevents overwriting an existing file at the same path (relevant even though the name is now random, as a defense against ID collisions or symlink pre-staging) and sets restrictive `0o600` permissions instead of the previous default from `os.Create` (`0666` before umask).
- The response still reports the saved name via `filepath.Base(destPath)`, but that name is now the generated random identifier plus verified extension, so it discloses nothing attacker-controlled and cannot itself be used to probe the filesystem layout.
