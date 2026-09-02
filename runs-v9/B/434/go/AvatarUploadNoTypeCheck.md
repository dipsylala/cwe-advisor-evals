## Verdict

CWE-434 (Unrestricted Upload of File with Dangerous Type) - **exploitable**. Confidence: high.

`avatarUploadHandler` writes an uploaded file to a directory that is served back verbatim by `http.FileServer`, using the client-supplied filename and with no check on the file's actual content. An attacker can upload a file with an executable or script extension (e.g. `shell.php`, `x.html`, `x.svg` with embedded script) and immediately retrieve it from `/avatars/<name>`, achieving stored content execution or script injection in visitors' browsers. The client-supplied `Filename` also permits path-separator/traversal sequences into `filepath.Join`, since nothing strips or rejects them.

## Source

- **Source**: `header.Filename` from `r.FormFile("avatar")` (line 23) - a client-controlled multipart part attribute, never validated.
- **Data flow**: `header.Filename` -> `destPath := filepath.Join(avatarDir, header.Filename)` (line 30) -> `os.Create(destPath)` (line 32, the reported sink) -> `io.Copy(dest, file)` (line 39) writes the raw request bytes to that path.
- **Sink**: `os.Create(destPath)`, inside `avatarDir` (`./public/avatars`), which `init()` registers as the document root of `http.FileServer` at `/avatars/` - so anything written there is served back to any client under the name it was stored with, with no code-level check of the client-supplied `Content-Type` header or the real file content anywhere on this path.

## Fix

Vulnerable code (`AvatarUploadNoTypeCheck.go`, lines 17-41):

```go
func avatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	destPath := filepath.Join(avatarDir, header.Filename)
	// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	io.Copy(dest, file)
	w.WriteHeader(http.StatusCreated)
}
```

Fixed code:

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

const avatarDir = "./public/avatars"
const maxUploadBytes = 10 << 20 // 10 MB

// Only these content types, detected from the file's actual bytes, may be
// stored as an avatar. The extension used for storage comes from this map,
// never from the client-supplied filename.
var allowedAvatarTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func init() {
	// Uploaded avatars are served back directly from this directory.
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir(avatarDir))))
}

func avatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Detect the real content type from the file's leading bytes; do not
	// trust the client-supplied filename or Content-Type header.
	sniff := make([]byte, 512)
	n, err := file.Read(sniff)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}
	ext, ok := allowedAvatarTypes[http.DetectContentType(sniff[:n])]
	if !ok {
		http.Error(w, "unsupported file type", http.StatusUnsupportedMediaType)
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not process file", http.StatusInternalServerError)
		return
	}

	// Generate the storage name; never use the client-supplied filename.
	nameBytes := make([]byte, 16)
	if _, err := rand.Read(nameBytes); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	generatedName := hex.EncodeToString(nameBytes) + ext
	destPath := filepath.Join(avatarDir, generatedName)

	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"filename":%q}`, generatedName)
}
```

No third-party library is required; the fix uses only the Go standard library (`net/http`, `crypto/rand`, `encoding/hex`).

## Explanation

The original handler trusted the client-supplied `header.Filename` both as the storage path and, implicitly, as the file's type - it never inspected the bytes it was about to write into a directory served directly by `http.FileServer`. The fix reads the first 512 bytes of the uploaded file and passes them to `http.DetectContentType`, checking the result against a fixed allowlist of image MIME types; anything else is rejected with `415 Unsupported Media Type` before any bytes are written. The storage filename is no longer taken from the client: a random 16-byte hex name is generated, and its extension is taken from the allowlist map keyed by the detected type - so the attacker no longer controls either the path (removing the path-traversal risk from `header.Filename`) or the extension the file is later served under (removing the ability to store a `.html`, `.svg`, or executable-looking file that would run or execute when fetched back through `/avatars/`). `os.Create` is replaced with `os.OpenFile(..., O_WRONLY|O_CREATE|O_EXCL, 0o600)` per the Go-specific guidance, and the stream is rewound with `file.Seek(0, io.SeekStart)` after sniffing so the full, untruncated file is written.

## Behaviour changes

- Requests are now capped at 10 MB by `http.MaxBytesReader` in addition to the existing `ParseMultipartForm` memory threshold. Previously a multipart body larger than 10 MB would still be accepted (the excess spooled to a temp file); now the connection is closed and the request rejected outright. Reason: hardening per the Go-specific guidance, closing an unbounded-storage exposure that exists alongside the type-confusion issue.
- Non-image uploads (or images whose real content doesn't match an allowed type) are now rejected with `415 Unsupported Media Type` where they previously succeeded with `201 Created`. Reason: this is the core fix - closing CWE-434.
- The stored filename is now a random hex string with an extension taken from the detected type, instead of the client-supplied filename and extension. Reason: core fix - removes attacker control over storage path and served extension; also closes an incidental path-traversal exposure in the original `filepath.Join(avatarDir, header.Filename)`.
- The success response body now contains `{"filename":"<generated-name>"}`; the original returned `201 Created` with no body. Reason: required to preserve retrievability - callers previously knew the avatar's URL because they had supplied its filename, and are told the file's real URL segment.
- File creation now uses `os.OpenFile` with `O_EXCL`, which fails if a file already exists at the generated path, instead of `os.Create`, which silently overwrites. Reason: guidance-prescribed to avoid overwriting another file on a name collision; collision probability is negligible with a 16-byte random name.
- `io.Copy`'s error return is now checked and turned into a `500` response; the original discarded it. Reason: incidental correctness fix needed so a write failure doesn't still report `201 Created`.
