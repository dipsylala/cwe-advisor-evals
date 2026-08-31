## Verdict

Confirmed. `avatarUploadHandler` writes an uploaded file to disk using the client-supplied filename and content, with no check on file type (extension or content) before saving. Because `avatarDir` is also served statically via `http.FileServer`, an attacker can upload a file with a dangerous type (e.g. `.html`, `.svg`, `.js`) and have it served back and interpreted by browsers that fetch `/avatars/<name>`, or overwrite an unexpected path if the filename contains traversal sequences.

## Source

`e:/Github/cwe-advisor/evals/cases/434/go/AvatarUploadNoTypeCheck/AvatarUploadNoTypeCheck.go`, `avatarUploadHandler`:

- Source: `header.Filename` from `r.FormFile("avatar")` (line 23) — fully attacker-controlled, multipart `Content-Disposition` filename field.
- Sink: `os.Create(destPath)` (line 32) where `destPath := filepath.Join(avatarDir, header.Filename)` (line 30), followed by `io.Copy(dest, file)` (line 39) writing the raw uploaded bytes verbatim.
- No validation of MIME/content type, no extension allowlist, and the destination filename is derived directly from user input rather than generated server-side.

## Fix

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const avatarDir = "./public/avatars"

// allowedAvatarTypes maps sniffed content types to the extension we persist.
// Only these image types may be served back from the avatars directory.
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
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Sniff the real content type from the file bytes; never trust the
	// client-supplied filename or the multipart Content-Type header.
	sniffBuf := make([]byte, 512)
	n, err := io.ReadFull(file, sniffBuf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}
	sniffBuf = sniffBuf[:n]
	contentType := http.DetectContentType(sniffBuf)

	ext, ok := allowedAvatarTypes[contentType]
	if !ok {
		http.Error(w, "unsupported file type", http.StatusUnprocessableEntity)
		return
	}

	// Generate the destination filename server-side so it can never carry a
	// path-traversal sequence or a dangerous extension chosen by the client.
	nameBytes := make([]byte, 16)
	if _, err := rand.Read(nameBytes); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	destPath := filepath.Join(avatarDir, hex.EncodeToString(nameBytes)+ext)

	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	// Write back the bytes already consumed while sniffing, then the rest.
	if _, err := dest.Write(sniffBuf); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
```

## Explanation

The original handler trusted two things it should not have: the uploaded content's type, and the client-supplied filename. Both feed the vulnerability independently, so the fix addresses each:

- **Type enforcement by content, not by extension or declared MIME type.** `http.DetectContentType` inspects the actual leading bytes of the file (magic numbers), which cannot be spoofed by renaming a file or setting an arbitrary `Content-Type` part header the way a client-declared value can. Only a small allowlist of genuine image types is accepted; everything else — including HTML, SVG (which can carry `<script>`), or any polyglot file — is rejected with `422 Unprocessable Entity`.
- **Server-generated filename, not client-supplied.** `header.Filename` is discarded entirely. The destination name is a random hex string plus the extension implied by the *verified* content type. This removes the path-traversal surface (`../../` sequences, absolute paths, null bytes) as well as the dangerous-extension surface (`.html`, `.php`, `.svg`, double extensions like `avatar.jpg.html`) in one step, since the filename written to disk is never derived from attacker input.
- **Sniffing without losing data.** `http.DetectContentType` only needs the first 512 bytes, so those bytes are read once via `io.ReadFull`, checked, then written to the destination file before the remainder of the stream is copied with `io.Copy` — the full upload is still persisted correctly.
- **Defense in depth.** Because `avatarDir` is served statically, restricting to real image types also prevents any uploaded file from being interpreted as executable content (script, markup) by a browser fetching `/avatars/<name>`, even though the storage location itself is unchanged.

Verification: attempt to upload a file whose first bytes are `<script>alert(1)</script>` (or a valid PNG renamed to `.html`) and confirm the handler now returns `422` and nothing is written under `public/avatars`; then upload a real JPEG/PNG and confirm it is saved under a random `.jpg`/`.png` name and served correctly from `/avatars/<name>`.
