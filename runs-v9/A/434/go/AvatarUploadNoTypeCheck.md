## Verdict

Confirmed. `avatarUploadHandler` writes an uploaded file straight into `avatarDir` using the client-supplied `header.Filename`, with no check on file type, content, or extension. Since `avatarDir` is served back to the world unmodified via `http.FileServer`, an attacker can upload any file - including an `.html` or `.svg` payload that the server will happily serve with a browser-executable content type - producing stored XSS (and, depending on deployment, worse if any adjacent process ever executes files from that directory). The filename is also used unsanitized, which separately risks path traversal / overwrite of arbitrary files under `avatarDir` (CWE-22/CWE-73 adjacent, but it compounds the same sink).

## Source

`r.FormFile("avatar")` at line 23 returns `header.Filename`, which is fully attacker-controlled multipart form data - never validated for extension, MIME type, or content before use.

## Fix

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

// allowedAvatarTypes maps sniffed content types to the extension we persist.
// Only image types we are prepared to serve back are permitted.
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
	n, err := file.Read(sniffBuf)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}
	contentType := http.DetectContentType(sniffBuf[:n])

	ext, ok := allowedAvatarTypes[contentType]
	if !ok {
		http.Error(w, "unsupported file type", http.StatusUnsupportedMediaType)
		return
	}

	// Rewind so the copy below writes the full file, sniffed bytes included.
	if seeker, ok := file.(io.Seeker); ok {
		if _, err := seeker.Seek(0, io.SeekStart); err != nil {
			http.Error(w, "could not save file", http.StatusInternalServerError)
			return
		}
	}

	// Generate a fresh, server-controlled filename. This removes the
	// client-supplied name from the path entirely, closing both the
	// dangerous-type upload and any path-traversal/overwrite risk from
	// header.Filename.
	nameBytes := make([]byte, 16)
	if _, err := rand.Read(nameBytes); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	safeName := hex.EncodeToString(nameBytes) + ext
	destPath := filepath.Join(avatarDir, safeName)

	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, `{"filename":"%s"}`, safeName)
	w.WriteHeader(http.StatusCreated)
}
```

## Explanation

Two changes close the finding:

1. **Content-based type check, not filename/header trust.** `http.DetectContentType` sniffs the first 512 bytes of the actual file content and is checked against an explicit allowlist of image MIME types (`allowedAvatarTypes`). The client-supplied `Content-Type` header and the filename's extension are never consulted, since both are attacker-controlled and easy to spoof. Anything that doesn't sniff as one of the permitted image types (in particular `text/html`, `image/svg+xml`, or any script-bearing content) is rejected with `415 Unsupported Media Type` before any bytes are written to disk.

2. **Server-generated filename.** `header.Filename` is dropped from the write path entirely; the destination name is a random 16-byte hex string plus the extension implied by the sniffed, allowlisted content type. This both prevents a dangerous extension (`.html`, `.svg`, `.php`, etc.) from ever reaching the directory the file server serves, and incidentally removes the path-traversal/overwrite exposure that came from joining an unsanitized client filename into `avatarDir`. `os.O_EXCL` additionally guarantees the random name can't collide with and silently overwrite an existing avatar.

After the fix, only files that are genuinely one of the four allowlisted image types can be written under `avatarDir`, and they are always stored (and later served) under a name the server chose - so `http.FileServer` can no longer be induced to serve attacker-supplied HTML/SVG/script content as if it were a static avatar image.
