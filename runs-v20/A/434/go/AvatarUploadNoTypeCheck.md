## Verdict
Confirmed. The handler writes an uploaded file to a web-served directory without checking its type, so a client can upload a script, HTML page, or other executable/active content under any filename and have it served back from `/avatars/`.

## Source
`r.FormFile("avatar")` in `avatarUploadHandler` (`AvatarUploadNoTypeCheck.go:23`) returns the uploaded file and its client-supplied `*multipart.FileHeader`. Both the file's content and `header.Filename` are fully attacker-controlled; neither the extension nor any `Content-Type` the client sends is verified before the file is written to disk.

## Fix

### File: AvatarUploadNoTypeCheck.go
```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const avatarDir = "./public/avatars"

// allowedAvatarTypes maps the sniffed content type to the extension the
// file is stored with. Only image types the avatar feature actually needs
// are accepted; everything else (HTML, SVG, executables, scripts, etc.)
// is rejected regardless of the filename or Content-Type header the
// client sent.
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

// sniffImageExtension reads the first 512 bytes of file to determine its
// real content type via content sniffing (http.DetectContentType), rather
// than trusting the client-supplied filename or form Content-Type. It
// returns the extension to store the file with, or an error if the
// content is not one of the allowed image types.
func sniffImageExtension(file io.ReadSeeker) (string, error) {
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	contentType := http.DetectContentType(buf[:n])
	ext, ok := allowedAvatarTypes[contentType]
	if !ok {
		return "", errors.New("unsupported file type: " + contentType)
	}
	return ext, nil
}

// randomAvatarFilename generates a filename that does not depend on any
// client-supplied input, eliminating both path traversal and any
// possibility of the stored name carrying an executable extension.
func randomAvatarFilename(ext string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw) + ext, nil
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

	ext, err := sniffImageExtension(file)
	if err != nil {
		http.Error(w, "unsupported file type", http.StatusBadRequest)
		return
	}

	filename, err := randomAvatarFilename(ext)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	destPath := filepath.Join(avatarDir, filename)
	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	io.Copy(dest, file)
	w.WriteHeader(http.StatusCreated)
}
```

## Explanation
The original handler trusted `header.Filename` for both the on-disk extension and the destination path, and never inspected the actual bytes of the upload. Because `/avatars/` is served statically, an attacker could upload `evil.html`, `x.svg`, or a file whose extension a downstream tool treats as executable, and have the server hand it back to any visitor with that content type.

The fix removes the client-supplied filename from the trust boundary entirely:

- **Type check via content sniffing**: `sniffImageExtension` reads the first 512 bytes and runs them through `http.DetectContentType`, which inspects the actual byte signature rather than trusting a header. Only four concrete image MIME types are accepted (`image/jpeg`, `image/png`, `image/gif`, `image/webp`); anything else is rejected with `400 Bad Request` before any data is written to disk.
- **Server-generated filename**: instead of joining `avatarDir` with `header.Filename`, the handler generates a random 16-byte hex name and appends the extension corresponding to the sniffed type. This also closes off path traversal (`../../etc/passwd`-style filenames) as a side effect, since the original name is never used to build a path.
- **Exclusive create with fixed permissions**: `os.OpenFile` uses `O_CREATE|O_EXCL` so two uploads can never collide on the same random name, and explicit `0o644` permissions keep the file non-executable regardless of the process umask.

To verify: an upload with an `image/png`-signed body (regardless of what filename or `Content-Type` field the client sends) succeeds and is stored with a `.png` extension; an upload of an HTML, SVG, or script payload is rejected with `400 Bad Request` and never reaches `avatarDir`.
