## Verdict

Exploitable. Confidence: high.

## Source

`avatarUploadHandler` in `AvatarUploadNoTypeCheck.go`, lines 23-30:

- `file, header, err := r.FormFile("avatar")` (line 23) — the uploaded file and its client-supplied `multipart.FileHeader`.
- `header.Filename` (line 30) — attacker-controlled multipart part metadata, used unmodified as the storage filename via `filepath.Join(avatarDir, header.Filename)`.
- The handler never reads the file's content or inspects `header.Header.Get("Content-Type")` before writing it to disk, so no type check exists anywhere on this path.

## Fix

Vulnerable code (lines 17-41 of the original file):

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
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const avatarDir = "./public/avatars"
const maxUploadBytes = 10 << 20 // 10 MiB

// allowedAvatarTypes maps a sniffed content type to the extension used for
// storage. The extension is never taken from the client-supplied filename.
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

	sniff := make([]byte, 512)
	n, err := file.Read(sniff)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}
	contentType := http.DetectContentType(sniff[:n])

	ext, ok := allowedAvatarTypes[contentType]
	if !ok {
		http.Error(w, "unsupported file type", http.StatusUnsupportedMediaType)
		return
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	nameBytes := make([]byte, 16)
	if _, err := rand.Read(nameBytes); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	storedName := hex.EncodeToString(nameBytes) + ext
	destPath := filepath.Join(avatarDir, storedName)

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
}
```

## Explanation

The handler trusted `header.Filename` as both the storage name and (implicitly) the file type, and performed no content inspection, so any file — including an executable script or a web shell — could be written into `avatarDir`, a directory served directly and statically by `http.FileServer` in `init()`. The fix reads the first 512 bytes of the opened upload and passes them to `http.DetectContentType`, comparing the result against a fixed allowlist of image MIME types; anything else is rejected with `415 Unsupported Media Type` before any file is created. Once a type passes, the file is rewound with `file.Seek(0, io.SeekStart)` so the full content (not just the sniffed prefix) is written. The storage filename and its extension are both generated server-side — 16 random bytes from `crypto/rand` hex-encoded, plus the extension taken from the `allowedAvatarTypes` map keyed by the detected type — so `header.Filename` is never used for anything, closing both the dangerous-type upload and the path-traversal exposure that came from joining an attacker-controlled filename into the storage path. `os.Create` is replaced with `os.OpenFile(..., os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)` per the language guidance, so the write fails closed on a (practically impossible) name collision instead of silently overwriting a file, and the stored file gets restrictive permissions rather than the default from `os.Create`. The `avatarDir` is still served directly by the unchanged `http.FileServer` in `init()` — the guidance's stronger recommendation is to move storage outside the webroot entirely and serve uploads through an application-controlled handler, which would require restructuring how avatars are served and was left out as beyond the scope of this fix; with only sniffed, allowlisted image types ever reaching disk, the specific dangerous-type-execution risk the finding reports is closed, but this residual architectural point is worth a follow-up.

## Behaviour changes

- Only `image/jpeg`, `image/png`, `image/gif`, and `image/webp` content (by sniffed signature, not by extension or client `Content-Type`) is now accepted; every other upload is rejected with `415 Unsupported Media Type`. This is the fix itself.
- The stored filename is now a server-generated 32-hex-character name plus an extension taken from the detected type; the client-supplied filename is no longer used for storage or as a display value. Necessary to remove the attacker-controlled storage path and the traversal exposure it carried.
- `os.Create` (which truncates or silently overwrites an existing file, default permissive mode before umask) is replaced with `os.OpenFile(..., O_WRONLY|O_CREATE|O_EXCL, 0o600)`, which fails instead of overwriting on a name collision and stores with owner-only permissions. Collisions are not expected given the 128-bit random name, but failing closed here costs nothing and matches the language guidance's prescribed sink.
- `r.ParseMultipartForm`'s memory bound is now paired with `http.MaxBytesReader(w, r.Body, maxUploadBytes)` on the request body, so an oversized request is rejected while streaming instead of only after being buffered. This is the language guidance's explicit hardening step, not part of the core type-check fix.
- `io.Copy`'s error return is now checked and turned into a `500` response; the original discarded it and still returned `201 Created` even if the copy failed partway. This surfaces a failure the original silently hid rather than changing any successful-path behaviour.
- The success response (`201 Created` with an empty body) is unchanged for a valid, allowlisted upload.
