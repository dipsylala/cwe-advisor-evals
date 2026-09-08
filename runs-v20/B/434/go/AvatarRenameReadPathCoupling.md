## Verdict

Confirmed. `UploadAvatar` in `avatar_upload.go` writes an uploaded file to disk using the client-supplied `header.Filename` joined onto a fixed storage directory, with no check on the file's actual content type. Any file type the client cares to send - including a script or web-executable file - is accepted and persisted under the caller's own extension. CWE-434 (Unrestricted Upload of File with Dangerous Type).

Assumption (autonomous mode, no human available to confirm): the two files form one logical avatar-storage module - `avatar_upload.go` writes under `storageDir` and `avatar_lookup.go` reads back from the same `storageDir` by filename. The rename required to fix the upload side therefore has a direct effect on the read side, so both files are addressed together rather than in isolation.

## Source

`r.FormFile("avatar")` in `UploadAvatar` (avatar_upload.go:14) yields `header.Filename`, the client-supplied original filename from the multipart part. This value is attacker-controlled and carries no verified relationship to the file's actual content.

## Fix

### File: avatar_upload.go

```go
package avatars

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const storageDir = "/var/app-data/avatars"

// Maximum accepted request body size and the memory ParseMultipartForm may use
// before spilling to disk, enforced before the upload is read at all.
const maxUploadBytes = 5 << 20 // 5 MiB
const maxMemoryBytes = 1 << 20 // 1 MiB

// allowedAvatarTypes maps a server-detected content type to the extension used
// for storage. The stored extension controls how the file is later served, so
// it comes from this allowlist rather than from the client-supplied filename.
var allowedAvatarTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
}

func UploadAvatar(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxMemoryBytes); err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}

	sniffLen := 512
	if len(data) < sniffLen {
		sniffLen = len(data)
	}
	contentType := http.DetectContentType(data[:sniffLen])
	ext, ok := allowedAvatarTypes[contentType]
	if !ok {
		http.Error(w, "unsupported file type", http.StatusUnsupportedMediaType)
		return
	}

	storedName, err := generateStoredFilename(ext)
	if err != nil {
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}

	dest := filepath.Join(storageDir, storedName)
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	if _, err := out.Write(data); err != nil {
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}

	// Return the server-generated name: the client's original filename was
	// never used as the storage path, so callers must use this name (not the
	// upload's original filename) for any later retrieval.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"filename":%q}`, storedName)
}

// generateStoredFilename builds a random, server-controlled storage name so the
// client-supplied filename is never used as, or folded into, a filesystem path.
func generateStoredFilename(ext string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw) + ext, nil
}
```

### File: avatar_lookup.go

```go
package avatars

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ReadAvatarBytes reads back an avatar previously written by UploadAvatar.
// storedFilename must be the server-generated name returned at upload time
// (see UploadAvatar), not the upload's original, client-supplied filename -
// that value was never used as the storage name.
func ReadAvatarBytes(storedFilename string) ([]byte, error) {
	if storedFilename == "" || strings.ContainsAny(storedFilename, "/\\") {
		return nil, errors.New("invalid avatar filename")
	}

	path := filepath.Join(storageDir, storedFilename)
	if filepath.Dir(path) != filepath.Clean(storageDir) {
		return nil, errors.New("invalid avatar filename")
	}

	return os.ReadFile(path)
}
```

## Explanation

The original handler trusted two client-supplied values it never verified: `header.Filename` as the storage path and (implicitly) whatever byte content the client sent, with no check that it was actually image data. That let an attacker upload any file type - a script, an HTML document carrying active content, or a web shell - under any name and extension of their choosing, satisfying CWE-434.

The fix applies the standard library allowlist-by-content pattern from the Go CWE-434 guidance: `http.DetectContentType` sniffs the first 512 bytes of the uploaded data and the result is checked against `allowedAvatarTypes`, a fixed map of accepted image MIME types to their storage extensions. Only the detected type decides the extension - `filepath.Ext(header.Filename)` is never consulted, so a client cannot pick a dangerous extension merely by naming the upload accordingly. The storage name itself is generated from `crypto/rand`, so the client-supplied filename (which could carry path separators or traversal sequences) never reaches the filesystem path at all. The file is written with `os.OpenFile(..., os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)` so an unexpected name collision fails closed instead of silently overwriting an existing file. `http.MaxBytesReader` plus an explicit `ParseMultipartForm` memory limit bound the request before any of this runs.

Renaming the file on write breaks any caller that still looks the upload up by its original name, which is exactly the coupling this case is named for: `avatar_lookup.go`'s `ReadAvatarBytes` joins its `filename` argument onto the same `storageDir` used at upload time. `UploadAvatar` now returns the generated `storedName` in its JSON response so a caller has a value to look the file up by afterward, and `ReadAvatarBytes`'s parameter is renamed from `originalFilename` to `storedFilename` to document that it must receive that generated name, not the upload's original client-supplied filename. As defence in depth for this same sink - it joins a caller-supplied string onto `storageDir` exactly as the vulnerable write did - `ReadAvatarBytes` now rejects any filename containing a path separator and verifies the joined path's parent directory is still `storageDir` before reading, so even a caller that mistakenly passes attacker-controlled input cannot traverse out of the avatar directory.

## Behaviour changes

- The response body for a successful upload changes from an empty `201 Created` to a `201 Created` with a JSON body `{"filename":"<generated-name>"}`. Any caller must be updated to read and persist this generated name in order to retrieve the avatar later - this is required by the rename fix, not incidental.
- Non-image uploads (previously accepted unconditionally) are now rejected with `415 Unsupported Media Type`.
- Uploads whose total request body exceeds 5 MiB are now rejected with `400 Bad Request` (from `MaxBytesReader`/`ParseMultipartForm` failing) instead of being processed to any size.
- Stored files use a randomly generated name and an extension drawn from `allowedAvatarTypes`, never the client's original filename or its extension; any external system that expected the original filename to be preserved on disk needs to use the returned generated name instead.
- `ReadAvatarBytes`'s parameter is renamed from `originalFilename` to `storedFilename` and now returns an error for any filename containing `/` or `\`, or one that would resolve outside `storageDir`, where it previously attempted the read with `filepath.Join` regardless.
- Verified: `gofmt -l`, `go vet ./...`, and `go build ./...` all ran clean against both fixed files in a scratch module.
