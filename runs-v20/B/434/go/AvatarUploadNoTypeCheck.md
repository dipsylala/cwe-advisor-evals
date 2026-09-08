## Verdict

Exploitable. Confidence: high.

## Source

- **Source**: the multipart file part `avatar`, read via `r.FormFile("avatar")` (line 23). The attacker fully controls both the file's bytes and its `Filename` metadata (`header.Filename`).
- **Sink**: `os.Create(destPath)` (line 32), where `destPath := filepath.Join(avatarDir, header.Filename)` (line 30).
- **Data flow**: `header.Filename` and the raw file bytes reach the sink with no check of any kind - no content-type/signature verification, no filename sanitization, no extension allowlist. `avatarDir` (`./public/avatars`) is mounted directly and unauthenticated at `/avatars/` via `http.FileServer` (line 14), so anything written there is immediately fetchable by URL. An attacker can upload a file named e.g. `x.html` or `x.svg` containing script and retrieve it from `/avatars/x.html` for a same-origin stored-XSS/web-shell-style delivery, and `header.Filename` also flows unsanitized into `filepath.Join`, giving a secondary path-traversal exposure on the write path.
- **Sink contract before the fix**: `os.Create` returns a writable `*os.File` truncated/created at `destPath` (0666 before umask) or an error; the handler discards nothing meaningful, but it also never records or returns the stored name, and `header.Filename`/content-type are left completely unchecked (both defaults are "trust the client"). Failure returns `500` with no further detail.

## Fix

### File: AvatarUploadNoTypeCheck.go

```go
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const avatarDir = "./public/avatars"
const maxUploadBytes = 10 << 20 // 10 MiB

// allowedAvatarTypes maps a server-detected content type to the extension
// used for storage. Only genuine, decodable image formats are accepted.
var allowedAvatarTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
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

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}

	sniffLen := 512
	if len(data) < sniffLen {
		sniffLen = len(data)
	}
	contentType := http.DetectContentType(data[:sniffLen])

	ext, ok := allowedAvatarTypes[contentType]
	if !ok {
		http.Error(w, "unsupported file type", http.StatusBadRequest)
		return
	}

	// Decode and re-encode the image so any payload hidden past the
	// leading bytes (a polyglot, embedded script, or trailing data) is
	// discarded rather than written to disk verbatim.
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		http.Error(w, "invalid image data", http.StatusBadRequest)
		return
	}

	name, err := randomFilename()
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	storedName := name + ext
	destPath := filepath.Join(avatarDir, storedName)

	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	switch contentType {
	case "image/jpeg":
		err = jpeg.Encode(dest, img, nil)
	case "image/png":
		err = png.Encode(dest, img)
	case "image/gif":
		err = gif.Encode(dest, img, nil)
	}
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(storedName))
}

// randomFilename generates an unpredictable storage name so the client's
// original filename (and any path separators or traversal sequences it
// might contain) is never used to build a filesystem path.
func randomFilename() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
```

## Explanation

The handler trusted the client on every axis that matters for this weakness: it never inspected the file's actual content, and it used the client-supplied `header.Filename` verbatim to build the on-disk path inside a directory served directly to the internet. The fix reads the uploaded bytes, calls `http.DetectContentType` on the leading bytes and checks the result against a fixed allowlist of real image types (`image/jpeg`, `image/png`, `image/gif`), then decodes and re-encodes the image with Go's standard `image`/`jpeg`/`png`/`gif` packages - which discards anything in the file beyond a valid image payload, closing the polyglot gap that a signature check alone would miss. The stored filename and its extension are both generated server-side (a random hex string plus the extension mapped from the detected type), so `header.Filename` no longer reaches the filesystem at all, eliminating both the arbitrary-extension upload and the path-traversal exposure in the same change. `os.Create` is replaced with `os.OpenFile(..., O_WRONLY|O_CREATE|O_EXCL, 0o600)` writing under the generated name, and the request body is capped with `http.MaxBytesReader` ahead of `ParseMultipartForm` as defence-in-depth against oversized uploads.

## Behaviour changes

- `header` from `r.FormFile` is now discarded (`_`) since the original filename is never used for storage - required to remove the tainted value from the write path.
- Added `http.MaxBytesReader(w, r.Body, maxUploadBytes)` ahead of `ParseMultipartForm` - the original only bounded multipart memory buffering (`10 << 20`) but not the total request size; this rejects an oversized request earlier. Reason: Go guidance's hardening step.
- New gate: file bytes are read fully, sniffed with `http.DetectContentType`, and checked against an allowlist of `image/jpeg`, `image/png`, `image/gif`. A request with any other detected type (or an undecodable image) is now rejected with `400` instead of being written to disk. This is the core weakness fix, not incidental.
- The accepted image is decoded and re-encoded before being written, which normalizes/re-compresses it - a legitimate upload's exact original bytes are not preserved bit-for-bit (e.g. embedded EXIF metadata or animation timing subtleties in an unusual GIF may be dropped by Go's encoder). This is intentional per the loaded guidance ("re-encode formats that can carry active content before trusting them") and is the trade-off that removes polyglot payloads a signature check alone cannot catch.
- Storage path and extension are now always `<random-hex>.jpg|.png|.gif` instead of `avatarDir/<client filename>`. Any existing code path (not present in this file) that located a stored avatar by the name the client originally uploaded would break; the fix compensates by returning the generated name.
- Response body changes from empty (`w.WriteHeader(http.StatusCreated)` only) to the generated stored filename written after the same status. Reason: avatars are served back by name from `/avatars/`, so the caller has no way to retrieve a file stored under a name it never chose unless the server tells it that name - required to preserve the read path per the Go guidance's "preserve the caller's contract" step, not an unrelated addition.
- `os.Create` (mode 0666 before umask, truncates or creates) is replaced by `os.OpenFile(..., O_WRONLY|O_CREATE|O_EXCL, 0o600)` (fails instead of truncating if the generated name already exists; owner-only permissions). Given the name space is a random 128-bit hex string, a collision is not realistically reachable, and no code here reads permissions or relies on truncation semantics, so this only tightens the existing "create a new file" contract.

**Verification**: `go vet ./...` and `gofmt -l` were run against the fixed file in an isolated scratch Go module (outside the repository and outside the case directory) and both completed cleanly (`go vet` exit 0 with no diagnostics; `gofmt -l` produced no output, i.e. no formatting differences). A full `go build` was not attempted because, like the original file, this is a single-file package snippet with no `main` function - the same limitation applies to the unmodified original. Every new import (`bytes`, `crypto/rand`, `encoding/hex`, `image`, `image/gif`, `image/jpeg`, `image/png`) is Go standard library, and each new call (`http.MaxBytesReader`, `http.DetectContentType`, `image.Decode`, `jpeg.Encode`, `png.Encode`, `gif.Encode`, `rand.Read`, `hex.EncodeToString`, `os.OpenFile`) was checked against its standard-library signature during the vet pass.

**Assumptions**: The allowlist is restricted to JPEG/PNG/GIF, the formats Go's standard library can decode/encode without a third-party dependency; if the product requires WebP or other formats, a maintained image library would need to be added and its decoder registered the same way. The route registration and any caller that consumes the upload response are not shown in this file, so returning the stored filename as a plain-text response body was chosen as the minimal way to satisfy the "caller can still retrieve the file" requirement - if the codebase has an existing JSON response convention elsewhere, the body format should be adjusted to match it.
