## Verdict

Confirmed. The handler decides whether an uploaded avatar is an image using only the client-supplied `Content-Type` header from the multipart part (`header.Header.Get("Content-Type")`), then hands the original, attacker-controlled filename straight to storage. Both signals are supplied by the requester and neither is checked against the file's actual bytes, so an attacker can upload an arbitrary file (e.g. a `.php`, `.jsp`, `.aspx`, or `.html` payload) by simply setting the multipart part's `Content-Type` header to `image/png` or `image/jpeg`, and it will be written to disk under whatever extension the attacker chose in the filename field.

## Source

`r.FormFile("avatar")` in `avatar_handler.go` line 14 returns `header`, a `*multipart.FileHeader` built entirely from client-supplied multipart form data. Its two fields used downstream — `header.Header.Get("Content-Type")` (line 21) and `header.Filename` (line 27) — are both attacker-controlled request data, not derived from the file's actual content.

## Fix

```go
// avatar_handler.go
package avatarupload

import (
	"net/http"
)

func UploadAvatarHandler(store *AvatarStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}

		file, _, err := r.FormFile("avatar")
		if err != nil {
			http.Error(w, "missing avatar", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Content type and stored filename are now derived entirely
		// server-side from the sniffed file bytes; the client-supplied
		// header and filename are never trusted.
		storedName, err := store.Save(file)
		if err != nil {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}
```

```go
// avatar_store.go
package avatarupload

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

type AvatarStore struct {
	Dir string
}

var allowedAvatarTypes = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
}

func (s *AvatarStore) Save(file io.Reader) (string, error) {
	// Sniff the real content type from the file's magic bytes; never
	// trust a client-supplied Content-Type header or filename.
	sniffBuf := make([]byte, 512)
	n, err := io.ReadFull(file, sniffBuf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", err
	}
	sniffBuf = sniffBuf[:n]

	detected := http.DetectContentType(sniffBuf)
	ext, ok := allowedAvatarTypes[detected]
	if !ok {
		return "", errors.New("unsupported avatar content type")
	}

	// Server-generated filename: the client never controls the name
	// or extension written to disk.
	nameBytes := make([]byte, 16)
	if _, err := rand.Read(nameBytes); err != nil {
		return "", err
	}
	filename := hex.EncodeToString(nameBytes) + ext
	target := filepath.Join(s.Dir, filename)

	out, err := os.Create(target)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := out.Write(sniffBuf); err != nil {
		return "", err
	}
	if _, err := io.Copy(out, file); err != nil {
		return "", err
	}

	return filename, nil
}
```

## Explanation

The original check validated a value the attacker fully controls: the `Content-Type` header on the multipart part is just a string the client sets in its request body, with no relationship enforced to the bytes that follow. An attacker can send a script, executable, or HTML payload with that header set to `image/png` and sail past the check. The stored filename came from the same untrusted source (`header.Filename`), so even if the content-type check had been meaningful, the file would still land on disk with an attacker-chosen extension (or, separately, an attacker-chosen path component).

The fix moves both decisions server-side and grounds them in the actual file content:

- **Content sniffing instead of header trust.** `http.DetectContentType` inspects the first 512 bytes of the file itself (magic numbers / signatures) rather than trusting anything the client asserts. Only bytes that genuinely look like PNG or JPEG are accepted, and the buffered prefix is written back out so no data is lost.
- **Server-derived filename and extension.** The stored filename is generated from random bytes plus an extension chosen by the store from a fixed allowlist keyed to the detected type — never from `header.Filename`. This removes the dangerous-extension vector entirely (no `.php`, `.jsp`, `.html`, double extensions, or path traversal via the filename) and also closes a path-traversal side channel that existed alongside the type-confusion issue.
- **Rejection, not stripping.** An unrecognized signature is rejected outright rather than coerced or sanitized into a "close enough" type, so there's no ambiguous file that partially passes validation.

Defense in depth for a production deployment would also include serving uploaded avatars from a directory with no execute permission and, ideally, from a separate origin/CDN with a fixed `Content-Type` and `Content-Disposition` response, so that even a sniffing bypass can't be interpreted as executable content by the browser or app server.
