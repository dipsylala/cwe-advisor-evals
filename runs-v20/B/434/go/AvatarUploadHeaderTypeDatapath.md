## Verdict

Confirmed. CWE-434 (Unrestricted Upload of File with Dangerous Type).

## Source

`avatar_handler.go:21` - `header.Header.Get("Content-Type")`, the `Content-Type` value from the `avatar` multipart part's own headers, as returned by `r.FormFile("avatar")`. This is metadata the client sets on the part itself; a request can carry any file content behind a part header that reads `Content-Type: image/png`.

## Fix

### File: avatar_handler.go

```go
package avatarupload

import (
	"io"
	"net/http"
)

const maxAvatarUploadBytes = 8 << 20

func UploadAvatarHandler(store *AvatarStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxAvatarUploadBytes)

		if err := r.ParseMultipartForm(maxAvatarUploadBytes); err != nil {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}

		file, _, err := r.FormFile("avatar")
		if err != nil {
			http.Error(w, "missing avatar", http.StatusBadRequest)
			return
		}
		defer file.Close()

		sniff := make([]byte, 512)
		n, err := io.ReadFull(file, sniff)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}
		contentType := http.DetectContentType(sniff[:n])

		if _, err := file.Seek(0, io.SeekStart); err != nil {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}

		storedName, err := store.Save(contentType, file)
		if err != nil {
			if err == errUnsupportedAvatarType {
				http.Error(w, "unsupported avatar", http.StatusBadRequest)
				return
			}
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}
```

### File: avatar_store.go

```go
package avatarupload

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

var errUnsupportedAvatarType = errors.New("unsupported avatar content type")

// allowedAvatarExtensions maps a sniffed content type to the extension used
// for storage. The extension always comes from this map, never from the
// client-supplied filename, since it decides how the file is served back.
var allowedAvatarExtensions = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
}

type AvatarStore struct {
	Dir string
}

// Save stores file under a generated name, using the extension mapped from
// contentType (the server-detected content type, not client-supplied
// metadata). It returns the generated filename or errUnsupportedAvatarType
// if contentType is not in the allowlist.
func (s *AvatarStore) Save(contentType string, file io.Reader) (string, error) {
	ext, ok := allowedAvatarExtensions[contentType]
	if !ok {
		return "", errUnsupportedAvatarType
	}

	name, err := randomAvatarFilename(ext)
	if err != nil {
		return "", err
	}

	target := filepath.Join(s.Dir, name)
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		return "", err
	}

	return name, nil
}

func randomAvatarFilename(ext string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf) + ext, nil
}
```

## Explanation

The handler validated only the multipart part's `Content-Type` header, a value the client sets and controls entirely - a request can declare `image/png` while the part body is a script, an HTML document, or any other executable content, so the check gated nothing. `Save` then wrote the file under `filepath.Join(s.Dir, filename)` using the client-supplied `Filename` unmodified, so the attacker also chose the stored name and extension, including any path separators or traversal sequences it carried.

The fix reads the first 512 bytes of the opened file and passes them to `http.DetectContentType`, which inspects the actual bytes rather than trusting any header, then checks the result against a fixed allowlist (`image/png`, `image/jpeg`). The client-supplied `Filename` is discarded entirely rather than sanitized: `Save` now takes the detected content type, not a filename, and generates a random 16-byte hex name whose extension comes from a fixed `map[string]string` keyed by the detected type - so the extension that decides how the file is later served can never be attacker-chosen, and there is no path-traversal surface left to close. The file is rewound with `file.Seek(0, io.SeekStart)` after sniffing so the full content is still written, and `os.OpenFile` with `O_WRONLY|O_CREATE|O_EXCL` replaces `os.Create` so the write cannot silently overwrite an existing file if a name were ever to collide. `http.MaxBytesReader` around `r.Body` is added ahead of `ParseMultipartForm`'s existing 8 MiB argument so an oversized request is rejected while reading the body, not only once buffered.

Checked names: `http.DetectContentType`, `http.MaxBytesReader`, `io.ReadFull`, `io.ErrUnexpectedEOF`, `io.SeekStart`, `crypto/rand.Read`, `encoding/hex.EncodeToString`, `os.OpenFile` with `os.O_WRONLY|os.O_CREATE|os.O_EXCL` are all Go standard library; no new third-party dependency is introduced. Both files were copied to a scratch module and checked with `go vet ./...` and `go build ./...`, both of which completed with no diagnostics.

## Behaviour changes

- The response body on a successful upload now returns a randomly generated filename (`<32 hex chars>.png` / `.jpg`) instead of echoing the client's original filename. Any caller that relied on the response being the original filename must switch to using the returned name to retrieve the stored file.
- A request whose part header claims a supported type but whose actual bytes are not PNG or JPEG now fails with `400 unsupported avatar` (correct rejection that the original code missed); conversely, a request whose part header claims an unsupported type but whose actual bytes are a real PNG/JPEG now succeeds - the check is on real content, not the client's declared value.
- Uploads are capped by `http.MaxBytesReader` in addition to the existing `ParseMultipartForm` limit, so an oversized request now fails earlier, while reading the body, rather than only once multipart parsing runs.
- `Save`'s signature changed from `Save(filename string, file io.Reader)` to `Save(contentType string, file io.Reader)`; any other caller of `AvatarStore.Save` needs updating to pass a detected content type rather than a filename.
