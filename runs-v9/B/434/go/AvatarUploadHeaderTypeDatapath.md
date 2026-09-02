## Verdict

- **cwe_id**: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **location**: `avatar_handler.go:21` (validation), sink at `avatar_store.go:14-15`
- **verdict**: exploitable
- **confidence**: high

The handler gates the upload only on `header.Header.Get("Content-Type")`, a value the client sets in the multipart part headers and can set to anything regardless of the file's real bytes. The file is then persisted under `header.Filename`, also client-supplied, unchanged. An attacker can send a part with `Content-Type: image/png` and `filename="shell.php"` (or `.aspx`, `.jsp`, etc.) containing arbitrary executable content; the check at line 22 passes because it only inspects the declared header, and `AvatarStore.Save` writes the file to `filepath.Join(s.Dir, "shell.php")` with that exact name and extension. If `AvatarStore.Dir` is inside a path the web server executes or serves directly, this results in remote code execution or stored active content; even where it is not, the stored extension is fully attacker-chosen with no server-side check ever inspecting the actual file content.

## Source

- **Source**: the `avatar` multipart form field on the incoming `http.Request` — specifically `multipart.FileHeader.Header.Get("Content-Type")` and `multipart.FileHeader.Filename`, both attacker-controlled multipart part metadata that Go's `net/http` does not verify.
- **Data flow**: `r.FormFile("avatar")` (avatar_handler.go:14) → `header.Header.Get("Content-Type")` compared against a two-value allowlist (avatar_handler.go:21-22, the reported line) → `store.Save(header.Filename, file)` (avatar_handler.go:27) → `os.Create(filepath.Join(s.Dir, filename))` (avatar_store.go:14-15), which writes the uploaded bytes under the client-supplied name and extension with no server-side content inspection anywhere in the chain.
- **Sink contract** (`AvatarStore.Save`): returns `(filename, nil)` on success, using the same string passed in — the handler echoes this back to the caller in the response body (line 34). It discards nothing security-relevant beyond permission control: `os.Create` uses the default `0666`-masked permissions and truncates unconditionally if the target already exists, so a same-name second upload silently overwrites the first. On error it returns `("", err)`, which the handler maps to a 500. No argument constrains the filename's characters, so path separators or traversal sequences in `header.Filename` reach `filepath.Join` unfiltered.

## Fix

**avatar_handler.go**

```go
// Vulnerable
contentType := header.Header.Get("Content-Type")
if contentType != "image/png" && contentType != "image/jpeg" {
    http.Error(w, "unsupported avatar", http.StatusBadRequest)
    return
}

storedName, err := store.Save(header.Filename, file)
```

```go
// Fixed
package avatarupload

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
)

// allowedAvatarTypes maps a sniffed content type to the extension used for
// the stored file. The extension always comes from this map, never from the
// client-supplied Content-Type header or filename.
var allowedAvatarTypes = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
}

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

		sniff := make([]byte, 512)
		n, err := io.ReadFull(file, sniff)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}

		detectedType := http.DetectContentType(sniff[:n])
		ext, ok := allowedAvatarTypes[detectedType]
		if !ok {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		if _, err := file.Seek(0, io.SeekStart); err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		generatedName, err := randomFilename(ext)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		storedName, err := store.Save(generatedName, file)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}

func randomFilename(ext string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf) + ext, nil
}
```

**avatar_store.go**

```go
// Vulnerable
func (s *AvatarStore) Save(filename string, file io.Reader) (string, error) {
	target := filepath.Join(s.Dir, filename)
	out, err := os.Create(target)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		return "", err
	}

	return filename, nil
}
```

```go
// Fixed
package avatarupload

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

type AvatarStore struct {
	Dir string
}

func (s *AvatarStore) Save(filename string, file io.Reader) (string, error) {
	if strings.ContainsAny(filename, `/\`) {
		return "", os.ErrInvalid
	}

	target := filepath.Join(s.Dir, filename)

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		return "", err
	}

	return filename, nil
}
```

## Explanation

The fix moves file-type validation from a client-asserted header to the actual bytes on disk: the handler now reads the first 512 bytes of the opened multipart file and runs them through `http.DetectContentType`, which inspects magic-byte signatures, then checks the result against a fixed allowlist (`image/png`, `image/jpeg`) instead of trusting `header.Header.Get("Content-Type")`. Because the sniff consumes part of the stream, the file is rewound with `file.Seek(0, io.SeekStart)` before it is written, preserving the full-content write the sink contract requires. The stored filename is no longer the client-supplied `header.Filename` — it is generated from 16 bytes of `crypto/rand`, with the extension taken solely from the `allowedAvatarTypes` map keyed by the *detected* type, so the extension the filesystem (and any downstream server) sees is exactly the one the server determined it to be, never one the attacker chose. `AvatarStore.Save` additionally opens the destination with `os.O_EXCL` (fails rather than silently overwrites on a name collision) and `0o600` permissions, and rejects any filename containing a path separator as defence-in-depth, per the Go CWE-434 guidance's write-mode recommendation. Together these close the finding: an attacker can no longer choose the stored extension or bypass validation by spoofing a header, because neither the header nor the original filename reaches storage.

## Behaviour changes

- The value written to the response body and returned as `storedName` changes from the client's original filename to a server-generated `<32-hex-chars><ext>` name. Required because the fix removes the client-supplied filename from the write path entirely; the response still returns whatever name the file was actually stored under, so callers that read the response to locate the file are unaffected.
- `AvatarStore.Save` now fails with `os.ErrInvalid` if `filename` contains `/` or `\`, where it previously accepted any value including traversal sequences. This narrows the function's accepted input; since the only caller now passes a generated hex name, no legitimate call is affected.
- `AvatarStore.Save` now uses `os.OpenFile(..., os.O_EXCL, 0o600)` instead of `os.Create` (which is `O_TRUNC`-equivalent with `0666`-masked permissions). A second upload that happens to collide with an existing stored name now returns an error instead of silently overwriting it — collision probability is negligible with 128 bits of randomness — and stored files are now `0600` instead of world-readable-by-default, which is a stricter but compatible change since nothing in this code path read the file back by direct filesystem permission.
- The content-type check now inspects file bytes instead of the declared header; a small number of previously-accepted requests where the client's declared `Content-Type` matched but the actual bytes were not a real PNG/JPEG will now be rejected with `400 unsupported avatar` — this is the intended effect of the fix, not an unrelated side effect.

## Assumptions

- `avatarupload` package and Go language inferred directly from file extension and syntax; no ambiguity to resolve.
- Assumed `AvatarStore.Dir` is operator-configured and not itself attacker-influenced; the fix does not change how `Dir` is set.
- Assumed PNG and JPEG are the only business-required avatar types, matching the two values already allowlisted in the original code; extending the allowlist is a product decision left unchanged.
