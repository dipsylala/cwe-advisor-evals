## Verdict

Exploitable. The handler validates the file's content type by checking the client-supplied `Content-Type` header (line 21-25), which is an attacker-controlled multipart form header and not verified by the Go standard library. An attacker can upload any file while spoofing the header as `image/png` or `image/jpeg`, bypassing the check entirely. Additionally, the client-supplied filename is passed directly to storage without validation or generation of a safe name.

## Source

Client-supplied `Content-Type` header from the multipart form, retrieved via `header.Header.Get("Content-Type")` at line 21 of `avatar_handler.go`.

## Fix

**Vulnerable code (avatar_handler.go, lines 21-27):**

```go
contentType := header.Header.Get("Content-Type")
if contentType != "image/png" && contentType != "image/jpeg" {
	http.Error(w, "unsupported avatar", http.StatusBadRequest)
	return
}

storedName, err := store.Save(header.Filename, file)
```

**Fixed code (avatar_handler.go):**

```go
// Detect actual content type by reading file's leading bytes
buf := make([]byte, 512)
n, err := file.Read(buf)
if err != nil && err != io.EOF {
	http.Error(w, "failed to read file", http.StatusInternalServerError)
	return
}

// Inspect the actual file content, not the client-supplied header
detectedType := http.DetectContentType(buf[:n])

// Allowlist permitted MIME types and their extensions
allowedTypes := map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpeg",
}

ext, allowed := allowedTypes[detectedType]
if !allowed {
	http.Error(w, "unsupported avatar", http.StatusBadRequest)
	return
}

// Rewind the file for reading again during save
if _, err := file.Seek(0, io.SeekStart); err != nil {
	http.Error(w, "upload failed", http.StatusInternalServerError)
	return
}

// Generate a new filename and pass the detected extension
storedName, err := store.Save(file, ext)
```

**Updated avatar_store.go to accept generated filename:**

```go
package avatarupload

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

type AvatarStore struct {
	Dir string
}

func (s *AvatarStore) Save(file io.Reader, ext string) (string, error) {
	// Generate a random filename with the safe extension
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	filename := hex.EncodeToString(randomBytes) + ext

	target := filepath.Join(s.Dir, filename)
	
	// Use O_CREATE|O_EXCL to fail if the file already exists
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

Add `import "io"` to avatar_handler.go.

## Explanation

The fix eliminates the weakness by replacing trust in the client-supplied `Content-Type` header with actual file content inspection. It reads the first 512 bytes of the uploaded file and passes them to `http.DetectContentType()`, which examines the file's magic bytes (file signature) to determine the real type. The detected type is then checked against an allowlist of allowed MIME types before proceeding. After validation, the file is rewound to the beginning so the full content can be saved. The handler now generates a cryptographically random filename with a safe extension derived from the detected content type (not from the client-supplied filename), breaking the attacker's ability to control the stored file's name or extension. The `Save` method is updated to accept the detected extension and generate the filename server-side, ensuring uploaded files cannot be named to exploit execution or traversal vulnerabilities.

## Behaviour changes

**Method signature change** - `store.Save()` now takes `(file io.Reader, ext string)` instead of `(filename string, file io.Reader)`. The stored filename is now generated server-side and returned to the caller, which must be updated to persist or return the new name if any route needs to serve the file back.

**Filename generation** - The original client-supplied filename is discarded entirely. The stored file receives a random hex-encoded name with a server-controlled extension based on detected content type. This breaks any existing code that expects to retrieve the file by its original name; callers must use the returned generated name instead.

**File permission mode** - Storage now uses `os.O_EXCL` to ensure unique file creation, failing if a collision occurs (probability negligible with 16 random bytes but gracefully handled). File permissions are set to `0o600` (read/write for owner only), narrower than `os.Create`'s default.

**Early size rejection** - While not in this fix, the guidance recommends adding `http.MaxBytesReader` before `ParseMultipartForm` to reject oversized uploads before memory/disk exhaustion.
