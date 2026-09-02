## Verdict

CWE-434 confirmed. The code relies on the client-supplied `Content-Type` header to validate file type. An attacker can upload arbitrary file types by setting a benign `Content-Type` header while sending malicious content.

## Source

**avatar_handler.go, line 21-25:**

```go
contentType := header.Header.Get("Content-Type")
if contentType != "image/png" && contentType != "image/jpeg" {
    http.Error(w, "unsupported avatar", http.StatusBadRequest)
    return
}
```

The `Content-Type` header is entirely controlled by the client. An attacker can send `Content-Type: image/png` with a PHP shell, executable, or other dangerous file type.

**avatar_handler.go, line 27:**

```go
storedName, err := store.Save(header.Filename, file)
```

The filename from the request is used directly without sanitization, enabling arbitrary extensions and potential directory traversal.

## Fix

```go
package avatarupload

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
)

// Magic bytes for PNG and JPEG
var (
	pngMagic  = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	jpegMagic = []byte{0xFF, 0xD8, 0xFF}
)

func UploadAvatarHandler(store *AvatarStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("avatar")
		if err != nil {
			http.Error(w, "missing avatar", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Read file header to validate actual content
		buf := make([]byte, 8)
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		// Validate file signature (magic bytes)
		isPNG := bytes.HasPrefix(buf[:n], pngMagic)
		isJPEG := bytes.HasPrefix(buf[:n], jpegMagic)

		if !isPNG && !isJPEG {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		// Determine extension from actual content
		var ext string
		if isPNG {
			ext = ".png"
		} else {
			ext = ".jpg"
		}

		// Generate random filename to prevent path traversal and extension attacks
		randomBytes := make([]byte, 16)
		if _, err := rand.Read(randomBytes); err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}
		safeName := hex.EncodeToString(randomBytes) + ext

		// Create a reader that includes the bytes we already read
		multiReader := io.MultiReader(bytes.NewReader(buf[:n]), file)

		storedName, err := store.Save(safeName, multiReader)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}
```

## Explanation

The fix addresses CWE-434 through three mechanisms:

1. **Magic byte validation**: Instead of trusting the `Content-Type` header, read the first 8 bytes of the file and check for PNG (0x89504E47...) or JPEG (0xFFD8FF...) signatures. This validates actual file content, not client-supplied metadata.

2. **Safe filename generation**: Replace the user-supplied filename with a cryptographically random hex string plus a validated extension. This prevents directory traversal attacks (e.g., `../../../etc/passwd`) and blocks dangerous extensions (e.g., `.php`, `.exe`).

3. **Preserved file content**: After reading the magic bytes for validation, combine them with the remaining file data using `io.MultiReader` before passing to storage, so no content is lost.

The client cannot bypass this validation because magic bytes must match the actual file structure—binary headers cannot be spoofed in a valid image file. Even if an attacker uploads a PHP shell, it either fails magic byte validation or, if the shell is embedded in a valid image, it will not execute because the file extension is now `.jpg` or `.png`, not `.php`.

