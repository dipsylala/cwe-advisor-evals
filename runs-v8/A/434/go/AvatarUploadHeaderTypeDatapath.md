## Verdict

Confirmed. The code validates the Content-Type header from the HTTP request, which is client-controlled and can be spoofed. An attacker can upload any file type (executable, script, etc.) by simply setting the Content-Type to "image/png" or "image/jpeg". The actual file contents are never validated.

## Source

Line 21 in `avatar_handler.go`:

```go
contentType := header.Header.Get("Content-Type")
if contentType != "image/png" && contentType != "image/jpeg" {
```

This relies entirely on the client-supplied Content-Type header. The code then passes `header.Filename` directly to `store.Save()`, which uses it in `filepath.Join()` without sanitization, creating both a file-type validation bypass and a potential path traversal vulnerability.

## Fix

Replace the Content-Type header validation with actual file-content validation using magic bytes. Additionally, sanitize the filename to prevent directory traversal:

```go
import (
	"bytes"
	"fmt"
	"net/http"
	"path/filepath"
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

		// Read file header to validate actual content type
		buf := make([]byte, 512)
		n, err := file.Read(buf)
		if err != nil && err.Error() != "EOF" {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}

		// Validate against magic bytes
		isValidType := false
		if n >= 8 {
			// PNG: 89 50 4E 47
			if bytes.HasPrefix(buf[:n], []byte{0x89, 0x50, 0x4E, 0x47}) {
				isValidType = true
			}
			// JPEG: FF D8 FF
			if bytes.HasPrefix(buf[:n], []byte{0xFF, 0xD8, 0xFF}) {
				isValidType = true
			}
		}

		if !isValidType {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		// Sanitize filename: reject if it contains directory traversal
		cleanName := filepath.Base(header.Filename)
		if cleanName == "." || cleanName == ".." || cleanName != header.Filename {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}

		// Seek back to beginning and save
		file.Seek(0, 0)
		storedName, err := store.Save(cleanName, file)
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

The original code fails to validate file type because it trusts the Content-Type header sent by the client. HTTP headers are metadata that the client controls; they do not represent the actual file contents and can be freely modified.

The fix implements two defenses:

1. **Magic byte validation**: Read the first 512 bytes of the uploaded file and check for PNG (magic bytes `89 50 4E 47`) and JPEG (magic bytes `FF D8 FF`) signatures. These byte sequences are embedded in the actual file format and cannot be spoofed by changing headers. Only files with valid magic bytes are accepted.

2. **Filename sanitization**: Use `filepath.Base()` to extract only the filename component, rejecting any path containing directory traversal sequences (`.`, `..`, or path separators). This prevents an attacker from writing to arbitrary locations on the filesystem.

The file is re-read from the beginning after header validation before being passed to `store.Save()` to ensure the complete file is persisted.
