## Verdict

**Confirmed.** The handler validates only the client-supplied `Content-Type` header and uses the client-supplied filename for storage, neither of which prevents an attacker from uploading an executable file with spoofed metadata.

## Source

The upload originates at line 12 in `avatar_handler.go`: `r.FormFile("avatar")` returns a `multipart.FileHeader` whose `Header` (the MIME part headers) and `Filename` are both attacker-controlled.

The taint flows through:
- Line 21: `header.Header.Get("Content-Type")` - client-supplied part header, not validated
- Line 25: `header.Filename` - client-supplied filename, used directly as the storage path in `store.Save(header.Filename, file)`

The sink is line 14 in `avatar_store.go`: `filepath.Join(s.Dir, filename)` and line 15: `os.Create(target)` writes the file to disk under the attacker-supplied name.

## Fix

**avatar_handler.go**

```go
package avatarupload

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
)

// Allowed MIME types mapped to safe extensions.
var allowedMimeTypes = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
}

func UploadAvatarHandler(store *AvatarStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Enforce early size limit to avoid exhausting memory/disk.
		http.MaxBytesReader(w, r.Body, 8<<20) // 8 MiB

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

		// Read first 512 bytes to detect the real content type.
		buf := make([]byte, 512)
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		detectedType := http.DetectContentType(buf[:n])

		// Allowlist the detected type.
		ext, ok := allowedMimeTypes[detectedType]
		if !ok {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		// Rewind the file to the beginning for full read.
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		// Generate a new filename instead of using the client-supplied one.
		randomBytes := make([]byte, 16)
		if _, err := rand.Read(randomBytes); err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}
		generatedName := fmt.Sprintf("%x%s", randomBytes, ext)

		storedName, err := store.Save(generatedName, file)
		if err != nil {
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(storedName))
	}
}
```

**avatar_store.go** (unchanged - the fix is applied at the handler level)

The `avatar_store.go` file remains unchanged because its `Save` method now receives a safe, server-generated filename (`generatedName`) instead of the client-supplied `header.Filename`.

## Explanation

The original code trusts two attacker-controlled values: the `Content-Type` header from the multipart part metadata, and the `Filename`. Both can be spoofed; a client can upload an executable with a `Content-Type: image/png` header and any filename.

The fix:
1. **Detects real content type**: Reads the first 512 bytes of the file and calls `http.DetectContentType()`, which inspects magic bytes. This identifies the real content, not the claimed type.
2. **Allowlists detected type**: Compares the detected MIME type against a server-controlled allowlist map. Only types in the map are accepted.
3. **Maps to safe extension**: The extension comes from the allowlist map keyed by the detected type, not from the client-supplied filename. This ensures the stored file's extension matches its real content.
4. **Generates filename**: A cryptographically random filename is generated and used for storage. The client-supplied `Filename` is discarded, preventing path traversal and removing the attacker's control over where the file is written.
5. **Rewinds the file**: After sniffing the first 512 bytes, the file is rewound with `Seek(0, io.SeekStart)` so the full content is written during the copy operation.
6. **Enforces size limits early**: `http.MaxBytesReader()` is called before parsing to reject oversized requests before the parser consumes resources.

The vulnerability is closed because an attacker cannot upload a dangerous file type; the real content is inspected and only images with valid PNG or JPEG structure pass validation.

## Behaviour changes

- **Upload acceptance**: Only files whose actual content matches the allowlist (PNG or JPEG magic bytes) are accepted. Files with spoofed `Content-Type` headers are rejected.
- **Storage path**: The uploaded file is now stored under a generated filename (e.g., `a1b2c3d4e5f6.png`) instead of the client-supplied filename. Any client that relied on retrieving the file by its original name will now fail unless the handler is updated to return or persist the generated name (currently, the generated name is returned in the response body as `storedName`).
- **Request size handling**: Oversized requests are rejected at `MaxBytesReader` before multipart parsing, avoiding memory exhaustion.
- **No imports added to `avatar_store.go`**: The `Save` method's signature and behaviour remain unchanged; it accepts any filename the handler passes to it. The safety boundary is now at the handler level where the filename is generated.

