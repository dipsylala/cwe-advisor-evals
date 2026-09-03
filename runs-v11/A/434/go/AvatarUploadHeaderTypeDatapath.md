## Verdict

**VULNERABLE** — The code validates uploaded file types using only the client-supplied `Content-Type` header, which is trivially spoofed. An attacker can upload executable files or other dangerous content by providing a fake image MIME type.

## Source

Line 21 in `avatar_handler.go`:
```go
contentType := header.Header.Get("Content-Type")
if contentType != "image/png" && contentType != "image/jpeg" {
    http.Error(w, "unsupported avatar", http.StatusBadRequest)
    return
}
```

The vulnerable pattern: trusting the `Content-Type` header from the multipart form file. This header originates entirely from the client request and can be set to any value an attacker chooses, independent of the file's actual content.

## Fix

Replace header-based validation with magic byte verification:

```go
package avatarupload

import (
	"bytes"
	"io"
	"net/http"
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

		// Read first 8 bytes to check magic signatures
		magicBytes := make([]byte, 8)
		n, err := file.Read(magicBytes)
		if err != nil && err != io.EOF {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		magicBytes = magicBytes[:n]

		// Verify file signature: PNG (89 50 4E 47) or JPEG (FF D8 FF)
		isPNG := bytes.HasPrefix(magicBytes, []byte{0x89, 0x50, 0x4E, 0x47})
		isJPEG := bytes.HasPrefix(magicBytes, []byte{0xFF, 0xD8, 0xFF})

		if !isPNG && !isJPEG {
			http.Error(w, "unsupported avatar", http.StatusBadRequest)
			return
		}

		// Reset file position and save
		file.Seek(0, io.SeekStart)
		storedName, err := store.Save(header.Filename, file)
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

The fix validates file content rather than headers by checking file magic bytes (file signatures). This approach:

1. **Magic byte verification**: Reads the file's leading bytes and compares them against known signatures for valid image formats (PNG starts with `89 50 4N 47` hex, JPEG starts with `FF D8 FF` hex).

2. **Header independence**: Does not rely on the client-supplied `Content-Type` header at all, making spoofing ineffective.

3. **Type confusion prevention**: Rejects executable files, scripts, and other dangerous formats even if an attacker claims they are images.

4. **File position reset**: After reading magic bytes for validation, the file position is reset before saving, ensuring the complete file is stored.

This prevents CWE-434 by enforcing that uploaded files are actually image types, not executable code disguised with fake headers. An attacker cannot bypass this by uploading a `.exe` file with a `Content-Type: image/png` header—the magic byte check will reject it.
