## Verdict

Confirmed CWE-434 vulnerability. The upload handler trusts the client-supplied filename and writes files directly to a webroot directory served by `http.FileServer` without validating file type or content.

## Source

`multipart.FileHeader` from `r.FormFile("avatar")` on line 23. The `header.Filename` field is attacker-controlled and comes from the multipart part headers sent by the client.

## Fix

```go
package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const avatarDir = "./public/avatars"

// Allowlist of permitted MIME types for avatar uploads
var allowedMimeTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func init() {
	// Uploaded avatars are served back directly from this directory.
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir(avatarDir))))
}

func avatarUploadHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read the first 512 bytes to detect the real content type
	sniffBuf := make([]byte, 512)
	n, err := file.Read(sniffBuf)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}

	// Detect the actual content type from the file content
	detectedType := http.DetectContentType(sniffBuf[:n])

	// Validate against allowlist of permitted types
	ext, ok := allowedMimeTypes[detectedType]
	if !ok {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Rewind the file for copying
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not process file", http.StatusInternalServerError)
		return
	}

	// Generate a random filename instead of using the client-supplied one
	randomName := make([]byte, 16)
	if _, err := rand.Read(randomName); err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	filename := fmt.Sprintf("%x%s", randomName, ext)

	destPath := filepath.Join(avatarDir, filename)
	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	io.Copy(dest, file)
	w.WriteHeader(http.StatusCreated)
}
```

## Explanation

The fix closes CWE-434 by implementing three core controls:

1. **Content validation**: Read the first 512 bytes and call `http.DetectContentType()` to determine the real file type based on magic bytes, not the client-supplied Content-Type header or filename extension.

2. **Allowlist validation**: Check the detected type against `allowedMimeTypes` map containing only permitted image types. Reject any file that does not match, preventing upload of scripts, executables, or other dangerous content.

3. **Filename generation**: Replace `header.Filename` with a server-generated random hexadecimal name (`rand.Read` from `crypto/rand`). Derive the extension from the detected type in the allowlist map, not from the client filename. This prevents both path traversal attacks and extension-based exploitation.

The file is rewind after content sniffing (`file.Seek(0, io.SeekStart)`) so the full content is copied to disk. The generated filename breaks the taint chain: the stored filename is now attacker-independent and cannot be exploited to inject script execution or traversal paths.

## Behaviour changes

- Uploaded files are now stored with generated names (e.g., `a1b2c3d4e5f6g7h8.jpg`) instead of original filenames. Any code that retrieves files by the original filename will need to update to either: (a) use the generated name returned in the upload response, or (b) maintain a mapping of original name to stored name in a database.
- Only image types (JPEG, PNG, GIF, WebP) are accepted; other file types are rejected with HTTP 400.
- Files with mismatched extension and content (e.g., an executable with `.jpg` extension) are rejected during content detection.
- File retrieval via the `/avatars/` endpoint now serves only the files that passed the allowlist check and were assigned generated names.
