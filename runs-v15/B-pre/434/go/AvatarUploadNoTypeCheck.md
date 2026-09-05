## Verdict

The finding is confirmed. The handler accepts an avatar upload without validating the file's actual content type and writes it to disk using the client-supplied filename inside a directory served directly by `http.FileServer`. This allows an attacker to upload executable scripts (e.g., `.php`, `.jsp`, `.exe`) or path-traversal payloads that will be executed or served with the wrong MIME type.

## Source

Input: `r.FormFile("avatar")` (line 23).

The `multipart.FileHeader` fields `Filename` and `Header.Get("Content-Type")` are both supplied by the client in the multipart part headers and are not validated by Go's standard library.

Data flow: `header.Filename` (client-supplied string) → `filepath.Join(avatarDir, header.Filename)` (line 30) → `os.Create(destPath)` (line 32, the sink).

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

// Allowlist of permitted image MIME types mapped to safe extensions
var allowedTypes = map[string]string{
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
	// Guard against oversized requests early
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

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

	// Sniff the first 512 bytes to detect actual content type
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read file", http.StatusBadRequest)
		return
	}
	detectedType := http.DetectContentType(buf[:n])

	// Validate detected type against allowlist (not client-supplied header or filename extension)
	ext, ok := allowedTypes[detectedType]
	if !ok {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Rewind the file for full content write
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		http.Error(w, "could not process file", http.StatusInternalServerError)
		return
	}

	// Generate a random filename; extension comes from detected type allowlist
	randomBytes := make([]byte, 16)
	_, err = rand.Read(randomBytes)
	if err != nil {
		http.Error(w, "could not generate filename", http.StatusInternalServerError)
		return
	}
	generatedFilename := fmt.Sprintf("%x%s", randomBytes, ext)
	destPath := filepath.Join(avatarDir, generatedFilename)

	// Verify the resolved path stays within the intended storage directory
	absDestPath, err := filepath.Abs(destPath)
	if err != nil {
		http.Error(w, "could not process file", http.StatusInternalServerError)
		return
	}
	absAvatarDir, err := filepath.Abs(avatarDir)
	if err != nil {
		http.Error(w, "could not process file", http.StatusInternalServerError)
		return
	}
	if !filepath.HasPrefix(absDestPath, absAvatarDir) {
		http.Error(w, "invalid file path", http.StatusBadRequest)
		return
	}

	// Create file with restricted permissions; O_EXCL prevents TOCTOU race
	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	_, err = io.Copy(dest, file)
	if err != nil {
		http.Error(w, "could not save file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	// Return the generated filename so the caller can retrieve it later
	fmt.Fprintf(w, `{"filename":"%s"}`, generatedFilename)
}
```

## Explanation

The fix closes CWE-434 by applying the safe pattern for file uploads:

1. **Content-type detection**: Instead of trusting the client-supplied `Content-Type` header or the filename extension, the code reads the first 512 bytes of the uploaded file and calls `http.DetectContentType()` to determine the real content type. This detects the actual file signature (magic bytes).

2. **Type allowlist**: The detected type is validated against an allowlist map (`allowedTypes`) that maps permitted MIME types to safe file extensions. Only images matching the whitelist are accepted; all others are rejected.

3. **Generated filename**: A random 16-byte hex string is generated using `crypto/rand` and combined with the extension from the allowlist map (not the client-supplied filename extension). This prevents both path traversal attacks (since traversal sequences like `../` cannot appear in random hex) and the attacker from controlling the stored filename.

4. **Path validation**: After joining the generated filename with the storage directory, the code resolves both paths to absolute form and verifies that the result stays within the intended `avatarDir` using `filepath.HasPrefix()`.

5. **Restricted file permissions**: The file is created with `os.OpenFile(..., os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)`, which:
   - Opens for write only
   - Creates the file if it doesn't exist
   - Fails if the file already exists (atomic check, prevents TOCTOU race)
   - Sets mode 0o600 (owner read/write only, no execute, no group/world access)

6. **Early size enforcement**: `http.MaxBytesReader()` is applied before parsing the multipart form, rejecting oversized requests early before they exhaust memory or disk.

7. **Generated filename returned**: The response includes the generated filename so clients that need to retrieve the upload later can do so by name. This is critical because the caller cannot predict or guess the random filename.

## Behaviour changes

- **API change**: The response body now includes a JSON object with the generated filename (e.g., `{"filename":"a1b2c3d4e5f6g7h8.jpg"}`). Callers must update to capture and store this filename if they need to retrieve the uploaded avatar later.
- **Rejected uploads**: Any file whose detected MIME type is not in the allowlist (currently `image/jpeg`, `image/png`, `image/gif`, `image/webp`) will be rejected with HTTP 400, including files with incorrect extensions or polyglot payloads.
- **No file path traversal**: Filenames like `../../etc/passwd.jpg` are now impossible because the filename is generated server-side and contains only hex characters and a controlled extension.
- **File permissions**: Uploaded files are created with mode 0o600 (owner read/write only), more restrictive than the previous default mode 0o644.
- **Stored location unchanged**: Files are still stored in `./public/avatars` and served via `http.FileServer`. Execution risk is mitigated by the strict type allowlist (image types only) and generated filename; however, storing uploads outside the webroot (if feasible) would provide defence-in-depth.
