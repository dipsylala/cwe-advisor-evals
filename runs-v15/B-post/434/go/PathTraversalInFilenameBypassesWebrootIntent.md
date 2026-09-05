## Verdict

**CONFIRMED**: CWE-434 (Unrestricted Upload of File with Dangerous Type)

The code trusts the client-supplied `Content-Type` header and the `Filename` from the multipart request without verifying the actual file content or generating a safe storage name. This allows an attacker to upload arbitrary files (scripts, executables, or web shells) that will be stored in the application's attachment directory with their original filenames, potentially with dangerous extensions.

## Source

The multipart file upload is received at line 36:
```go
file, fileHeader, err := r.FormFile("attachment")
```

The client-supplied metadata enters the handler through:
- `fileHeader.Header.Get("Content-Type")` (line 45) — attacker-controlled multipart part header
- `fileHeader.Filename` (line 51) — attacker-controlled filename from the multipart part

## Fix

Replace lines 43–53 with the following code that detects the actual file content, generates a safe filename, and stores it securely:

```go
	// Detect the actual file content type by reading the first 512 bytes
	sniffBuf := make([]byte, 512)
	n, err := file.Read(sniffBuf)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read attachment", http.StatusInternalServerError)
		return
	}
	detectedType := http.DetectContentType(sniffBuf[:n])

	// Check the detected type against the allowlist
	if !allowedContentTypes[detectedType] {
		http.Error(w, "unsupported attachment type", http.StatusUnsupportedMediaType)
		return
	}

	// Rewind the file to the beginning after sniffing
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		http.Error(w, "could not process attachment", http.StatusInternalServerError)
		return
	}

	// Map detected content type to safe file extension
	typeToExt := map[string]string{
		"application/pdf": ".pdf",
		"image/png":       ".png",
		"image/jpeg":      ".jpg",
	}
	ext := typeToExt[detectedType]

	// Generate a random filename
	randomName, err := generateRandomFilename(ext)
	if err != nil {
		http.Error(w, "could not generate filename", http.StatusInternalServerError)
		return
	}

	destPath := filepath.Join(uploadDir, randomName)
	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "could not save attachment", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "attachment saved as %s", filepath.Base(destPath))
```

Add this helper function to the package (can be placed after the handler function):

```go
import (
	"crypto/rand"
	"fmt"
)

// generateRandomFilename creates a secure random filename with the given extension.
func generateRandomFilename(ext string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x%s", b, ext), nil
}
```

Also add `http.MaxBytesReader` before calling `ParseMultipartForm` (line 31) to guard against oversized uploads:

```go
	maxUploadSize := int64(20 << 20) // 20 MB
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
```

## Explanation

The fix closes the CWE-434 vulnerability by addressing three unsafe patterns:

1. **Verify actual content, not client-supplied headers**: Instead of trusting `fileHeader.Header.Get("Content-Type")`, the fixed code reads the first 512 bytes of the uploaded file and calls `http.DetectContentType()` to detect the real MIME type. This prevents an attacker from uploading a PHP script while claiming it is a PDF.

2. **Generate a safe storage filename**: The original code used `fileHeader.Filename` directly, which can contain path traversal sequences (`../../../etc/passwd`) or dangerous extensions. The fixed code generates a cryptographically random filename using `crypto/rand` and derives the extension from a fixed map keyed only by the detected content type—not the client-supplied extension.

3. **Use atomic creation with exclusivity**: The fixed code uses `os.OpenFile` with the `os.O_EXCL` flag instead of `os.Create`. This ensures the file is created atomically and fails if it already exists, preventing race conditions.

4. **Enforce file size limits upfront**: The `http.MaxBytesReader` wrapper limits the request body size before parsing, preventing memory exhaustion or disk-filling attacks during multipart parsing.

The fix preserves the handler's contract: it still returns an HTTP 201 status and the saved filename to the caller, allowing the application to retrieve the file in subsequent requests.

## Behaviour changes

- Rejected uploads now use the detected file content type instead of the client-supplied `Content-Type` header. This will reject files with mismatched extensions (e.g., a `.exe` file renamed to `.pdf`).
- Uploaded files are now stored with cryptographically random names instead of their original names. Any code or UI that displays or retrieves files by name must use the new generated filename returned in the response, not the original upload name.
- The request body is now limited to 20 MB before parsing begins, rather than during parsing. Requests exceeding this limit are rejected immediately with a 400 error.
- File creation now uses `os.O_EXCL`, which will fail if a file with the random name already exists (highly unlikely with 128-bit random names, but the handler will return a 500 error if this occurs rather than overwriting).
