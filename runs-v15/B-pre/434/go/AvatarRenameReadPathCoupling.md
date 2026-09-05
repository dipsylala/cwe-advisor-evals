# CWE-434 Remediation: AvatarRenameReadPathCoupling

## Verdict

Exploitable. The upload handler accepts a client-supplied filename directly without validating the file's actual content type or generating a storage name, permitting an attacker to upload an executable file or web shell under an arbitrary filename. The stored file can be served back through `ReadAvatarBytes()`, which retrieves files by the client-supplied name.

## Source

`header.Filename` from the client's multipart form data, received by `r.FormFile("avatar")` on line 13.

## Fix

**Vulnerable code:**
```go
func UploadAvatar(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}

	// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
	os.WriteFile(filepath.Join(storageDir, header.Filename), bytes, 0o600)
	w.WriteHeader(http.StatusCreated)
}
```

**Fixed code:**
```go
import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Allowlist of permitted content types and their storage extensions
var allowedTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/webp": ".webp",
	"image/gif":  ".gif",
}

func UploadAvatar(w http.ResponseWriter, r *http.Request) {
	// Enforce a maximum upload size: 5 MB
	r.Body = http.MaxBytesReader(w, r.Body, 5*1024*1024)
	
	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "upload too large or malformed", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Sniff the actual content type from file leading bytes
	sniffBuf := make([]byte, 512)
	n, err := file.Read(sniffBuf)
	if err != nil && err != io.EOF {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	detectedType := http.DetectContentType(sniffBuf[:n])

	// Validate against allowlist
	ext, ok := allowedTypes[detectedType]
	if !ok {
		http.Error(w, "file type not allowed", http.StatusBadRequest)
		return
	}

	// Rewind to beginning for full read
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Read full file content
	bytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}

	// Generate a random storage filename
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	generatedFilename := hex.EncodeToString(randomBytes) + ext
	storagePath := filepath.Join(storageDir, generatedFilename)

	// Use O_EXCL to fail if file already exists (protect against race conditions)
	f, err := os.OpenFile(storagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if _, err := f.Write(bytes); err != nil {
		f.Close()
		os.Remove(storagePath)
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}

	// Return the generated filename to the caller so they can retrieve it later
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"filename":"` + generatedFilename + `"}`))
}
```

## Explanation

The fix closes CWE-434 by implementing three key controls: (1) the handler now sniffs the actual file content using `http.DetectContentType()` on the file's leading bytes, rejecting any content type not in the hardcoded allowlist, rather than trusting the client-supplied `Content-Type` header; (2) the handler generates a random storage filename (using 16 bytes of cryptographic randomness) instead of using `header.Filename`, preventing an attacker from choosing the stored name or injecting path traversal sequences; (3) the extension is derived from the allowlist map keyed by detected type, not from `header.Filename`, so the file's eventual serving behavior is controlled server-side. The fix also adds `http.MaxBytesReader()` to enforce a size limit early (preventing memory exhaustion), uses `os.O_EXCL` to atomically reject collisions, and cleans up partial writes on error. Critically, the response now returns the generated filename to the caller in JSON format, so downstream code can retrieve the file using the server-controlled name rather than the original client-supplied one; this breaks the coupling between the write and read paths that exists in the current code.

## Behaviour changes

- **Added `http.MaxBytesReader()` before `r.FormFile()`**: Enforces a 5 MB upload limit and rejects oversized requests with HTTP 400 before parsing. Original code had no size limit. Justification: defence-in-depth hardening per Go guidance.
- **Added content-type sniffing and allowlist validation**: Reads the first 512 bytes with `http.DetectContentType()` and checks against a hardcoded `allowedTypes` map. Original code did not validate content at all. Justification: closes CWE-434 by rejecting disallowed content types.
- **Added file seek-to-start after sniffing**: Rewinds the file to position 0 after reading the sniff buffer. Original code's `io.ReadAll()` would read the full file without rewinding. Justification: ensures the full file is written, including the leading bytes already sniffed.
- **Changed from `os.WriteFile()` to `os.OpenFile()` with `O_EXCL`**: Replaces the direct write call with an atomic create-only open. Justification: prevents race-condition collisions if the generated filename already exists, and gives better error handling.
- **Changed filename from `header.Filename` to a generated random name**: Stores the file under a server-controlled name derived from cryptographic randomness, not client-supplied input. Justification: closes CWE-434 by removing attacker control over the storage name and preventing path traversal.
- **Changed response format from HTTP 201 with no body to HTTP 201 with JSON body**: Response now includes the generated filename in JSON, e.g., `{"filename":"a1b2c3d4...jpg"}`. Original code sent an empty HTTP 201. Justification: allows the caller to retrieve the file by its generated name, breaking the coupling to the original filename and ensuring the read path can work without the original `header.Filename`.
- **Added error cleanup**: If the write fails, the file is explicitly removed with `os.Remove()`. Original code would leave a partial file on error. Justification: prevents accumulated partial/failed uploads from consuming storage.
