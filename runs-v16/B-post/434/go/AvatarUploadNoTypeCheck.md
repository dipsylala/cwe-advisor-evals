## Verdict

Exploitable. The upload handler accepts any file type using the client-supplied filename without validation of content, file type, or path integrity. Combined with serving uploads via `http.FileServer` from the webroot, this allows arbitrary file upload including scripts and malicious content.

## Source

`r.FormFile("avatar")` at line 23, specifically the untrusted `FileHeader.Filename` value.

## Sink

`os.Create(destPath)` at line 32, which writes the file to a path constructed directly from the client-supplied filename with no validation.

## Fix

**Vulnerable code (lines 23-32):**

```go
file, header, err := r.FormFile("avatar")
if err != nil {
	http.Error(w, "missing file", http.StatusBadRequest)
	return
}
defer file.Close()

destPath := filepath.Join(avatarDir, header.Filename)
// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
dest, err := os.Create(destPath)
```

**Fixed code:**

```go
// Enforce size limit early
r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB
if err := r.ParseMultipartForm(10 << 20); err != nil {
	http.Error(w, "bad request", http.StatusBadRequest)
	return
}

file, _, err := r.FormFile("avatar")
if err != nil {
	http.Error(w, "missing file", http.StatusBadRequest)
	return
}
defer file.Close()

// Detect real content type by reading file content
buf := make([]byte, 512)
n, err := file.Read(buf)
if err != nil {
	http.Error(w, "could not read file", http.StatusBadRequest)
	return
}

detectedType := http.DetectContentType(buf[:n])

// Allowlist of permitted content types
allowedTypes := map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

ext, ok := allowedTypes[detectedType]
if !ok {
	http.Error(w, "unsupported file type", http.StatusBadRequest)
	return
}

// Generate random filename using detected type's extension
randBytes := make([]byte, 16)
if _, err := rand.Read(randBytes); err != nil {
	http.Error(w, "could not generate filename", http.StatusInternalServerError)
	return
}
filename := hex.EncodeToString(randBytes) + ext

// Rewind file to beginning after content detection
if _, err := file.Seek(0, io.SeekStart); err != nil {
	http.Error(w, "could not process file", http.StatusInternalServerError)
	return
}

destPath := filepath.Join(avatarDir, filename)
// Use O_EXCL to fail if file already exists, and restrictive 0o600 permissions
dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
if err != nil {
	http.Error(w, "could not save file", http.StatusInternalServerError)
	return
}
defer dest.Close()

if _, err := io.Copy(dest, file); err != nil {
	http.Error(w, "could not save file", http.StatusInternalServerError)
	return
}

// Return generated filename to caller
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(http.StatusCreated)
json.NewEncoder(w).Encode(map[string]string{"filename": filename})
```

**Required imports added:**

```go
"crypto/rand"
"encoding/hex"
"encoding/json"
```

## Explanation

The fix implements the three-layer defence from CWE-434 guidance:

1. **Content Validation**: `http.DetectContentType()` reads the actual file signature (magic bytes) from the file's leading 512 bytes, not the client-supplied filename extension or Content-Type header. This prevents spoofed file types.

2. **Allowlist Enforcement**: Only image MIME types (JPEG, PNG, GIF, WebP) are permitted. The detected type is validated against the allowlist before proceeding; any other type is rejected immediately. The stored extension comes from the allowlist map, not from `FileHeader.Filename`, so the attacker cannot choose the extension that determines how the file is served.

3. **Generated Storage Filename**: `crypto/rand.Read()` with `hex.EncodeToString()` creates a server-controlled, collision-resistant filename. The original filename is discarded; the generated name is returned to the caller so retrieval still works.

4. **Size Limits**: `http.MaxBytesReader()` enforces an early, strict byte limit before `ParseMultipartForm()`, preventing memory exhaustion or disk DoS.

5. **Safe File Creation**: `os.OpenFile()` with `os.O_EXCL` flag fails if the file already exists (preventing collision races), and `0o600` permissions restrict access to the owning process alone.

The file is rewound to the beginning after content detection (`file.Seek(0, io.SeekStart)`) so the full content is written, not truncated to the detection buffer.

## Behaviour changes

- **Return value changed**: The handler now returns JSON with the generated filename instead of no body. Reason: The caller needs the generated filename to retrieve the file later; without this, the read path breaks silently.

- **Size enforcement added**: `http.MaxBytesReader()` rejects requests larger than 10MB before parsing. Reason: Early rejection prevents memory and disk exhaustion.

- **File type rejected for non-images**: The handler now returns HTTP 400 for any content type outside the allowlist. Reason: This is the primary defence; rejecting dangerous types is the fix.

- **Response header added**: `Content-Type: application/json` is set. Reason: The response now contains structured data (filename); the header reflects this.

- **File permissions set to 0o600**: Previous `os.Create()` used the process umask default. Reason: Explicit restrictive permissions prevent other users on the system from reading uploaded avatars.

- **Error handling expanded**: New error cases for `Seek()`, `rand.Read()`, `http.DetectContentType()` validation. Reason: These operations can fail independently and must not silently degrade; each failure is surfaced to the caller.
