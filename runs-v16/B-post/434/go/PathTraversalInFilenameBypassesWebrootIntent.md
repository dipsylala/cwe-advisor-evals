## Verdict

The vulnerability is confirmed. The handler validates only the client-supplied `Content-Type` header and uses the untrusted `FileHeader.Filename` directly in the storage path. This permits two attack vectors: (1) a script file can be uploaded by spoofing a safe Content-Type header, and (2) the filename can contain path traversal sequences (`../`) to escape the intended upload directory.

## Source

`multipart.FileHeader.Header.Get("Content-Type")` (line 45) - client-supplied multipart part header, untrusted.
`multipart.FileHeader.Filename` (line 51) - client-supplied filename, untrusted and may contain path separators or traversal sequences.

## Fix

Replace lines 43–66 with the following:

```go
	// Detect real content type from file bytes, not client-supplied header.
	sniffBuf := make([]byte, 512)
	n, err := file.Read(sniffBuf)
	if err != nil && err != io.EOF {
		http.Error(w, "could not read attachment", http.StatusInternalServerError)
		return
	}
	
	detectedType := http.DetectContentType(sniffBuf[:n])
	if !allowedContentTypes[detectedType] {
		http.Error(w, "unsupported attachment type", http.StatusUnsupportedMediaType)
		return
	}
	
	// Rewind the file after content detection.
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "could not read attachment", http.StatusInternalServerError)
		return
	}
	
	// Map detected type to a safe extension from an allowlist.
	typeToExt := map[string]string{
		"application/pdf": ".pdf",
		"image/png":       ".png",
		"image/jpeg":      ".jpg",
	}
	
	ext := typeToExt[detectedType]
	if ext == "" {
		http.Error(w, "unsupported attachment type", http.StatusUnsupportedMediaType)
		return
	}
	
	// Generate a random filename; do not use the client-supplied one.
	randomName := fmt.Sprintf("%d%s", rand.Int63(), ext)
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
	fmt.Fprintf(w, "attachment saved as %s", randomName)
```

Add the import `"math/rand"` at the top of the file.

Also add the following at the beginning of the handler to enforce file size limits:

```go
	// Guard multipart parsing with explicit size limit.
	http.MaxBytesReader(w, r.Body, 50<<20) // 50 MiB
	if err := r.ParseMultipartForm(20 << 20); err != nil {
```

(This replaces the current `r.ParseMultipartForm(20 << 20)` call on line 31.)

## Explanation

The fix closes the weakness by moving from client-supplied validation to server-side content detection. `http.DetectContentType()` reads the file's leading bytes (magic bytes) to determine the true content type, eliminating spoofing. A randomly generated filename replaces the client-supplied one, preventing path traversal (`../`) and ensuring the attacker cannot choose the stored name or extension. The extension itself is drawn from a fixed allowlist map keyed by detected type, not from the original filename, so the stored file's handling is entirely controlled by the server.

`http.MaxBytesReader()` wraps the request body to reject uploads exceeding 50 MiB before parsing, preventing resource exhaustion. `file.Seek(0, io.SeekStart)` rewinds the file after sniffing so the entire content is copied to storage. `os.OpenFile()` with `os.O_EXCL` atomically creates the file and fails if it already exists, preventing accidental overwrites.

## Behaviour changes

- The endpoint now rejects files whose actual content does not match the allowlisted MIME types, regardless of the `Content-Type` header or extension.
- Uploaded files are stored with server-generated names (e.g., `1234567890.jpg`) instead of the original filenames.
- The handler returns the generated filename to the client so they can retrieve the file later via a retrieval handler that accepts the generated name.
- File size limit is enforced: uploads exceeding 50 MiB are rejected during multipart parsing.
- Stored files are created with restricted permissions (`0o600` / read-write for owner only).
