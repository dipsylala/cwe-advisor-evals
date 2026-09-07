## Verdict

Exploitable. The extension appended to the stored filename is derived from the client-supplied `FileHeader.Filename` rather than from the detected content type. Even though the file content is properly validated using `http.DetectContentType()`, an attacker can upload a file with a dangerous extension (e.g., `.phtml`, `.jsp`, `.exe`) containing valid magic bytes of an allowed type (e.g., PNG). The validation passes the content check, but the file is stored with the attacker-controlled extension. If the file is later served or executed based on its extension, the attacker can achieve code execution or content injection.

## Source

Line 66 in `document_upload.go`:

```go
storedName += filepath.Ext(fileHeader.Filename)
```

`fileHeader.Filename` is client-supplied multipart part metadata and cannot be trusted. The extension determines how the file is treated downstream (served MIME type, execution context), so it must come from the detected content type, not the client.

## Fix

Replace line 66 with a map-based lookup that derives the extension from the validated content type:

```go
	// Map detected content types to safe file extensions.
	extByType := map[string]string{
		"image/png":       ".png",
		"image/jpeg":      ".jpg",
		"application/pdf": ".pdf",
	}
	storedName += extByType[detectedType]
```

This ensures the stored filename's extension always matches the file's actual content, as determined by the server-side validation. An attacker cannot inject a dangerous extension, because the extension comes from the allowlist of detected types, not from the client.

## Explanation

The original code validated the file's actual content correctly using `http.DetectContentType()` and checked it against an allowlist. However, the validation result (`detectedType`) was discarded for the purpose of determining the file extension. Instead, the code used `filepath.Ext(fileHeader.Filename)`, which extracts the extension from the attacker-controlled filename.

This creates a polyglot attack: an attacker uploads a file with a dangerous extension (`.phtml`, `.jsp`, `.exe`, etc.) but crafts its initial bytes to match the magic signature of an allowed type (e.g., PNG). The content validation passes because the file *is* a valid PNG at the byte level, but the stored filename carries the attacker's chosen extension. When the file is later served or executed by another process, the extension determines how it is treated, not the validated content—enabling the attacker to achieve code execution or content injection.

The fix establishes a fixed map from allowed content types to their corresponding safe extensions, then uses that map to determine the extension. This ensures the stored filename's extension always reflects the validated content type, not the client-supplied value, closing the injection path.

## Behaviour changes

- **Pre-fix**: A file uploaded as `shell.phtml` with PNG magic bytes is stored as `<random>.phtml` even though the content is a valid PNG.
- **Post-fix**: The same upload is stored as `<random>.png` because the detected content type is `image/png`, and the map assigns it the extension `.png`.

Downstream code that serves files based on extension (e.g., a handler that sets `Content-Type: application/x-httpd-php` for `.phtml` files) now receives files whose extension matches their actual, validated content type. This prevents the attacker from controlling how the file is interpreted.
