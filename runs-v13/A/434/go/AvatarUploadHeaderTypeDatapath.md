## Verdict

CWE-434 confirmed. The code validates file type by checking the client-controlled `Content-Type` header, which can be spoofed. An attacker can upload a malicious file (executable, script, etc.) while setting the Content-Type to "image/png" or "image/jpeg" to bypass validation.

## Source

Line 21: `contentType := header.Header.Get("Content-Type")`

The `Content-Type` header in a multipart form upload comes directly from the client and is not trustworthy. An attacker can set it to any value, regardless of the actual file content.

## Fix

Replace the Content-Type header check with magic-bytes validation. Read the first few bytes of the uploaded file and verify they match the expected file signatures for PNG and JPEG:

1. Read the file's first 12 bytes into a buffer.
2. Check for PNG signature: `89 50 4E 47 0D 0A 1A 0A` (hex).
3. Check for JPEG signature: `FF D8 FF` followed by a marker byte `E0-EF` (the first three bytes `FF D8 FF` are sufficient for a baseline check; `FF D8 FF E0` is the JFIF variant).
4. Reject the upload if neither signature is found.
5. Seek back to the start of the file before passing it to `store.Save()`.

Example approach:

```
Read the first 12 bytes of the file.
Check if they start with the PNG magic bytes (bytes 0-7).
Otherwise, check if they start with JPEG magic bytes (bytes 0-2 are 0xFF 0xD8 0xFF).
If neither, reject with StatusBadRequest.
Seek the file back to offset 0 before saving.
```

## Explanation

The `Content-Type` header is a MIME type hint provided by the client during the upload and has no integrity guarantee. Validating only this header trusts the attacker's classification of their own payload. File uploads require validation of actual file content—typically via magic bytes (file signatures) that identify the true format regardless of client-supplied metadata.

Magic bytes are the first few bytes of a file that identify its format. PNG files always begin with `89 50 4E 47 0D 0A 1A 0A`; JPEG files always begin with `FF D8 FF`. This validation cannot be spoofed because it checks the actual bytes in the file, not client-controlled headers. Combined with rejecting uploads based on the extension in `header.Filename` (a second layer) and storing files with a safe, generated name rather than the user-provided name (to prevent path traversal), magic-byte validation closes the attack surface for unrestricted file uploads.
