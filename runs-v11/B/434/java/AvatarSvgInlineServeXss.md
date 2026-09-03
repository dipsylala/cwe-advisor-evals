## Verdict
exploitable

## Source
The `storedName` parameter from `@PathVariable` at line 17 identifies a previously uploaded file stored with a validated type and UUID filename.

## Fix

**Vulnerable Code:**
```java
@GetMapping("/api/avatars/{storedName}")
public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
    byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
    String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(bytes);
}
```

**Fixed Code:**
```java
@GetMapping("/api/avatars/{storedName}")
public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
    byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
    String contentType = storedName.endsWith(".svg") ? "application/octet-stream" : "image/*";

    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_TYPE, contentType)
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + storedName + "\"")
        .header("X-Content-Type-Options", "nosniff")
        .body(bytes);
}
```

## Explanation
The vulnerability arises because SVG files can contain embedded JavaScript that executes when the browser parses them inline. Although the upload validation restricts file types, serving SVG with `Content-Type: image/svg+xml` allows the browser to execute any script inside the file. The fix applies secondary controls at the download point: serve SVG files as binary attachment to force download instead of inline viewing, use `Content-Disposition: attachment` to prevent the browser from interpreting the content, and add `X-Content-Type-Options: nosniff` to prevent MIME sniffing that could enable script execution. For other image types (PNG, JPEG), `image/*` is safe and does not require attachment headers, but including them does not harm and provides consistent defence-in-depth.

## Behaviour changes
- **Content-Type for SVG**: Changed from `image/svg+xml` to `application/octet-stream`. This forces the browser to download the file as binary data rather than parse it inline. The file content is identical; only how the browser handles it changes.
- **Content-Disposition header added**: New header signals the browser to save the file as an attachment using the server-generated filename. This is a secondary control that reinforces download-only behavior.
- **X-Content-Type-Options header added**: New header instructs the browser not to sniff the file type, preventing bypasses where a malformed file might be interpreted as a different type capable of executing code.

These additions apply the guidance's secondary controls for files containing active content, with no impact on functionality - the bytes returned are unchanged, and the developer's application logic calling this endpoint remains valid.
