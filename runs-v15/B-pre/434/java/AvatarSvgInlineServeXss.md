## Verdict

Exploitable. The application stores user-uploaded files with validated content but serves them back with MIME types that enable browser execution, allowing XSS attacks via embedded scripts in SVG files.

## Source

`storedName` path parameter in `AvatarDownloadController.download()` (line 17). While the parameter originates from user-controlled input, it has already been validated and replaced with a server-generated filename during the upload phase via `AvatarStorage.store()`. The actual source of the taint is the file content itself—an attacker can upload an SVG file with embedded `<script>` tags during the upload phase (not shown in this case, but implied by the name `AvatarSvgInlineServeXss`).

## Fix

**Vulnerable code (line 16–23):**

```java
@GetMapping("/api/avatars/{storedName}")
public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
    byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
    String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(bytes);
}
```

**Fixed code:**

```java
@GetMapping("/api/avatars/{storedName}")
public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
    byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
    
    // Reject SVG uploads entirely, or serve all files as attachments to prevent inline rendering
    if (storedName.endsWith(".svg")) {
        throw new IllegalArgumentException("SVG files are not supported for serving");
    }
    
    String contentType = storedName.endsWith(".png") ? "image/png" : 
                         storedName.endsWith(".jpg") ? "image/jpeg" : "application/octet-stream";

    return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_TYPE, contentType)
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + storedName + "\"")
            .header("X-Content-Type-Options", "nosniff")
            .body(bytes);
}
```

**Alternative fix (if SVG support is required):**

Instead of rejecting SVG, serve all files as attachments without specifying `image/svg+xml`:

```java
@GetMapping("/api/avatars/{storedName}")
public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
    byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
    
    String contentType = storedName.endsWith(".png") ? "image/png" : 
                         storedName.endsWith(".jpg") ? "image/jpeg" : 
                         storedName.endsWith(".svg") ? "application/octet-stream" : "application/octet-stream";

    return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_TYPE, contentType)
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + storedName + "\"")
            .header("X-Content-Type-Options", "nosniff")
            .body(bytes);
}
```

## Explanation

The vulnerability exists because the application serves SVG files with `Content-Type: image/svg+xml`, which instructs browsers to render the SVG and execute any embedded JavaScript. An attacker can upload an SVG file containing `<script>` tags, and when another user downloads and views that file, the malicious script executes in their browser context, enabling XSS attacks.

The primary fix is to reject SVG uploads entirely (recommended for most applications) or to serve all files as attachments with `Content-Disposition: attachment`, forcing the browser to download rather than render them inline. The `X-Content-Type-Options: nosniff` header prevents MIME-type sniffing attacks.

For SVG support, the alternative approach serves SVG with `application/octet-stream` (or any non-executable MIME type), which browsers download rather than render. A more robust long-term solution involves re-encoding images (including SVG) before storage using a sanitization library to strip embedded scripts, but that requires changes to `AvatarStorage` and would need a dependency like `batik` or an external SVG sanitization service.

## Behaviour changes

- **User experience change**: Files are now downloaded as attachments rather than displayed inline. For image files, users must open them separately after download instead of viewing them in the browser tab.
- **Rejection of SVG uploads**: The application now rejects requests for SVG files with a 400 error, breaking any client code that depends on SVG availability. If SVG support is required, use the alternative fix instead.
- **Response headers added**: Two new headers (`Content-Disposition` and `X-Content-Type-Options`) are added to every download response; applications that parse or validate response headers may need to account for these additions.
- **MIME type for SVG changed** (alternative fix only): SVG files are served with `application/octet-stream` instead of `image/svg+xml`, preventing inline rendering but requiring explicit client handling if SVG preview functionality is expected.
