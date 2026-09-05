## Verdict
Real issue confirmed. SVG files served with `Content-Type: image/svg+xml` execute embedded scripts in the browser context, allowing XSS.

## Source
The vulnerable code is at line 22 in `AvatarDownloadController.java`:

```java
return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(bytes);
```

where `contentType` is set to `"image/svg+xml"` for `.svg` files (line 19). When a user-uploaded SVG file contains malicious JavaScript (e.g., `<script>alert('XSS')</script>`), the browser executes it because the MIME type tells the browser to parse and run scripts within SVG content.

## Fix
Serve SVG files with `Content-Disposition: attachment` to force download instead of inline rendering, preventing browser script execution:

```java
@GetMapping("/api/avatars/{storedName}")
public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
    byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
    String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";
    
    ResponseEntity.BodyBuilder builder = ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_TYPE, contentType);
    
    // Force download for all files to prevent inline script execution
    builder.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + storedName + "\"");
    
    return builder.body(bytes);
}
```

Alternatively, serve SVG files with a safer MIME type that prevents script execution:

```java
String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";
// Add Content-Security-Policy header for SVG to block inline scripts
ResponseEntity.BodyBuilder builder = ResponseEntity.ok()
    .header(HttpHeaders.CONTENT_TYPE, contentType)
    .header("Content-Security-Policy", "default-src 'none'");
return builder.body(bytes);
```

## Explanation
The `AvatarStorage.store()` method validates file content by MIME type (image/png, image/jpeg, image/svg+xml) before storage. However, the download endpoint re-derives the MIME type from the file extension (.svg) and serves the file inline. SVG is an XML-based format that can embed `<script>` tags; when served with `Content-Type: image/svg+xml`, browsers parse and execute these scripts in the origin's security context, bypassing same-origin policy protections.

The fix enforces download behavior via `Content-Disposition: attachment`, forcing browsers to save the file rather than render it, preventing script execution. Alternatively, a strict `Content-Security-Policy` header blocks all inline script execution within the SVG context.
