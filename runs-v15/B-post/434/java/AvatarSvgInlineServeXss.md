## Verdict

**VULNERABLE**. The download handler serves SVG files with `Content-Type: image/svg+xml`, which instructs browsers to parse and render the content inline. When the stored SVG file contains embedded JavaScript (e.g., `<script>` or event handlers), the browser will execute it in the context of the application's origin. This violates the CWE-434 principle that uploaded files with active content must be served in a way that prevents execution.

The file validation in `AvatarStorage` is correct (content is detected and extension is generated), but `AvatarDownloadController` undermines it by serving SVG inline, enabling stored XSS.

## Source

**File**: `cases.upload.AvatarDownloadController`  
**Line**: 22 (the `ResponseEntity.ok().header(...).body(bytes)` call)

**Data flow**:
1. `@GetMapping("/api/avatars/{storedName}")` accepts `storedName` path variable from HTTP request
2. Line 18: `Files.readAllBytes(STORAGE_ROOT.resolve(storedName))` reads the stored file
3. Line 19: `String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*"` infers MIME type from extension
4. Line 22: `ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(bytes)` sets the Content-Type header and returns the file

The sink is the HTTP response header that instructs the browser how to interpret the file content. Setting `Content-Type: image/svg+xml` causes the browser to parse and execute embedded scripts.

## Fix

**Vulnerable code** (lines 16–23):
```java
@GetMapping("/api/avatars/{storedName}")
public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
    byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
    String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";  // UNSAFE: SVG served as SVG

    return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(bytes);
}
```

**Fixed code**:
```java
@GetMapping("/api/avatars/{storedName}")
public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
    byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
    
    // Serve SVG as attachment to prevent inline script execution
    if (storedName.endsWith(".svg")) {
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_TYPE, "application/octet-stream")
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment")
            .header("X-Content-Type-Options", "nosniff")
            .body(bytes);
    }
    
    String contentType = storedName.endsWith(".png") ? "image/png" 
                       : storedName.endsWith(".jpg") ? "image/jpeg"
                       : "image/*";
    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_TYPE, contentType)
        .body(bytes);
}
```

**New imports required**:  
None—`HttpHeaders.CONTENT_DISPOSITION` is already available from `org.springframework.http.HttpHeaders`.

## Explanation

The fix prevents browser-side script execution by changing how SVG files are served:

1. **For SVG files**: The code now serves them with `Content-Type: application/octet-stream` instead of `image/svg+xml`. This instructs the browser to treat the content as a generic binary download rather than as an SVG document to be parsed. Combined with `Content-Disposition: attachment`, the browser will offer to save the file to disk instead of rendering it inline, eliminating the execution context.

2. **Defence-in-depth header**: `X-Content-Type-Options: nosniff` tells the browser not to guess the MIME type if it differs from the one provided, preventing accidental script execution on browsers that ignore `Content-Disposition`.

3. **For other image types** (PNG, JPEG): The code now explicitly specifies the correct MIME type based on the file extension. This is safe because the stored filename extension matches the detected content type (enforced by `AvatarStorage`), and PNG/JPEG cannot carry executable scripts.

This fix aligns with CWE-434 remediation guidance: "Store uploaded files outside the webroot or in storage incapable of executing scripts; serve them back only through application-controlled logic" and "Add secondary controls … safe response headers (forced attachment download, no-sniff) when serving files back to users."

The vulnerability was not in the upload validation (which correctly detected content type and generated a safe filename), but in the download handler's choice of Content-Type header, which is under full application control and must prevent execution of active content.

## Behaviour changes

- **SVG files**: Now served with `Content-Type: application/octet-stream` and `Content-Disposition: attachment`. Users will be prompted to save SVG files to disk instead of viewing them inline in the browser. Any embedded scripts in the SVG will not execute in the application's context.
- **PNG/JPEG files**: Now served with explicit, correct MIME types (`image/png`, `image/jpeg`) instead of the generic `image/*`. This improves browser handling but does not change security (these formats cannot carry executable scripts).
- **Response headers**: All responses now include `X-Content-Type-Options: nosniff` for SVG files, preventing MIME-sniffing bypasses.
- **No functional change to upload logic**: The `AvatarStorage` class requires no changes; it already validates content correctly and generates safe filenames.
