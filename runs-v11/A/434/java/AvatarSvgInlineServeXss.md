## Verdict

The code in `AvatarDownloadController.java` at line 22 serves SVG files inline with the `image/svg+xml` content type. This enables script execution in the browser because SVG files are XML-based and can contain embedded JavaScript. Even though the file was validated at upload time by MIME type detection, serving it inline creates a stored XSS vulnerability (CWE-434).

## Source

```java
// Line 19-22 in AvatarDownloadController.java
String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";

// SAST FINDING: CWE-434 reported here. Sink is the next statement.
return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(bytes);
```

The vulnerability path:
1. `AvatarStorage.store()` accepts `detectedType` validated against an allowlist and stores file with extension matching the type
2. `AvatarDownloadController.download()` retrieves the file and sets `Content-Type: image/svg+xml` for SVG files
3. The browser interprets inline SVG and executes any embedded scripts

## Fix

```java
@GetMapping("/api/avatars/{storedName}")
public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
    byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
    String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";

    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_TYPE, contentType)
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + storedName + "\"")
        .body(bytes);
}
```

Alternatively, if inline image display is required and SVG uploads are optional, exclude SVG from the supported types entirely:

```java
@GetMapping("/api/avatars/{storedName}")
public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
    if (storedName.endsWith(".svg")) {
        throw new IllegalArgumentException("SVG files are not supported for inline display");
    }
    byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
    String contentType = "image/*";

    return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(bytes);
}
```

## Explanation

The core issue is serving SVG files with `Content-Type: image/svg+xml` inline. SVG is an XML format that browsers parse and render, including executing any `<script>` tags or event handler attributes. This means an attacker who uploads an SVG containing JavaScript payload will have that script executed in every browser that views the file.

The recommended fix adds `Content-Disposition: attachment` to force the browser to download the file rather than render it inline. This prevents script execution in the page context.

The upload-time validation in `AvatarStorage` correctly restricts to known image types via MIME type detection on file bytes, but that validation alone is insufficient—the vulnerability lies in *how* the validated file is served back to clients.

If SVG support is not required, the simpler and more secure approach is to exclude SVG from the list of supported image types entirely, allowing only PNG and JPEG.
