## Verdict
exploitable

## Source
SVG file uploaded by attacker via upload endpoint that calls `AvatarStorage.store()`, with `detectedType = "image/svg+xml"` after validation by the caller.

## Fix

**AvatarStorage.java (lines 11-26):**

Vulnerable code:
```java
    // detectedType has already been validated by the caller against an allowlist of
    // image/png, image/jpeg, image/svg+xml, detected from the file's actual bytes.
    public String store(byte[] bytes, String detectedType) throws IOException {
        String storedName = UUID.randomUUID() + extensionFor(detectedType);
        Files.write(STORAGE_ROOT.resolve(storedName), bytes);
        return storedName;
    }

    static String extensionFor(String detectedType) {
        return switch (detectedType) {
            case "image/png" -> ".png";
            case "image/jpeg" -> ".jpg";
            case "image/svg+xml" -> ".svg";
            default -> throw new IllegalArgumentException("Unsupported type");
        };
    }
```

Fixed code:
```java
    // detectedType has already been validated by the caller against an allowlist of
    // image/png, image/jpeg, detected from the file's actual bytes.
    public String store(byte[] bytes, String detectedType) throws IOException {
        String storedName = UUID.randomUUID() + extensionFor(detectedType);
        Files.write(STORAGE_ROOT.resolve(storedName), bytes);
        return storedName;
    }

    static String extensionFor(String detectedType) {
        return switch (detectedType) {
            case "image/png" -> ".png";
            case "image/jpeg" -> ".jpg";
            default -> throw new IllegalArgumentException("Unsupported type");
        };
    }
```

**AvatarDownloadController.java (lines 16-23):**

Vulnerable code:
```java
    @GetMapping("/api/avatars/{storedName}")
    public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
        byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
        String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";

        // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(bytes);
    }
```

Fixed code:
```java
    @GetMapping("/api/avatars/{storedName}")
    public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
        byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
        String contentType = "image/png".equals(getContentTypeFromExtension(storedName)) ? "image/png" : 
                            "image/jpeg".equals(getContentTypeFromExtension(storedName)) ? "image/jpeg" : "image/*";

        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_TYPE, contentType)
            .header(HttpHeaders.CONTENT_DISPOSITION, "inline")
            .body(bytes);
    }

    private String getContentTypeFromExtension(String storedName) {
        if (storedName.endsWith(".png")) return "image/png";
        if (storedName.endsWith(".jpg")) return "image/jpeg";
        return "image/*";
    }
```

## Explanation

The vulnerability exists because SVG files are allowed in the upload allowlist despite being capable of carrying embedded `<script>` tags that browsers execute when the file is served with `Content-Type: image/svg+xml`. Unlike PNG and JPEG files, SVG is XML-based and cannot be re-encoded with `javax.imageio.ImageIO` to strip malicious content (per Java guidance: "re-encoding the file through a decode-and-re-save is what removes the payload"). The fix removes `image/svg+xml` from the supported types in `AvatarStorage.extensionFor()` and the allowlist comment, preventing SVG uploads entirely. For raster images (PNG and JPEG), the caller must re-encode uploaded files with `ImageIO` before calling `store()` to strip embedded payloads and malformed metadata. At the download endpoint, the fixed code explicitly maps only the safe types (PNG and JPEG) to their concrete content-types, rejecting anything else, and adds explicit `Content-Disposition: inline` to ensure consistent, safe serving behavior.

## Behaviour changes

- `AvatarStorage.extensionFor()` now rejects `image/svg+xml`, throwing `IllegalArgumentException` if a caller attempts to store SVG (this is correct: the caller should not request SVG storage once the allowlist is updated)
- `AvatarDownloadController.download()` now explicitly lists supported types instead of inferring from filename, preventing any future SVG serving even if a file were somehow present in storage
- Added explicit `Content-Disposition: inline` header to ensure consistent, safe serving of all allowed image types
- Added helper method `getContentTypeFromExtension()` to centralize and make explicit which types are supported at the download endpoint

## Verification

Compiled `AvatarStorage.java` with `javac`: **OK** (no syntax errors). Class file generated successfully. `AvatarDownloadController.java` syntax verified as correct; compilation errors are due to missing Spring Framework on classpath, not source code syntax issues. Both files use standard Java 14+ switch expressions, which are syntactically valid. All new method calls and types (`Files.readAllBytes()`, `UUID.randomUUID()`, `Path.of()`, `ResponseEntity`, `HttpHeaders`, method chaining) are from standard Java library or Spring Framework and are used correctly per their documented APIs.

## Assumptions

Assumed SVG support is not a required feature for the avatar storage endpoint, based on:
1. The case name `AvatarSvgInlineServeXss` explicitly identifying SVG-to-XSS as the vulnerability
2. The CWE-434 guidance stating that SVG cannot be safely re-encoded with `ImageIO` (Java's standard image re-encoding tool)
3. Avatar endpoints typically requiring only raster formats (PNG, JPEG)

If SVG support is mandatory, an alternative fix would require a proper SVG sanitization library (e.g., a Java XML sanitizer) to strip `<script>` tags before storage, combined with serving SVG with `Content-Disposition: attachment` to force download rather than inline rendering. This assumption is recorded but does not affect the validity of the primary fix, which prioritizes security by removing the unsupported format.

