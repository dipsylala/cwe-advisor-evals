## Verdict
Real issue. `Files.probeContentType()` detects MIME types through filename heuristics and platform-specific registry lookups, not actual file content inspection. This permits a determined attacker to upload dangerous executable files (shell scripts, Java class files, compiled binaries) by crafting mismatched filename extensions, bypassing the allowlist check.

## Source
Line 42 in DocumentUploadController.java uses `Files.probeContentType(tempFile)` to determine whether to accept an uploaded file. The detected type is checked against `ALLOWED_TYPES`, which contains only `image/jpeg`, `image/png`, and `application/pdf`. However, `probeContentType()` relies on file extension and operating system associations rather than inspecting actual file bytes.

An attacker uploads a file named `script.pdf` containing bash commands or compiled Java bytecode. On systems where `.pdf` maps to `application/pdf` in the file type registry, `probeContentType()` returns `application/pdf` without reading the file's actual content, allowing the malicious file through the filter.

## Fix
Replace `Files.probeContentType()` with Apache Tika, which performs deep content inspection by reading file magic bytes and examining internal structures:

1. Add the Tika dependency to pom.xml: `org.apache.tika:tika-core:2.9.1` (or current maintained version).
2. Initialize a `Tika` detector: `Tika tika = new Tika();`
3. Replace the detection call: `String detectedType = tika.detect(tempFile);`
4. Keep the allowlist check unchanged; Tika's detection is accurate enough that the whitelist now enforces real security rather than guessing.

```java
import org.apache.tika.Tika;

String detectedType = new Tika().detect(tempFile);

if (detectedType == null || !ALLOWED_TYPES.contains(detectedType)) {
    Files.deleteIfExists(tempFile);
    return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
            .body("Rejected: unrecognized or disallowed file type (" + detectedType + ")");
}
```

## Explanation
`Files.probeContentType()` is insufficient for security-sensitive file upload validation because it does not inspect actual file content. Tika reads file signatures (magic bytes) and examines internal structure—for example, PDF files start with `%PDF`, JPEGs with `FFD8`, and PNGs with `89 50 4E 47`. An attacker cannot spoof these signatures by renaming a shell script to `.pdf`; Tika will detect the true type and reject it.

This shift moves the validation from filename-based guessing to content-based detection, eliminating a vector for arbitrary code execution or malicious file storage.
