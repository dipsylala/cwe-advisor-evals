## Verdict

Confirmed. CWE-434 (Unrestricted Upload of File with Dangerous Type) is exploitable as reported.

## Source

`$_FILES['avatar']` (script-level, line 41) - specifically `['name']` (client-supplied original filename) and `['tmp_name']` (server-side temp path of the uploaded content), both attacker-controlled via the multipart request.

## Fix

### File: DoubleExtensionBypassesAllowlist.php

```php
<?php
/**
 * Handles avatar image uploads for a user profile form.
 * Restricts uploads to image files by detecting the actual file content
 * against an allowlist of image MIME types before storing the file.
 */

function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    if (!extension_loaded('fileinfo')) {
        return ['ok' => false, 'error' => 'Server misconfiguration'];
    }

    // Detect the real file type from its content rather than trusting the
    // client-supplied filename or Content-Type header. Map the detected
    // MIME type to a fixed, server-controlled extension so the client can
    // never choose the extension the file is stored under.
    $mimeToExtension = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
    ];

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedMime = $finfo !== false ? finfo_file($finfo, $file['tmp_name']) : false;
    if ($finfo !== false) {
        finfo_close($finfo);
    }

    if ($detectedMime === false || !isset($mimeToExtension[$detectedMime])) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    $extension = $mimeToExtension[$detectedMime];

    // Generate a new, server-controlled filename for storage; never use the
    // client-supplied name or its extension chain as the storage path.
    $storedName = bin2hex(random_bytes(16)) . '.' . $extension;
    $destination = $uploadDir . '/' . $storedName;

    move_uploaded_file($file['tmp_name'], $destination);

    return ['ok' => true, 'path' => $destination];
}

$result = handleAvatarUpload($_FILES['avatar'], __DIR__ . '/uploads');
if (!$result['ok']) {
    http_response_code(400);
    echo json_encode(['error' => $result['error']]);
    exit;
}

echo json_encode(['path' => $result['path']]);
```

## Explanation

The original check used `strpos(strtolower($originalName), $ext) !== false` to test for an allowed extension, which matches the substring anywhere in the filename. A name like `shell.jpg.php` contains `.jpg` and passes the gate, but the file is then stored under its full original name (`$uploadDir . '/' . $originalName`), so it lands on disk as `shell.jpg.php`. A webserver configured to execute PHP based on the final extension runs it as a script - the classic double-extension bypass - regardless of the file's real content.

The fix removes the filename-substring check entirely and instead detects the file's actual type from its bytes with `finfo_open(FILEINFO_MIME_TYPE)` / `finfo_file()` on `$file['tmp_name']`, guarded by an `extension_loaded('fileinfo')` check so a missing extension fails closed with an error rather than fatally erroring or silently skipping validation. The detected MIME type is looked up in a fixed allowlist map (`image/jpeg`, `image/png`, `image/gif`) that yields a single canonical extension; anything not in the map is rejected. That canonical extension - never the client-supplied name or its extension chain - is combined with a random, server-generated filename (`bin2hex(random_bytes(16))`) to build the storage path. Because both the extension and the base filename are now fully server-controlled, an attacker cannot cause a script extension to reach `move_uploaded_file()`'s destination no matter what name or chained extensions the upload carries, closing the double-extension bypass at its root: the untrusted filename never contributes to the stored path or its extension.

Directory-level hardening (denying script execution for the upload directory at the webserver/FPM level, and serving files back through a streaming script rather than a direct URL) is recommended as defence-in-depth per the PHP guidance, but is a webserver/SAPI configuration concern outside this single PHP file and is not asserted as fixed here.

**Verification performed:** `php -l` against the fixed file in a scratch copy reported no syntax errors. Every newly introduced name (`extension_loaded`, `finfo_open`, `finfo_file`, `finfo_close`, `FILEINFO_MIME_TYPE`, `bin2hex`, `random_bytes`) is a PHP standard-library/Fileinfo-extension builtin named explicitly in the loaded `cwe/434/php/INDEX.md` guidance, not a recalled or assumed API. The Fileinfo extension is not installed in this sandbox's PHP build, so the MIME-detection branch itself could not be exercised end-to-end here; a harness copy of the validation logic was run instead and confirmed the `extension_loaded('fileinfo')` guard fails closed (returns `ok:false`) rather than fatally erroring or allowing an unchecked upload through when the extension is absent - the failure mode the guidance specifically calls out. The MIME-to-extension lookup itself is a plain array match against `finfo`'s documented, stable output values (`image/jpeg`, `image/png`, `image/gif`) and was reviewed by inspection.

## Behaviour changes

- Stored files are now named with a random hex string plus a server-chosen extension (e.g. `a3f1...9c.jpg`) instead of the client's original filename. The response's `path` field reflects this new name; callers that expected the original filename to appear in the returned path (e.g. for display purposes) need to track the original name separately (not part of this fix's scope) if that is required.
- Uploads whose real content does not match one of `image/jpeg`, `image/png`, or `image/gif` are now rejected with `"Unsupported file type"` even if the filename previously appeared to match an allowed extension - this is the intended effect of closing the bypass, but any legitimate file type not in this map (e.g. WebP) that was previously accepted purely by filename will now be rejected and must be added to `$mimeToExtension` if it is a required business type.
- If the Fileinfo extension is not loaded on the deployment target, uploads now fail closed with `"Server misconfiguration"` instead of running with no real type validation.
