## Verdict
True Positive

## Source
Lines 20-25 perform an allowlist check using `strpos()` to search for allowed extensions anywhere in the filename. This is insufficient because a file named `malicious.php.jpg` will pass the check (contains `.jpg`) but may still be executed by the web server as PHP code if `.php` is handled before `.jpg`.

## Fix
Extract the actual file extension (the portion after the final dot) and compare only that against the allowlist. Additionally, generate a safe filename to prevent any double extension or extension manipulation:

```php
function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    $originalName = $file['name'];

    // Extract the actual file extension (the part after the final dot).
    $pathInfo = pathinfo($originalName);
    $extension = isset($pathInfo['extension']) ? strtolower($pathInfo['extension']) : '';

    // Only allow specific image extensions.
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
    
    if (!in_array($extension, $allowedExtensions, true)) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Generate a safe filename using a unique ID plus the validated extension.
    // This prevents multiple extensions and other filename-based bypasses.
    $safeFilename = bin2hex(random_bytes(16)) . '.' . $extension;
    $destination = $uploadDir . '/' . $safeFilename;

    move_uploaded_file($file['tmp_name'], $destination);

    return ['ok' => true, 'path' => $destination];
}
```

## Explanation
The original code searches for allowed extensions anywhere in the filename using `strpos()`, which is vulnerable to double extension bypasses. An attacker uploads `malicious.php.jpg`; the check finds `.jpg` and allows it, but the server executes it as PHP if the `.php` handler runs first or if configuration processes extensions in a certain order.

The fix uses `pathinfo()` to extract only the true file extension—the part after the final dot—and validates against an allowlist using `in_array()` with strict type checking. Crucially, it then generates a new, safe filename using a random identifier and the validated extension alone, eliminating any possibility of double extensions or other filename manipulation. The original filename is discarded, preventing the web server from seeing any dangerous extension prefix.
