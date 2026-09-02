<?php
/**
 * Handles avatar image uploads for a user profile form.
 * Restricts uploads to image files by checking the filename against
 * an allowlist of image extensions before storing the file.
 */

function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    $originalName = $file['name'];

    // Only allow filenames that contain one of the approved image
    // extensions somewhere in the name.
    $allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif'];
    $hasAllowedExtension = false;
    foreach ($allowedExtensions as $ext) {
        if (strpos(strtolower($originalName), $ext) !== false) {
            $hasAllowedExtension = true;
            break;
        }
    }

    if (!$hasAllowedExtension) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }

    // Keep the client's original filename (extension chain and all) so
    // the avatar keeps a recognizable name in the uploads listing.
    $destination = $uploadDir . '/' . $originalName;

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
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
