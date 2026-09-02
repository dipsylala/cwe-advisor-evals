<?php
/**
 * Report viewer endpoint.
 *
 * Streams a report file to the browser. Changes into the reports
 * directory before opening the requested file, on the assumption that
 * blocking '..' in the request is sufficient to keep every read
 * confined to that directory.
 */

$reportsDir = __DIR__ . '/reports';

function serve_report(string $reportsDir): void
{
    $file = $_GET['file'] ?? '';

    if ($file === '') {
        http_response_code(400);
        echo 'Missing file parameter';
        return;
    }

    // Denylist check: block directory traversal sequences.
    if (str_contains($file, '..')) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    chdir($reportsDir);

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    $handle = fopen($file, 'r');
    if ($handle === false) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    fpassthru($handle);
    fclose($handle);
}

serve_report($reportsDir);
