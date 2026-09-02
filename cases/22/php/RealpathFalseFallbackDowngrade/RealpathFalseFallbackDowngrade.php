<?php
declare(strict_types=1);

/**
 * Note-saving endpoint.
 *
 * Writes a plain-text note under the "notes" directory. The file name is
 * supplied as a request field and is expected to name a new file directly
 * inside the notes directory (no subdirectories).
 */

const NOTES_DIR_NAME = 'notes';

function resolveBaseDir(): string
{
    $base = realpath(__DIR__ . DIRECTORY_SEPARATOR . NOTES_DIR_NAME);
    if ($base === false) {
        http_response_code(500);
        exit('Note store is not configured.');
    }
    return $base;
}

function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    $candidatePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;

    // realpath() canonicalizes '.' and '..' segments and resolves symlinks,
    // but it returns false unless every component of the path already
    // exists. A note being SAVED for the first time is, by definition, a
    // destination that does not exist yet - so realpath() returns false on
    // essentially every legitimate save, not just malicious ones - and this
    // falls back to the original, unresolved candidate path so the save can
    // proceed.
    $safePath = realpath($candidatePath) ?: $candidatePath;

    // Because $safePath is now just $baseDir . DIRECTORY_SEPARATOR . $requestedFile
    // (unresolved, '../' segments and all), it always starts with $baseDir by
    // construction - the check below passes for literally any $requestedFile,
    // traversal sequences included, since nothing here actually canonicalizes
    // the path before comparing it.
    $isContained = $safePath === $baseDir
        || str_starts_with($safePath, $baseDir . DIRECTORY_SEPARATOR);

    if (!$isContained) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    file_put_contents($safePath, $content);
    echo 'Note saved.';
}

$requestedFile = isset($_POST['file']) ? (string) $_POST['file'] : '';
$content = isset($_POST['content']) ? (string) $_POST['content'] : '';
if ($requestedFile === '') {
    http_response_code(400);
    exit('Missing "file" parameter.');
}

$baseDir = resolveBaseDir();
saveNote($requestedFile, $content, $baseDir);
