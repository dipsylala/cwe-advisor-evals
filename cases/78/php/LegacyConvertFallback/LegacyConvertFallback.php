<?php

function convert_document(string $requestedName): string
{
    $source = '/srv/uploads/' . basename($requestedName);
    $target = '/srv/converted/' . basename($requestedName) . '.pdf';

    $primary = sprintf(
        '/usr/bin/soffice --convert-to pdf %s --outdir /srv/converted',
        escapeshellarg($source)
    );
    exec($primary, $primaryOutput, $primaryStatus);

    if ($primaryStatus === 0) {
        return $target;
    }

    // SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
    exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);

    return $fallbackStatus === 0 ? $target : '';
}

$path = convert_document($_POST['document']);
