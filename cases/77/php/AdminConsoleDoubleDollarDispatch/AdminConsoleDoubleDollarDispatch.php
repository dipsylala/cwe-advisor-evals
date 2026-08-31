<?php
// Admin console: staff type a short command word into a text box and this
// handler dispatches it to the matching internal function.

function clearCache() {
    return 'cache cleared';
}

function purgeSessions() {
    return 'sessions purged';
}

function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
    $result = $$cmd();

    return $result;
}
