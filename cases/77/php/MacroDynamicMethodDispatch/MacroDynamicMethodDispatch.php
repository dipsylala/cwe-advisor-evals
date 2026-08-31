<?php
// Report macro engine: template authors embed tokens like {{refresh}} or
// {{exportCsv}} inside a saved report layout, and this handler resolves each
// token to a method call on the report renderer that built the page.

class ReportRenderer {
    public function refresh() { /* ... */ }
    public function exportCsv() { /* ... */ }
    public function purgeCache() { /* ... */ }
    public function deleteReport() { /* ... */ }
}

function runReportMacro(ReportRenderer $renderer) {
    // The macro token comes straight from the report's saved layout, which a
    // report owner can edit through the "custom macro" field in the UI.
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
    $renderer->$macro();
}
