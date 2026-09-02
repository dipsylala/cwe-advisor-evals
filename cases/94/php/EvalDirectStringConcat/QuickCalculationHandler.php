<?php
/**
 * Admin-only "quick calculation" tool. Lets an operator type an arithmetic
 * expression (e.g. "12 * (3 + 7)") and see the result without opening a
 * separate calculator. Targets PHP 8.1.
 */

class QuickCalculationHandler
{
    /**
     * Handles POST /admin/tools/quick-calc.
     *
     * Expects a single form field, "expr", containing a PHP-syntax
     * arithmetic expression such as "45 * 1.15" or "(10 + 2) / 4".
     */
    public function handleRequest(array $post): array
    {
        $expr = $post['expr'] ?? '';

        if ($expr === '') {
            return ['ok' => false, 'error' => 'Enter an expression to evaluate.'];
        }

        $result = null;
        // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
        eval('$result = ' . $expr . ';');

        return ['ok' => true, 'result' => $result];
    }
}
