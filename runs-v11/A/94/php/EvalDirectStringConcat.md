## Verdict

CWE-94 code injection confirmed. The `eval()` function on line 26 directly executes user-supplied input concatenated into a PHP code string. An attacker can inject arbitrary PHP expressions or statements by providing malicious input in the `expr` POST parameter.

## Source

Line 26: `eval('$result = ' . $expr . ';');`

The `$expr` variable originates from untrusted user input (`$post['expr']` on line 18) and flows directly into an `eval()` call without validation or sanitization.

## Fix

```php
<?php
class QuickCalculationHandler
{
    public function handleRequest(array $post): array
    {
        $expr = $post['expr'] ?? '';

        if ($expr === '') {
            return ['ok' => false, 'error' => 'Enter an expression to evaluate.'];
        }

        // Validate that the expression contains only safe arithmetic characters
        if (!preg_match('/^[\d+\-*\/().%\s]+$/', $expr)) {
            return ['ok' => false, 'error' => 'Expression contains invalid characters.'];
        }

        $result = null;
        eval('$result = ' . $expr . ';');

        return ['ok' => true, 'result' => $result];
    }
}
```

Alternatively, use a safer expression evaluation library such as `symplify/easy-coding-standard` or replace `eval()` entirely with a dedicated math expression parser.

## Explanation

The vulnerability allows code injection because `eval()` interprets its argument as PHP code. Concatenating unvalidated user input into the eval argument creates a direct code injection sink.

The fix adds input validation using a regex pattern that restricts the expression to only numeric digits, arithmetic operators (`+`, `-`, `*`, `/`, `%`), decimal points, whitespace, and parentheses for grouping. This ensures the input cannot contain PHP language constructs, function calls, or statement separators.

The regex `/^[\d+\-*\/().%\s]+$/` explicitly rejects any character outside the allowed set, returning an error for malformed input. This reduces the attack surface while maintaining support for standard arithmetic expressions like `"12 * (3 + 7)"` and `"45 * 1.15"`.

For stronger protection, replace `eval()` entirely with a dedicated math expression parser library, which avoids the inherent risks of code generation altogether.
