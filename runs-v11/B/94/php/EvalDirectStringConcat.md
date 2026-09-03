## Verdict

Exploitable. The `$expr` variable originates from untrusted user input (`$post['expr']`) and is concatenated directly into an `eval()` call without validation. An attacker can inject arbitrary PHP code that executes with full application privileges.

## Source

**Data flow**: `$post['expr']` (line 18, user-controlled form input) → `$expr` variable → concatenated into `eval()` call (line 26).

The sole validation is checking that `$expr` is not empty; no character filtering, syntax validation, or scope restriction prevents code injection. An attacker submitting `system('id');` or `phpinfo()` as the expression parameter will execute arbitrary commands or expose server information.

## Fix

**Vulnerable code** (line 26):
```php
eval('$result = ' . $expr . ';');
```

**Fixed code**:
```php
use MathParser\StdMathParser;
use MathParser\Interpreting\Evaluator;

class QuickCalculationHandler
{
    public function handleRequest(array $post): array
    {
        $expr = $post['expr'] ?? '';

        if ($expr === '') {
            return ['ok' => false, 'error' => 'Enter an expression to evaluate.'];
        }

        try {
            $parser = new StdMathParser();
            $evaluator = new Evaluator();
            $ast = $parser->parse($expr);
            $result = $evaluator->evaluate($ast);
        } catch (\Exception $e) {
            return ['ok' => false, 'error' => 'Invalid expression: ' . htmlspecialchars($e->getMessage())];
        }

        return ['ok' => true, 'result' => $result];
    }
}
```

**Library recommendation**: `mossadal/math-parser`. This is a mature, maintained library that parses mathematical expressions into an abstract syntax tree and evaluates them safely without using `eval()`. Add to `composer.json`: `"mossadal/math-parser": "^0.3"` (verify the current stable version via SCA/dependency-check tooling before merging).

## Explanation

The fix eliminates code injection by replacing `eval()` with a dedicated mathematical expression parser that tokenizes and validates the input syntax before evaluation. `StdMathParser` constructs an AST that only permits arithmetic operations, functions, and variables—it rejects arbitrary PHP code. The `Evaluator` class interprets the AST in a constrained, expression-only context with no access to PHP's function call, system command, or variable manipulation capabilities.

The error handler wraps exceptions from malformed expressions in `htmlspecialchars()` to prevent error message injection if details are displayed to a client.

## Behaviour changes

- **Added exception handling**: The fixed code catches parse errors and returns an error response instead of fatal application termination. The original code would have thrown `ParseException` if the input could not be parsed as an arithmetic expression; the fix communicates this to the caller as a structured error response, improving robustness.
- **Dependency requirement**: Requires `mossadal/math-parser` to be installed via Composer. The original code had no external dependencies.
- **Error message format**: The original code would silently fail or throw a PHP parse error if malformed input reached `eval()`. The fixed code returns a controlled error message (with HTML escaping) via the API response, preventing information leakage while making debugging clearer for the admin.
- **Supported syntax**: `StdMathParser` supports standard arithmetic operators, parentheses, and built-in math functions (sin, cos, sqrt, etc.). It does not support arbitrary PHP syntax (variable assignment outside the expression, function definitions, loops). This is intentional: the feature is documented as supporting "arithmetic expressions," not general PHP code. If the original design required dynamic PHP evaluation, that design must be reconsidered, as there is no safe way to sandbox `eval()` in PHP.

