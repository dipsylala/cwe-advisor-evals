## Verdict

- **cwe_id**: CWE-94 (Improper Control of Generation of Code ('Code Injection'))
- **verdict**: exploitable
- **confidence**: high

The finding is confirmed. On the PHP 5.x runtime this file targets (per its own header comment), the `/e` modifier makes `preg_replace()` evaluate its replacement string as PHP code for every regex match. The replacement string is built by directly concatenating an attacker-controlled value into that code, so the sink is genuinely reachable and exploitable, not merely suspicious.

## Source

- **Source**: `$_POST['formatter']` (and `$_POST['template']`), read in `handleRenderRequest()` with no validation, defaulting to `'strtoupper'` only when the POST field is absent.
- **Path**: `handleRenderRequest()` passes `$formatter` straight into `renderUserTemplate($template, $vars, $formatter)`.
- **Sink**: line 24, `preg_replace('/\{(\w+)\}/e', $formatter . '($vars["$1"])', $template)`. For each `{field}` match, `preg_replace` substitutes the captured group into the replacement string and evaluates the result as PHP. Because `$formatter` is concatenated in unescaped, a value such as `system` turns the evaluated code into `system($vars["field"])`, and a value with trailing PHP after a closing paren runs arbitrary additional statements. Any value not present as a callable name (or crafted with extra code) executes with the same privileges as the application.
- **Sink contract**: `preg_replace()` returns the substituted string (or an array if given array input; not applicable here) and `null` on a PCRE error (e.g. backtrack-limit exhaustion); the caller (`handleRenderRequest`) `echo`s the return value directly with no null check. Nothing else is discarded, and no other argument is passed implicitly.

## Fix

### File: PregReplaceEModifierLegacy.php
```php
<?php
// Legacy PHP 5.x template renderer.
// Formatter names are now restricted to a fixed allowlist of safe,
// side-effect-free formatting functions rather than being invoked by
// whatever name the caller supplies.

/**
 * Renders a simple {field} template, applying a per-render formatter
 * function name to each substituted value (e.g. strtoupper, trim).
 *
 * @param string $template  Template string containing {field} placeholders.
 * @param array  $vars      Field name => value pairs to substitute.
 * @param string $formatter Name of a formatting function to apply to each value.
 * @return string Rendered template.
 */
function renderUserTemplate($template, array $vars, $formatter)
{
    // Fixed set of permitted formatters, keyed by the identifier a caller
    // may request. Only names in this map are ever invoked, so an
    // attacker-supplied $formatter can no longer select an arbitrary
    // function (e.g. "system") let alone have code concatenated into an
    // evaluated string.
    static $allowedFormatters = array(
        'strtoupper'       => 'strtoupper',
        'strtolower'       => 'strtolower',
        'trim'             => 'trim',
        'ucfirst'          => 'ucfirst',
        'htmlspecialchars' => 'htmlspecialchars',
    );

    if (!array_key_exists($formatter, $allowedFormatters)) {
        throw new InvalidArgumentException('Unsupported formatter: ' . $formatter);
    }
    $safeFormatter = $allowedFormatters[$formatter];

    return preg_replace_callback(
        '/\{(\w+)\}/',
        function ($matches) use ($vars, $safeFormatter) {
            $value = isset($vars[$matches[1]]) ? $vars[$matches[1]] : '';
            return $safeFormatter($value);
        },
        $template
    );
}

/**
 * HTTP handler: renders a user-supplied template using a user-chosen
 * formatter function name. Both the template text and the formatter name
 * come straight from the POST body with no allowlist or validation.
 */
function handleRenderRequest()
{
    $template  = isset($_POST['template']) ? $_POST['template'] : '';
    $formatter = isset($_POST['formatter']) ? $_POST['formatter'] : 'strtoupper';
    $vars      = (isset($_POST['vars']) && is_array($_POST['vars'])) ? $_POST['vars'] : array();

    echo renderUserTemplate($template, $vars, $formatter);
}
```

## Explanation

The `/e` modifier is what turns this into a code-injection sink: it evaluates the replacement string as PHP, and that string was built by concatenating the raw `$formatter` value. The fix replaces `preg_replace(..., '/e')` with `preg_replace_callback()`, which passes each match to an ordinary PHP closure instead of evaluating a generated code string - the vendor-documented replacement for the removed `/e` modifier. Because `$formatter` still names which function runs, closing the eval sink alone would leave an equivalent arbitrary-function-call weakness (an attacker-chosen `$formatter` such as `system` or `passthru` invoked via `call_user_func`/variable-function syntax). The fix therefore also restricts `$formatter` to a fixed allowlist of known-safe, side-effect-free formatting functions and looks up the matching entry rather than calling the caller-supplied name directly, per the CWE-94 guidance's "array of named callables keyed by allowlisted identifiers" pattern. Together this removes both the code-evaluation sink and the arbitrary-function-invocation path it depended on, while preserving the template's substitution behaviour for every formatter the application actually uses.

## Behaviour changes

- **Formatter restricted to an allowlist**: `strtoupper`, `strtolower`, `trim`, `ucfirst`, `htmlspecialchars`. A `$formatter` value outside this set now throws `InvalidArgumentException` instead of running. This is a deliberate, security-required behaviour change - an attacker-controlled formatter name can no longer select or fabricate a call to an arbitrary function - and it is a product decision: extend the allowlist if the application legitimately uses other formatter functions, but do not widen it to accept any callable name. `handleRenderRequest()`'s own default (`'strtoupper'`) and its documented example (`trim`) both remain in the allowlist, so the existing default path is unaffected.
- **Missing template variable now substitutes an empty string instead of raising a PHP notice/warning for an undefined array key before implicitly coercing to an empty string.** The original `$vars["$1"]` accessed the array directly inside the evaluated code; a missing key produced an undefined-index notice (suppressed or logged depending on `error_reporting`) but the same effective empty-string value. The fixed code performs the same fallback explicitly via `isset()`, so the substituted output is identical and no notice is emitted. Not a functional change to the visible output.
- **Return-value and failure behaviour of the sink are preserved**: `preg_replace_callback()` returns a string on success and `null` on a PCRE-level failure, matching `preg_replace()`'s contract, so `handleRenderRequest()`'s unchanged `echo` continues to behave the same way in both cases.
- All other code (parameter list, docblock intent, `handleRenderRequest()`) is unchanged.

## Verification

`php -l` (PHP 8.5.8 CLI) on the fixed file: "No syntax errors detected". Functional check run against a copy of the fixed file outside the case directory: `renderUserTemplate('Hello {name}, your role is {role}.', ['name'=>'alice','role'=>'admin'], 'strtoupper')` returned `"Hello ALICE, your role is ADMIN."` (matches the original substitution behaviour for an allowed formatter), and calling it with `'system'` as the formatter threw `InvalidArgumentException: Unsupported formatter: system` instead of executing anything - confirming the injection path is closed. Every new symbol used (`preg_replace_callback`, `array_key_exists`, `InvalidArgumentException`, `isset`) is a PHP standard-library function or built-in exception class already available in this codebase's PHP version.

## Assumptions

- The allowlist of five formatters (`strtoupper`, `strtolower`, `trim`, `ucfirst`, `htmlspecialchars`) was chosen to cover the application's documented example formatters (`strtoupper`, `trim`) plus a small set of common, side-effect-free string functions; the actual set of formatters the application needs is a product decision the developer should confirm and adjust.
- Treated the file's own header comment (targeting the PHP 5.x branch where `/e` still evaluates) as authoritative for the exploitability verdict, since no separate runtime-version artifact was provided.
