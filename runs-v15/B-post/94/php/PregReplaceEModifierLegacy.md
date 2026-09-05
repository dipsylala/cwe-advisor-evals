## Verdict
exploitable

## Source
`$_POST['formatter']` from handleRenderRequest() at line 35, user-controlled with no validation.

## Fix

**Vulnerable code (line 24):**
```php
return preg_replace('/\{(\w+)\}/e', $formatter . '($vars["$1"])', $template);
```

**Fixed code:**
```php
// Allowlist of permitted formatter functions
$allowedFormatters = ['strtoupper', 'strtolower', 'trim'];

// Validate formatter is in allowlist
if (!in_array($formatter, $allowedFormatters, true)) {
    throw new InvalidArgumentException("Invalid formatter");
}

return preg_replace_callback(
    '/\{(\w+)\}/',
    function($matches) use ($vars, $formatter) {
        $key = $matches[1];
        $value = isset($vars[$key]) ? $vars[$key] : null;
        return (string)$formatter($value);
    },
    $template
);
```

## Explanation

The original code uses the `/e` modifier in `preg_replace()`, which evaluates the replacement string as PHP code. Since `$formatter` comes directly from user input and is concatenated into this evaluated string, an attacker can inject arbitrary PHP code (e.g., submitting "system" as the formatter causes `system($vars["..."])` to execute). The fix replaces the deprecated `/e` modifier with `preg_replace_callback()`, which accepts a callable instead of evaluated code. An allowlist restricts the formatter to safe built-in functions, preventing dynamic code execution entirely. The callback safely applies the whitelisted formatter to each matched placeholder value without any code evaluation.

## Behaviour changes

1. **Allowlist validation (error handling):** Invalid formatters now throw `InvalidArgumentException` instead of being passed through to dynamic evaluation. This is a security-critical change that restricts what formatters can be used to a whitelist of safe built-ins.

2. **Formatter application mechanism:** Changed from dangerous concatenation into evaluated code to a direct variable function call within the callback. The formatter is invoked as `$formatter($value)` which is safe since the formatter name is validated.

3. **Return type casting:** Added explicit `(string)` cast on the formatter result to ensure string return from callback. This matches the original behavior but makes it explicit.

4. **Handling missing keys:** Behavior remains the same—when a key doesn't exist in `$vars`, the formatter receives `null` and returns an empty string, matching the original.
