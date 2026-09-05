## Verdict

Exploitable

## Source

Untrusted input: `$body['action']` from JSON request body in `WorkflowStepController::handleStepRequest()` (line 17-29). The action string is forwarded through `WorkflowStep` to `ActionResolver::resolve()`, where it is split on `.` and the method portion is extracted without validation.

## Fix

**Vulnerable code in ActionResolver.php:**

```php
public function resolve(string $action): array
{
    $parts = explode('.', $action, 2);
    $category = $parts[0];
    $method = $parts[1] ?? 'handle';

    if (!isset($this->registry[$category])) {
        throw new \RuntimeException("Unknown workflow category: $category");
    }

    // $method still carries whatever the caller wrote after the dot.
    return [$this->registry[$category], $method];
}
```

**Fixed code:**

```php
public function resolve(string $action): array
{
    $parts = explode('.', $action, 2);
    $category = $parts[0];
    $method = $parts[1] ?? 'handle';

    if (!isset($this->registry[$category])) {
        throw new \RuntimeException("Unknown workflow category: $category");
    }

    // Validate the method name against an allowlist of known methods per category
    $allowedMethods = [
        'email' => ['send'],
    ];

    if (!isset($allowedMethods[$category]) || !in_array($method, $allowedMethods[$category], true)) {
        throw new \RuntimeException("Unknown method for category $category: $method");
    }

    return [$this->registry[$category], $method];
}
```

## Explanation

The vulnerability exists because `ActionResolver::resolve()` extracts the method name from untrusted user input without validating it against a whitelist of known methods. An attacker can supply arbitrary method names (e.g., `email.__wakeup` or `email.nonexistent`) that will be invoked on the handler object via variable method dispatch in `ActionDispatcher::dispatch()`. The fix adds an explicit allowlist mapping known categories to their permitted methods, validates the extracted method name against this map, and raises a `RuntimeException` if an unknown method is requested. Only allowlisted methods reach the dynamic dispatch sink, eliminating the command injection vector.

## Behaviour changes

The fix introduces a new validation step that rejects requests with unknown method names. Previously, any method name passed in the action string would be attempted on the handler object. After the fix, only methods explicitly listed in `$allowedMethods` are permitted. This is the intended behavior change: legitimate requests using `email.send` continue to work, while requests attempting to invoke unintended methods are rejected with a clear error message. No other behavior of the resolve or dispatch pipeline changes.
