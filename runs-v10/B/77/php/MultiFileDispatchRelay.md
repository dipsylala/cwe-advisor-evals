## Verdict

Exploitable.

## Source

Untrusted user input originates at `WorkflowStepController::handleStepRequest()` line 16, where the JSON-decoded request body is received via `php://input`. The `action` field from the JSON is passed directly to `WorkflowStep` constructor without validation of its content (line 29). The method name is extracted in `ActionResolver::resolve()` by splitting the action string on `.` (line 36-38), with no allowlist validation of the resulting method name. That unvalidated method name flows to `ActionDispatcher::dispatch()` where it is used in variable method dispatch.

## Fix

**Primary Fix at the Sink (ActionDispatcher):**

```php
// VULNERABLE
class ActionDispatcher
{
    public function dispatch(object $handler, string $method, array $params): void
    {
        // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
        $handler->$method($params);
    }
}
```

```php
// FIXED
class ActionDispatcher
{
    // Allowlist of permitted method names across all action handlers
    private const ALLOWED_METHODS = ['send', 'handle', 'execute'];

    public function dispatch(object $handler, string $method, array $params): void
    {
        // Validate method against allowlist before dispatch
        if (!in_array($method, self::ALLOWED_METHODS, true)) {
            throw new \RuntimeException("Disallowed action method: $method");
        }

        $handler->$method($params);
    }
}
```

**Supplementary Fix at the Source (ActionResolver) - Recommended for Defence-in-Depth:**

```php
// VULNERABLE
class ActionResolver
{
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
}
```

```php
// FIXED
class ActionResolver
{
    // Map categories to their permitted methods
    private array $allowedMethodsByCategory = [
        'email' => ['send', 'handle'],
    ];

    public function resolve(string $action): array
    {
        $parts = explode('.', $action, 2);
        $category = $parts[0];
        $method = $parts[1] ?? 'handle';

        if (!isset($this->registry[$category])) {
            throw new \RuntimeException("Unknown workflow category: $category");
        }

        // Validate that the method is permitted for this category
        $allowed = $this->allowedMethodsByCategory[$category] ?? [];
        if (!in_array($method, $allowed, true)) {
            throw new \RuntimeException("Disallowed action method: $method");
        }

        return [$this->registry[$category], $method];
    }
}
```

## Explanation

The vulnerability allows an attacker to invoke arbitrary public methods on handler objects by submitting workflow actions with method names not intended as action endpoints. An attacker could submit `{"action":"email.toString"}` or target any other public method on the handler, potentially triggering unintended behaviour or bypassing application logic.

The fix applies an allowlist validation to restrict which methods can be dispatched. The primary fix at `ActionDispatcher` validates the method name before the variable dispatch call (`$handler->$method(...)`), ensuring only methods in `ALLOWED_METHODS` can be invoked. The supplementary fix in `ActionResolver` enforces category-specific method allowlists at the source, preventing invalid method names from reaching the dispatcher in the first place. This defence-in-depth approach stops the injection at multiple points in the call chain.

The allowlist is hardcoded based on the legitimate action methods available on the handlers (e.g., `send` and `handle` for the `EmailActionHandler`). If new handlers and methods are added in future, the allowlists in both locations must be updated to include them.

## Behaviour changes

- **New exception type on invalid method**: Submitting an action with a method not in the allowlist now throws `\RuntimeException("Disallowed action method: ...")` instead of attempting dispatch. Calling code must handle this exception (e.g., return an HTTP 400 error). This is a change from the original behaviour where invalid methods would attempt dispatch and then produce a `Call to undefined method` error at runtime, but is more secure and predictable.
- **Allowlist maintenance required**: The `ALLOWED_METHODS` constant (or `$allowedMethodsByCategory` array in ActionResolver) must be updated whenever new legitimate action methods are added to handlers. Failure to do so will block legitimate requests.
- **No change to method return values or parameters**: The method invocation signature remains identical; the only change is the validation gate before dispatch.
