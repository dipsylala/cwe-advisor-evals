# CWE-77 Remediation: MultiFileDispatchRelay

## Verdict

exploitable

The vulnerability is confirmed and exploitable. Untrusted user input (the action string) flows from the HTTP request handler through to the dynamic method invocation without validation of the method name, allowing an attacker to invoke arbitrary methods on handler objects.

## Source

- **Entry point:** WorkflowStepController.handleStepRequest() line 16-17, where user-supplied JSON is decoded
- **Untrusted value:** `$body['action']` - the action string submitted by the client
- **Source path:** JSON input → `WorkflowStepController::handleStepRequest()` → `WorkflowStep` constructor → `WorkflowExecutionService::execute()` → `ActionResolver::resolve()` → `ActionDispatcher::dispatch()`

## Sink

- **File:** ActionDispatcher.php
- **Line:** 12
- **Operation:** `$handler->$method($params);`
- **Vulnerability:** The `$method` parameter is a user-controlled string (from the untrusted action input) that is used for dynamic method invocation without validation.

## Data Flow Trace

1. User submits JSON: `{"action":"email.send", "params":{...}}`
2. WorkflowStepController receives and decodes: `$body['action']` = "email.send" (untrusted)
3. WorkflowStep stores action with only whitespace trimming (line 18), no validation
4. WorkflowExecutionService calls resolver.resolve(step.getAction())
5. ActionResolver splits on "." and extracts:
   - category = "email" (validated against registry at line 40-42) ✓
   - method = "send" (extracted but NOT validated at line 38/44-45) ✗
6. Attacker can provide any method name: "email.__destruct", "email.__toString", "email.nonexistent", etc.
7. ActionDispatcher calls `$handler->$method()` - the arbitrary method is invoked

An attacker can bypass the category allowlist by calling any method on the handler object, including magical methods or methods that trigger __call() handlers, leading to unintended code execution or information disclosure.

## Fix

The vulnerability is fixed by adding method-name validation in ActionResolver. The resolver must allowlist known methods per category, similar to how it already allowlists categories. Only the allowlisted method for the validated category should be returned and used.

### File: ActionResolver.php

```php
<?php

/**
 * Minimal handler used by the email category. Real deployments have several
 * of these (Sms, Slack, Webhook, ...); only one is included here to keep
 * the example self-contained.
 */
class EmailActionHandler
{
    public function send(array $params): void
    {
        error_log('email.send: ' . ($params['to'] ?? 'unknown'));
    }
}

/**
 * Maps a workflow action string like "email.send" to a handler instance for
 * the "email" category plus the method name within it. Both the category and
 * method are checked against known allowlists to prevent injection of
 * arbitrary handlers or methods.
 */
class ActionResolver
{
    /** @var array<string, object> */
    private array $registry;

    /** @var array<string, array<string>> */
    private array $allowedMethods = [
        'email' => ['send', 'handle'],
    ];

    public function __construct()
    {
        $this->registry = [
            'email' => new EmailActionHandler(),
        ];
    }

    /** @return array{0: object, 1: string} */
    public function resolve(string $action): array
    {
        $parts = explode('.', $action, 2);
        $category = $parts[0];
        $method = $parts[1] ?? 'handle';

        if (!isset($this->registry[$category])) {
            throw new \RuntimeException("Unknown workflow category: $category");
        }

        // Validate method against allowlist for this category.
        if (!isset($this->allowedMethods[$category]) || !in_array($method, $this->allowedMethods[$category], true)) {
            throw new \RuntimeException("Unknown action method: $method for category $category");
        }

        return [$this->registry[$category], $method];
    }
}
```

## Explanation

The fix adds a private `$allowedMethods` array that maps each handler category to an array of method names that are safe to invoke on that category's handler. The resolve() method now validates not only that the category exists in the registry (as it did before), but also that the method name is in the allowlist for that category.

When resolve() is called with an action string, it:
1. Splits the string into category and method parts
2. Validates the category exists (unchanged)
3. **NEW:** Validates the method is in the allowlist for that category
4. Throws a RuntimeException if the method is not allowlisted
5. Returns only the validated handler and method

This prevents an attacker from calling arbitrary methods by providing malicious action strings like "email.__destruct" or "email.nonexistent". Only methods explicitly registered in the allowlist can be invoked, matching the CWE-77 remediation guidance: "map each recognised command verb to a specific, hardcoded handler via an explicit allowlist array."

## Behaviour Changes

**Breaking change (intended):** Any action string with a method not in the `$allowedMethods` allowlist will now throw a RuntimeException, where the original code would attempt to invoke it. For example:
- Original: `"email.invalid"` → `$handler->invalid($params)` (invokes magic method or creates an error)
- Fixed: `"email.invalid"` → throws RuntimeException("Unknown action method: invalid for category email")

This is a security boundary enforced at runtime. Valid workflows that use allowlisted methods (e.g., "email.send", "email.handle") will continue to work unchanged.

**Addition:** The allowlist must be maintained when new methods are added to handlers. Each handler category's valid methods must be registered in the `$allowedMethods` array before they can be invoked through this resolver.

**No other behaviour changes:** The return signature, parameter handling, and error handling for unknown categories remain unchanged. Legitimate calls with allowlisted methods will work identically to the original code, but arbitrary method injection is now blocked at the resolution layer before it reaches the dispatcher.

## Verification

PHP syntax check on the fixed code:

```
$ php -l ActionResolver.php
No syntax errors detected
```

The fix:
- Adds a private property `$allowedMethods` with the expected method lists per category
- Uses `in_array($method, $this->allowedMethods[$category], true)` to check membership with strict equality
- Throws RuntimeException on invalid method, matching the existing category validation pattern
- Preserves the exact return type and contract of resolve()
- All new symbols (the allowedMethods array and validation logic) are defined within the ActionResolver class; no external dependencies

## Assumptions

- The application only needs to call the "send" and "handle" methods on EmailActionHandler. If additional methods need to be invoked through the workflow, they must be explicitly added to the allowlist.
- The category validation (checking `$this->registry[$category]`) remains the primary security boundary for handler selection; method allowlisting is a secondary validation that further restricts which methods can be called on validated handlers.
- The allowlisted methods represent the full public interface of each handler that should be callable through the workflow system. Any method not in the allowlist is treated as out of scope for this API.
