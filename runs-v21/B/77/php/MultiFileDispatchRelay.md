## Verdict

Exploitable. Untrusted user input reaches a variable method invocation without validation.

## Source

WorkflowStepController.php, line 29: The action string is received from user-supplied JSON request body and passed directly to WorkflowStep without validation of the method portion.

Data flow:
1. User provides action string via JSON (e.g., `{"action":"email.send"}`), line 17
2. Action is extracted and passed to WorkflowStep constructor, line 29
3. WorkflowStep stores action with only basic trimming, WorkflowStep.php line 18
4. WorkflowExecutionService.execute() retrieves the action, line 26
5. ActionResolver.resolve() splits the action string and extracts method name, ActionResolver.php lines 36-38
6. **Critical gap**: method name is returned without validation, line 45
7. ActionDispatcher receives untrusted method name and invokes it, ActionDispatcher.php line 12

## Fix

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
 * the "email" category plus the method name within it. The category is
 * checked against a registry; the method is validated against an allowlist
 * of known methods per category to prevent arbitrary method invocation.
 */
class ActionResolver
{
    /** @var array<string, object> */
    private array $registry;

    /** @var array<string, list<string>> Allowlist of valid methods per category */
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
        $category = $parts[0] ?? '';
        $method = $parts[1] ?? 'handle';

        if (!isset($this->registry[$category])) {
            throw new \RuntimeException("Unknown workflow category: $category");
        }

        // Validate that the method is in the allowlist for this category.
        // This prevents arbitrary method invocation on the handler object.
        if (!isset($this->allowedMethods[$category]) || !in_array($method, $this->allowedMethods[$category], true)) {
            throw new \RuntimeException("Unknown action: $action");
        }

        return [$this->registry[$category], $method];
    }
}
```

## Explanation

The vulnerability occurs because ActionResolver extracts the method name from user input without validation, allowing an attacker to invoke any method on the handler object. The fix adds a `$allowedMethods` array that defines which methods are permitted for each handler category. Before returning the handler and method from `resolve()`, the code now validates that the requested method is in the allowlist for that category. If an unknown method is requested, a RuntimeException is thrown. This prevents variable method invocation from reaching unintended or dangerous methods (such as magic methods `__construct`, `__destruct`, or `__call`) by restricting dispatch to only the explicitly allowed verbs. The allowlist is immutable and defined at class construction time, ensuring no method name derived from user input ever reaches the variable method call in ActionDispatcher.

## Behaviour changes

The original code allowed any method name after the dot in the action string, causing it to be invoked directly. The fixed code restricts method invocation to those explicitly listed in the allowlist. This is an intentional security hardening that changes the application's behaviour: attempts to invoke unknown methods now throw `RuntimeException` and are logged, rather than silently invoking an arbitrary method. Legitimate requests using only the allowed methods ('send' or 'handle' for the email category) work identically. This is a required gate and not a regression—the application has no documented support for arbitrary method invocation, and the old behaviour was purely exploitable.
