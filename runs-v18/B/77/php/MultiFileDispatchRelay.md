## Verdict

Exploitable

## Source

User-supplied action string from HTTP request body in `WorkflowStepController::handleStepRequest()`, line 29: `$body['action']`

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
 * checked against a registry; the method half of the string is validated
 * against an allowlist to prevent method injection.
 */
class ActionResolver
{
    /** @var array<string, object> */
    private array $registry;

    /** @var array<string, array<int, string>> Map of handler categories to allowed methods */
    private array $allowedMethods;

    public function __construct()
    {
        $this->registry = [
            'email' => new EmailActionHandler(),
        ];

        // Allowlist of valid methods per category
        $this->allowedMethods = [
            'email' => ['send'],
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

        // Validate the method against the allowlist for this category
        if (!isset($this->allowedMethods[$category]) || !in_array($method, $this->allowedMethods[$category], true)) {
            throw new \RuntimeException("Unknown action method: $category.$method");
        }

        return [$this->registry[$category], $method];
    }
}
```

## Explanation

The vulnerability existed because the `ActionResolver::resolve()` method validated the category half of the action string against a registry, but passed through the method name without any validation. This allowed an attacker to supply any method name (e.g., `email.__construct` or any other method on the handler object), which would then be invoked directly via `$handler->$method()` in `ActionDispatcher::dispatch()`.

The fix introduces an `$allowedMethods` array that explicitly allowlists valid methods per handler category. The `resolve()` method now validates the requested method against this allowlist before returning it. If the method is not recognized, a `RuntimeException` is thrown. This breaks the taint chain by ensuring only pre-approved methods can reach the dispatcher, preventing the injection of arbitrary method names from user input.

The fix uses strict comparison (`in_array(..., true)`) to prevent type juggling attacks, anchors the validation to the category's specific allowed methods, and follows the PHP CWE-77 guidance principle of mapping recognized command verbs to hardcoded handlers via an explicit allowlist.

## Behaviour changes

The fix changes the behavior when an unknown method is requested: instead of allowing the method name to pass through to the dispatcher, it now throws a `RuntimeException` with the message "Unknown action method: {category}.{method}". This is the intended defense - requests with unrecognized method names will fail at the resolver level rather than attempting dynamic invocation. Legitimate requests with allowlisted methods (e.g., `email.send`) continue to work identically. The return type and contract of `resolve()` remain unchanged - it still returns a tuple of `[handler, method]` where the method is now guaranteed to be from the allowlist.
