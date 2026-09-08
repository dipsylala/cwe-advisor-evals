## Verdict

Exploitable (CWE-77, PHP bespoke command-dispatch variant). Confidence: high.

## Source

- **Source:** the `action` field of the JSON request body in `WorkflowStepController::handleStepRequest()` (`$body['action']`, read from `php://input`) - fully attacker-controlled, since the workflow is authored by a customer-facing admin, not a developer.
- **Path:** `$body['action']` is passed unmodified into `new WorkflowStep($body['action'], $params)`, which only `trim()`s it (`WorkflowStep.php`). `WorkflowExecutionService::execute()` reads it back via `$step->getAction()` and passes it to `ActionResolver::resolve()`. There, `explode('.', $action, 2)` splits it into `$category` and `$method`; `$category` is checked against a fixed registry (`isset($this->registry[$category])`), but `$method` (`$parts[1] ?? 'handle'`) is returned to the caller with no check at all. `WorkflowExecutionService::execute()` then calls `ActionDispatcher::dispatch($handler, $method, $step->getParams())`.
- **Sink:** `ActionDispatcher.php:12`, `$handler->$method($params);` - a variable method call where `$method` is the attacker-supplied string after the dot. This matches the PHP CWE-77 guidance's taint sink `$obj->$method()`: the category is allowlisted but the verb is not, so any public method on the resolved handler object (currently `EmailActionHandler`, and per the code comments, additional handler classes in real deployments) can be invoked by name, with an attacker-chosen `$params` array as its sole argument. This is dynamic command dispatch, not OS shell execution, so CWE-77 applies directly rather than routing to CWE-78.

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
 * the "email" category plus the method name within it. Both the category
 * and the method are checked against a fixed allowlist before being
 * returned to the caller for dispatch.
 */
class ActionResolver
{
    /** @var array<string, object> */
    private array $registry;

    /**
     * Per-category allowlist of the only method names a workflow action is
     * permitted to invoke. Adding a handler method here is what exposes it
     * to workflow actions; anything not listed is rejected before dispatch.
     *
     * @var array<string, list<string>>
     */
    private const ACTION_METHODS = [
        'email' => ['send'],
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
        $requestedMethod = $parts[1] ?? 'handle';

        if (!isset($this->registry[$category])) {
            throw new \RuntimeException("Unknown workflow category: $category");
        }

        $allowedMethods = self::ACTION_METHODS[$category] ?? [];
        $index = array_search($requestedMethod, $allowedMethods, true);

        if ($index === false) {
            throw new \RuntimeException("Unknown workflow method: $requestedMethod");
        }

        // Use the canonical value from the allowlist, not the raw input,
        // so a match can only ever select one of the known-safe methods.
        $method = $allowedMethods[$index];

        return [$this->registry[$category], $method];
    }
}
```

## Explanation

`ActionResolver::resolve()` already allowlisted the category half of the action string against `$this->registry` but returned the method half straight through, so `ActionDispatcher::dispatch()`'s `$handler->$method($params)` would invoke any public method name an attacker put after the dot. The fix adds a second, per-category allowlist (`ACTION_METHODS`) mapping each known category to the exact method names a workflow action is permitted to call. `resolve()` looks up `$requestedMethod` in that list with a strict `array_search()` and throws the same `\RuntimeException` used for an unknown category if it isn't present; on a match it takes the canonical string from the allowlist array itself rather than the caller-supplied one, so the value reaching `ActionDispatcher::dispatch()` - and therefore the `$handler->$method()` sink - can only ever be one of the hardcoded, known-safe method names. `ActionDispatcher.php` and the sink call itself are unchanged: the fix closes the gap at the point where the verb is resolved, consistent with the existing category-allowlist pattern in the same function, and keeps the taint break where the guidance places it (allowlist, then pass only the selected value downstream).

## Behaviour changes

- Workflow actions whose method half is not on the new allowlist (anything other than `email.send` for the current single registered category) now throw `\RuntimeException("Unknown workflow method: ...")` instead of reaching dynamic dispatch. Previously such a call either hit PHP's own "call to undefined method" fatal error (if the name didn't exist on the handler) or silently executed an unintended real method on the handler class (if it did) - both outcomes are now replaced by an explicit, caught rejection, matching the handling already in place for an unknown category.
- The default method name `'handle'` used when the action string has no dot (e.g. plain `"email"`) is likewise now rejected, since `'handle'` was never added to `ACTION_METHODS['email']`. No legitimate action in this codebase relies on that fallback (the only real handler method, `send`, requires the dotted form), so this is a closure of unintended surface, not a functional regression.
- The one currently legitimate action, `email.send`, resolves and dispatches identically to before (verified by test below).
- No change to `ActionDispatcher.php`, `WorkflowExecutionService.php`, `WorkflowStep.php`, or `WorkflowStepController.php`; the sink call, its arguments, and the return shape of `ActionResolver::resolve()` (`array{0: object, 1: string}`) are all unchanged.

**Verification:** `php -l` run against all five files in the case's call chain (copied to a scratch directory) reported no syntax errors. A standalone functional test instantiating `ActionResolver`/`ActionDispatcher` directly confirmed: `email.send` still resolves to `EmailActionHandler::send` and dispatches successfully; `email.someOtherMethod` and the bare `email` (implicit `handle`) are both rejected with `RuntimeException`; an unknown category (`sms.send`) is still rejected as before.
