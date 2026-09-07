## Verdict

EXPLOITABLE. Untrusted input from the workflow request directly selects the method name invoked on a handler object without validation. An attacker can craft a request like `{"action":"email.maliciousMethod"}` to invoke any method on the EmailActionHandler, or any handler once additional categories are added.

## Source

WorkflowStepController.handleStepRequest() line 16-17: reads untrusted JSON from the request body. The `action` field is checked only for presence and string type, but its content is never restricted to known verbs. The action string flows through WorkflowStep (line 29) to WorkflowExecutionService.execute() (line 21-26) to ActionResolver.resolve() (line 34-45), where the method half is extracted but NOT validated.

## Fix

In ActionResolver.php, add a method allowlist for each handler category and validate the method name against it before dispatch. Replace ActionResolver.php with:

```php
<?php

class ActionResolver
{
    /** @var array<string, object> */
    private array $registry;

    /** @var array<string, string[]> */
    private array $methodAllowlist;

    public function __construct()
    {
        $this->registry = [
            'email' => new EmailActionHandler(),
        ];
        // Define allowed methods for each category handler
        $this->methodAllowlist = [
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

        // Validate method name against the allowlist for this category
        if (!in_array($method, $this->methodAllowlist[$category] ?? [], true)) {
            throw new \RuntimeException("Unknown action method: $method");
        }

        return [$this->registry[$category], $method];
    }
}
```

The fix introduces `$methodAllowlist`, a hardcoded array mapping each handler category to the set of safe method names callable on it. The `resolve()` method now validates that the method extracted from the action string is explicitly listed in the allowlist for that category before returning it. Any method not in the allowlist triggers a `RuntimeException`.

## Explanation

The vulnerability exists because ActionResolver splits the action string on the first dot to extract the category and method name, validates only the category against the registry, and returns the unvalidated method to ActionDispatcher, which then invokes it via dynamic dispatch (`$handler->$method()`). This allows an attacker to invoke any public method on any registered handler by constructing an action string like "email.someOtherMethod".

The fix applies the primary defence principle from CWE-77 PHP guidance: an explicit allowlist array maps each category to its safe, hardcoded method names. The method is now validated before it reaches the dispatch sink. The allowlist is maintained per category, so as new handlers are added, their safe methods must be explicitly registered. This breaks the taint at the resolution stage: only the methods in the allowlist can be returned to the dispatcher, preventing arbitrary method invocation.

## Behaviour changes

**Non-breaking for legitimate use:** Requests with known action strings like `{"action":"email.send"}` continue to work exactly as before.

**Breaking for invalid verbs:** Requests with unknown methods like `{"action":"email.maliciousMethod"}` now throw a `RuntimeException` with message "Unknown action method: maliciousMethod" instead of silently invoking an arbitrary method. Callers receive a 500 error (unless caught higher in the stack). This is the correct behaviour for CWE-77: reject unknown command verbs outright rather than attempting to execute them.

**Scaling consideration:** When new handler categories are added (e.g., Sms, Slack, Webhook), each must have its allowed methods explicitly registered in `$methodAllowlist`. Forgetting to do so will cause all requests for that category to fail with "Unknown action method" until the allowlist is populated, providing immediate feedback during testing.
