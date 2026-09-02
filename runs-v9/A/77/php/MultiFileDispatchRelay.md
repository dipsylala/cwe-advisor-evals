## Verdict

Confirmed. The `$method` value that `ActionDispatcher::dispatch()` invokes on line 12 (`$handler->$method($params)`) is attacker-controlled and is never checked against a set of permitted method names before being used to select the operation that runs.

## Source

`WorkflowStepController::handleStepRequest()` reads the raw HTTP request body (`file_get_contents('php://input')`), JSON-decodes it, and takes `$body['action']` as-is — only its presence and type (`is_string`) are checked, not its content. That string is wrapped in a `WorkflowStep` (which only trims it, applying no allowlist or format check) and flows through `WorkflowExecutionService::execute()` into `ActionResolver::resolve()`.

`resolve()` splits the action on the first `.`: the left half (`$category`) is checked against a fixed handler registry, but the right half (`$method`) is taken verbatim — "`$method` still carries whatever the caller wrote after the dot," per the code's own comment — and returned unchanged. `ActionDispatcher::dispatch()` then calls `$handler->$method($params)`, so the caller's raw text becomes the name of the method PHP invokes.

## Fix

Root-cause the fix in `ActionResolver`: stop deriving the method name from user input at all. Resolve the *entire* action string against an explicit, hard-coded allowlist that maps each supported action to the one method it is permitted to invoke, and reject anything not in that list.

```php
class ActionResolver
{
    /** @var array<string, object> */
    private array $registry;

    /**
     * Every action this system supports, and only that method, mapped
     * explicitly. Nothing derived from request input appears on the
     * right-hand side.
     */
    private const ALLOWED_ACTIONS = [
        'email.send' => 'send',
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
        if (!isset(self::ALLOWED_ACTIONS[$action])) {
            throw new \RuntimeException("Unknown workflow action: $action");
        }

        $category = explode('.', $action, 2)[0];
        $method = self::ALLOWED_ACTIONS[$action];

        return [$this->registry[$category], $method];
    }
}
```

`$method` is now always one of the fixed literal strings on the right-hand side of `ALLOWED_ACTIONS`; the request body can only select *which* known entry is used, never supply the method name itself. Adding a new supported action means adding a line to this map, not opening it up to arbitrary input.

As defense in depth, harden `ActionDispatcher` so it still refuses to run even if a future caller passes it an untrusted method some other way:

```php
class ActionDispatcher
{
    public function dispatch(object $handler, string $method, array $params): void
    {
        if (!is_callable([$handler, $method])) {
            throw new \RuntimeException("Handler does not expose action: $method");
        }

        $handler->$method($params);
    }
}
```

This does not by itself fix the vulnerability (a handler's own public methods are all "callable"), but it stops obvious misuse such as passing a nonexistent or non-public target, and documents the dispatcher's own expectation that `$method` must already be trusted by the time it arrives here.

## Explanation

The vulnerability is a dynamic method call whose target name is chosen by request input instead of by server-side logic — PHP's variable method call syntax (`$obj->$method(...)`) will invoke *any* public method the object exposes, so an attacker who controls the string after the `.` in `action` can invoke methods the application never intended to expose through this endpoint (any other public method on `EmailActionHandler`, or on whatever handler classes are added to the registry later, including ones with side effects far more dangerous than `send`).

The original code only allowlists the `category` half of the string (via the `$this->registry` lookup) and lets the `method` half pass through unchecked; the fix collapses that into a single allowlist over the *whole* action string, so both halves are validated together and the method that actually gets called is always one of a fixed set of literals the application defines, never text taken from the request body.
