## Verdict

Confirmed. The workflow action string submitted by the caller is split on `.`, and the substring after the dot is used, unvalidated, as the method name in a dynamic method call on a handler object. Only the category prefix is checked against a registry; the method half is attacker-controlled and lets the caller invoke any public method on the resolved handler object (or, depending on the handler class in a given deployment, any inherited/magic method), not just the intended action.

## Source

- `WorkflowStepController::handleStepRequest()` reads `php://input`, JSON-decodes it, and takes `$body['action']` directly from the request body with only a type check (must be a string) - no content restriction.
- That raw string is passed into `new WorkflowStep($body['action'], $params)`. `WorkflowStep::__construct()` only trims it; the value is otherwise preserved verbatim and returned by `getAction()`.
- `WorkflowExecutionService::execute()` passes `$step->getAction()` straight into `ActionResolver::resolve()`.
- `ActionResolver::resolve()` does `explode('.', $action, 2)`, checks only `$parts[0]` (the category) against `$this->registry`, and takes `$parts[1] ?? 'handle'` as `$method` with no validation at all.
- `ActionDispatcher::dispatch()` then calls `$handler->$method($params)` - the sink - using that attacker-derived `$method`.

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
 * Maps a workflow action string like "email.send" to a handler instance and
 * a method to call on it. The mapping is an explicit allowlist keyed by the
 * full action string, so a caller can only ever trigger one of the exact
 * action names registered here - there is no attacker-influenced method
 * name reaching the dispatcher.
 */
class ActionResolver
{
    /** @var array<string, array{0: object, 1: string}> */
    private array $actions;

    public function __construct()
    {
        $emailHandler = new EmailActionHandler();

        $this->actions = [
            'email.send' => [$emailHandler, 'send'],
        ];
    }

    /** @return array{0: object, 1: string} */
    public function resolve(string $action): array
    {
        if (!isset($this->actions[$action])) {
            throw new \RuntimeException("Unknown workflow action: $action");
        }

        return $this->actions[$action];
    }
}
```

## Explanation

The vulnerable pattern was resolving trust at the wrong granularity: the registry allowlisted the category (`email`) but let the method name ride through unchecked from the request body all the way to a variable method call (`$handler->$method($params)`), which is PHP's dynamic-dispatch equivalent of command injection - the attacker chooses which "command" (method) runs on the object, not just its arguments. Stripping or pattern-matching the method substring would still leave the door open to any name that happens to match a filter; the fix instead removes the attacker's ability to name a method at all. `ActionResolver` now keys its allowlist on the *entire* action string and maps each known one directly to a fixed `(handler, method)` pair chosen by the application, not derived from input. `ActionDispatcher::dispatch()` needs no change: by the time it runs, `$method` is always one of the literal strings the resolver's constructor wrote into `$this->actions`, never a value that passed through user-controlled data. Adding a new action means adding an explicit entry to the map (e.g. `'sms.send' => [$smsHandler, 'send']`), which keeps every reachable method an intentional, reviewable decision instead of an accident of string-splitting.
