<?php

require_once __DIR__ . '/ActionResolver.php';
require_once __DIR__ . '/ActionDispatcher.php';

/**
 * Orchestrates one workflow step: enforces the account's execution quota,
 * records an audit entry, then hands the step off to be resolved and run.
 */
class WorkflowExecutionService
{
    private ActionResolver $resolver;
    private ActionDispatcher $dispatcher;

    public function __construct()
    {
        $this->resolver = new ActionResolver();
        $this->dispatcher = new ActionDispatcher();
    }

    public function execute(WorkflowStep $step): void
    {
        $this->enforceQuota();
        error_log(sprintf('[workflow] step "%s" queued at %d', $step->getAction(), $step->getCreatedAt()));

        [$handler, $method] = $this->resolver->resolve($step->getAction());

        $this->dispatcher->dispatch($handler, $method, $step->getParams());
    }

    private function enforceQuota(): void
    {
        // Unrelated bookkeeping: counts executions per minute per account.
        // Left as a stub here; production reads/writes a rate-limit store.
    }
}
