<?php

/**
 * Immutable value object for one workflow step. Bundles the action string
 * with its parameters and a creation timestamp so downstream services don't
 * have to pass three loose arguments around.
 */
class WorkflowStep
{
    private string $action;
    private array $params;
    private int $createdAt;

    public function __construct(string $action, array $params)
    {
        // Only shape is enforced here (must be a non-empty string); the
        // content of $action is not restricted to any known verb.
        $this->action = trim($action);
        $this->params = $params;
        $this->createdAt = time();
    }

    public function getAction(): string
    {
        return $this->action;
    }

    public function getParams(): array
    {
        return $this->params;
    }

    public function getCreatedAt(): int
    {
        return $this->createdAt;
    }
}
