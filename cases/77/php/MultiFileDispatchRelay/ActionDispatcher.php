<?php

/**
 * Final step of the workflow pipeline: invokes the resolved method on the
 * resolved handler with the step's parameters.
 */
class ActionDispatcher
{
    public function dispatch(object $handler, string $method, array $params): void
    {
        // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
        $handler->$method($params);
    }
}
