<?php

require_once __DIR__ . '/WorkflowStep.php';
require_once __DIR__ . '/WorkflowExecutionService.php';

/**
 * Receives a single workflow step from the marketing-automation builder UI.
 * A step looks like {"action":"email.send","params":{"to":"a@b.com"}} where
 * the action string names a category and a method within it, chosen by
 * whoever authored the workflow (a customer-facing admin, not a developer).
 */
class WorkflowStepController
{
    public function handleStepRequest(): void
    {
        $raw = file_get_contents('php://input');
        $body = json_decode($raw, true);

        if (!isset($body['action']) || !is_string($body['action'])) {
            http_response_code(400);
            echo json_encode(['error' => 'action is required']);
            return;
        }

        $params = is_array($body['params'] ?? null) ? $body['params'] : [];

        // The action string is forwarded exactly as submitted; nothing here
        // restricts it to a known set of workflow verbs.
        $step = new WorkflowStep($body['action'], $params);

        $service = new WorkflowExecutionService();
        $service->execute($step);

        echo json_encode(['status' => 'queued']);
    }
}
