## Verdict

Exploitable.

## Source

POST request data submitted to `/expense-reports/` (implied by DRF ModelViewSet routing), specifically the `owner` field in the JSON body or form data.

## Fix

**Vulnerable code (line 21-23):**
```python
def perform_create(self, serializer):
    # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    serializer.save()
```

**Fixed code:**
```python
def perform_create(self, serializer):
    serializer.save(owner=self.request.user)
```

## Explanation

The vulnerability occurs because `IsExpenseReportOwner.has_object_permission()` enforces ownership only for retrieve/update/destroy operations, which call `get_object()`. During create, `get_object()` is never called, so `has_object_permission()` does not run. The serializer exposes the `owner` field as writable, allowing an authenticated attacker to POST an expense report with `owner` set to another user's ID, bypassing ownership enforcement entirely. The fix passes `owner=self.request.user` to `serializer.save()`, forcing the created report to be owned by the requesting user and closing the authorization gap on create.

## Behaviour changes

None. The fix preserves the serializer's return value (the created ExpenseReport instance) and the semantics of the save operation. The only change is constraining the `owner` field to the authenticated user rather than allowing it to be specified in the request, which is the intended authorization enforcement and not a regression.
