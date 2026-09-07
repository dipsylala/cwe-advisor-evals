## Verdict

Exploitable. An authenticated user can create an ExpenseReport and assign it to any other user by including an `owner` field in the request body. The `perform_create()` method accepts whatever the serializer provides without enforcing that the new report's owner is the requesting user.

## Source

HTTP POST request to the create endpoint, with `owner` field in the request body, from an authenticated user.

## Fix

**Vulnerable code:**
```python
def perform_create(self, serializer):
    # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    serializer.save()
```

**Fixed code:**
```python
def perform_create(self, serializer):
    # Enforce ownership: the report being created must belong to the requesting user
    serializer.save(owner=self.request.user)
```

## Explanation

The vulnerability occurs because object-level permission checks (via `IsExpenseReportOwner.has_object_permission()`) do not run during resource creation in DRF - `get_object()` is never called. The ExpenseReportSerializer includes `owner` as a writable field, allowing clients to specify any user as the owner. The fix explicitly sets `owner=self.request.user` in `perform_create()`, ensuring the created report always belongs to the authenticated user regardless of what the request body contains. This closes the ownership-bypass vulnerability while preserving the serializer's contract and the existing permission class structure.

## Behaviour changes

`serializer.save(owner=self.request.user)` now explicitly provides the `owner` argument, overriding any client-supplied value. The original code passed no explicit arguments, leaving owner derivation to the serializer's validated_data. The change constrains owner assignment to the authenticated user, which is the documented intended behavior per the ViewSet's docstring ("retrieve/update/destroy are object-scoped"). No other method signatures, return values, or exception handling change.
