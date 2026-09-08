## Verdict

exploitable

- cwe_id: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- location: `serializers.py:19`, in `DocumentUploadSerializer.create()`
- confidence: high

## Source

`validated_data["file"]` - the `file` field of `DocumentUploadSerializer`, a `serializers.FileField()` populated directly from the multipart body of `POST /documents/`. DRF's `FileField` only validates that a file-like object was supplied; it performs no content-type or magic-byte inspection.

## Fix

### File: serializers.py

```python
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from .models import Document


class DocumentUploadSerializer(serializers.Serializer):
    """Handles POST /documents/ - accepts a title and a single file upload."""

    title = serializers.CharField(max_length=255)
    file = serializers.FileField()

    def create(self, validated_data):
        # Document.file carries validators=[validate_file_content], a
        # magic-byte check, but that validator only runs under
        # full_clean(). Build the instance unsaved and call full_clean()
        # explicitly so the field validator actually runs before the file
        # is written to storage.
        document = Document(
            owner=self.context["request"].user,
            title=validated_data["title"],
            file=validated_data["file"],
        )
        try:
            document.full_clean()
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.message_dict)
        document.save()
        return document
```

## Explanation

The sink is `Document.objects.create(...)`, which builds and saves the model in one call. `Document.file` already declares `validators=[validate_file_content]`, a magic-byte check, but Django only runs field validators inside `full_clean()` - a path `Model.objects.create()` and `instance.save()` never take. The serializer's `create()` therefore wrote the uploaded file to storage with zero content-type enforcement, regardless of the validator declared on the field. The fix instantiates `Document` without saving, calls `document.full_clean()` to run `validate_file_content` (and the model's other field validators) against the in-memory upload, and only calls `document.save()` once that succeeds. A `django.core.exceptions.ValidationError` raised by the magic-byte check is caught and re-raised as `rest_framework.serializers.ValidationError` so the API still returns a 400 with the validator's message instead of an unhandled 500. This closes the bypass without touching `validate_file_content` itself or the model's `FileField` declaration - the existing allowlist check the field already carries is simply made to run.

## Behaviour changes

- The request now fails with an HTTP 400 (via `serializers.ValidationError`) when `validate_file_content` rejects the upload, where previously the file was always written to storage regardless of type. This is the intended effect of closing the finding, not incidental.
- `full_clean()` also runs Django's standard field validation for `title` and `owner` (required-ness, max length, FK existence) and calls `validate_unique()` for the model. If `Document` has any additional field constraints beyond what the serializer already checks, a request that previously succeeded could now be rejected with a 400 where it previously saved. This is a consequence of routing the save through the model's real validation path rather than around it, which is the documented, intended enforcement point for `validators=[...]` in Django - not a new constraint introduced by this fix.
- `exc.message_dict` assumes the `ValidationError` collected by `full_clean()` carries per-field messages (the standard shape `clean_fields()` produces); this is Django's default behavior and was not independently re-verified against a live Django install.

## Verification

`python -m py_compile` on the fixed file succeeded (no syntax errors). `models.py` was not present in the case directory, so `Document`'s field list and `validate_file_content`'s exact signature could not be cross-checked against a live import; `django.core.exceptions.ValidationError` and `rest_framework.serializers.ValidationError` are standard, well-known APIs from Django and DRF respectively, not names introduced from the fix's own invention. The `full_clean()` bypass mechanism itself is stated directly in the loaded `cwe/434/python/INDEX.md` guidance, not inferred.

## Assumptions

- `Document`'s other fields (`owner`, `title`) do not carry validators that would newly reject data the serializer already considers valid; if they do, that is `full_clean()` correctly enforcing model-level constraints that `Model.objects.create()` was silently skipping, not a defect in this fix.
- `validate_file_content` raises `django.core.exceptions.ValidationError` (the conventional signature for a Django field validator), consistent with the comment in the original file describing it as "a magic-byte check" wired through `validators=[...]`.
