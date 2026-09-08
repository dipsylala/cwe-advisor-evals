## Verdict

CONFIRMED - The finding is valid. The vulnerability occurs at line 19 in `serializers.py` where `Document.objects.create()` bypasses the model's field validators, allowing unrestricted file uploads despite `validate_file_content()` being declared on the `Document.file` field.

## Source

The file upload enters through the serializer's `file` field parameter (`validated_data["file"]` at line 22), which receives the uploaded file bytes from the client.

## Fix

The vulnerable pattern uses `Model.objects.create()`, which bypasses model field validators. The corrected approach creates the model instance explicitly, calls `full_clean()` to trigger validators (including the magic-byte type check), and then saves it.

### File: serializers.py

```python
from rest_framework import serializers

from .models import Document


class DocumentUploadSerializer(serializers.Serializer):
    """Handles POST /documents/ - accepts a title and a single file upload."""

    title = serializers.CharField(max_length=255)
    file = serializers.FileField()

    def create(self, validated_data):
        # Create the instance without saving, so field validators can run
        instance = Document(
            owner=self.context["request"].user,
            title=validated_data["title"],
            file=validated_data["file"],
        )
        # full_clean() runs all field validators, including validate_file_content(),
        # which inspects actual file bytes against ALLOWED_DOCUMENT_TYPES.
        # This raises ValidationError if the file type is not allowed.
        instance.full_clean()
        # Save only after validation succeeds
        instance.save()
        return instance
```

## Explanation

The vulnerability arose because `Model.objects.create()` bypasses Django's field-level validation - it writes the instance directly to the database without calling `full_clean()`. The `Document.file` field declares `validators=[validate_file_content]`, which uses `python-magic` to detect the real file type and rejects uploads outside `ALLOWED_DOCUMENT_TYPES`, but that validator only executes under `full_clean()`.

The fix restructures the `create()` method to:
1. Instantiate the `Document` object without saving it
2. Call `instance.full_clean()`, which triggers all field validators including `validate_file_content()`
3. Call `instance.save()` only if validation succeeds

This ensures the magic-byte type check actually runs before the file is persisted to disk. If the file type is not in the allowlist, `full_clean()` raises a `ValidationError`, preventing the save.

## Behaviour changes

- **Validation enforcement**: Field validators on the model now run for all upload paths (not just `ModelForm.is_valid()`). Files with disallowed content types (even if disguised with misleading extensions or Content-Type headers) are rejected before being written to disk.
- **Error handling**: If file validation fails, a `django.core.exceptions.ValidationError` is raised instead of silently persisting the file. DRF's exception handler will return a 400 Bad Request with the validation error details.
- **Performance**: Minimal - the validation overhead is the file magic-byte inspection, which is already declared on the model and was intended to run.
- **No API changes**: The serializer's interface remains identical; callers see the same input/output contract.
