## Verdict

Exploitable. An attacker can upload files with dangerous MIME types (e.g., executable, shell script, etc.) despite the Document model declaring a `validate_file_content` validator on the FileField, because the DRF serializer's `create()` method bypasses field validation by calling `Model.objects.create()` instead of enforcing `full_clean()`.

## Source

Untrusted file upload: `validated_data["file"]`, received from the HTTP request body via the FileField on the DocumentUploadSerializer.

## Fix

### File: serializers.py

```python
from rest_framework import serializers

from .models import Document


class DocumentUploadSerializer(serializers.Serializer):
    """Handles POST /documents/ - accepts a title and a single file upload."""

    title = serializers.CharField(max_length=255)
    file = serializers.FileField()

    def create(self, validated_data):
        # Document.file carries validators=[validate_file_content], a
        # magic-byte check. This validator only runs under full_clean(),
        # not under Model.objects.create() or instance.save() directly.
        # Create the instance first, call full_clean() to trigger validation,
        # then save it.
        document = Document(
            owner=self.context["request"].user,
            title=validated_data["title"],
            file=validated_data["file"],
        )
        document.full_clean()  # This runs the validate_file_content validator
        document.save()
        return document
```

## Explanation

The original code used `Document.objects.create()`, which persists a model instance directly without calling field validators. Django field validators only run when `full_clean()` is invoked—typically in ModelForms or when explicitly called on an instance. The Document model declares `validators=[validate_file_content]` on its FileField, which performs magic-byte validation against an allowlist of safe MIME types (PDF, PNG, JPEG), but this validator was never executed. The fix creates a Document instance, calls `full_clean()` to enforce all field validators (including the magic-byte check), and only then saves it to the database. If the file's actual content does not match an allowed type, `full_clean()` raises a ValidationError before the file is ever persisted.

## Behaviour changes

- Changed from atomic `Model.objects.create()` to instance creation + validation + save. This is the correct Django pattern for enforcing model-level validators.
- `full_clean()` now runs and will raise `ValidationError` if the file's detected MIME type is not in ALLOWED_DOCUMENT_TYPES. This enforces the intended security constraint that was previously bypassed.
- Calling code (the view or API endpoint) should catch and handle ValidationError appropriately (return a 400 Bad Request to the client). This is standard Django form/serializer error handling.
- No change to the return value: the method still returns the created Document instance on success.
- The `document.full_clean()` call will read the file bytes to detect type (the validator calls `magic.from_buffer()`), so there is a small I/O cost, but this is the intended validation cost and occurs only once per upload.
