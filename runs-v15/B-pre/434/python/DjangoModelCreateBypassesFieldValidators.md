## Verdict

exploitable

## Source

`validated_data["file"]` - an untrusted file object from the request, passed through DRF serializer deserialization without type validation.

## Fix

**Vulnerable code (serializers.py, line 19):**

```python
def create(self, validated_data):
    # Document.file carries validators=[validate_file_content], a
    # magic-byte check, but that validator only runs under
    # full_clean() - Model.objects.create() never calls it, so the
    # upload lands on disk unchecked regardless of what the model
    # field declares.
    return Document.objects.create(
        owner=self.context["request"].user,
        title=validated_data["title"],
        file=validated_data["file"],
    )
```

**Fixed code:**

```python
from rest_framework import serializers

from .models import Document, validate_file_content


class DocumentUploadSerializer(serializers.Serializer):
    """Handles POST /documents/ - accepts a title and a single file upload."""

    title = serializers.CharField(max_length=255)
    file = serializers.FileField()

    def create(self, validated_data):
        # Validate the file content before creating the Document.
        # The model field has a validator, but Model.objects.create() never
        # calls full_clean(), so we must validate explicitly here.
        validate_file_content(validated_data["file"])
        return Document.objects.create(
            owner=self.context["request"].user,
            title=validated_data["title"],
            file=validated_data["file"],
        )
```

## Explanation

The vulnerability arises because Django model field validators only run when `full_clean()` is called, but `Model.objects.create()` bypasses that validation step entirely. Although the model defines `validators=[validate_file_content]` to check the real file type using `python-magic`, this validator is silently skipped when the serializer calls `Document.objects.create()`. By explicitly calling `validate_file_content(validated_data["file"])` in the serializer's `create()` method before persisting the model, the file's actual content type is checked against the allowlist (`ALLOWED_DOCUMENT_TYPES`) and any mismatch raises a `ValidationError`, preventing the upload and closing the CWE-434 weakness.

## Behaviour changes

- The `create()` method now validates file content before creating the Document instance.
- If validation fails, a `ValidationError` is raised and no Document is created; previously, any file was accepted.
- The file object is read twice (once in the validator to check magic bytes, then during model save), but the validator seeks the file back to position 0, so the save operation proceeds normally.
- No change to the return value or the successful creation path when validation passes.
