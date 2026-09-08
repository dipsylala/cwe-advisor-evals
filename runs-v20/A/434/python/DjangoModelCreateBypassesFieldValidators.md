## Verdict

Confirmed. `Document.objects.create(...)` builds and saves the model in one call without ever invoking `Model.full_clean()`. Django only runs a field's `validators` list (here, `validate_file_content` on `Document.file`, which inspects the file's magic bytes) from `full_clean()`. `objects.create()` skips that entirely, so the uploaded file is written to disk with no content-type check regardless of what the model field declares - an attacker can upload an executable, script, or any other dangerous file type through this endpoint.

## Source

`self.context["request"].user`-owned multipart upload reaching `validated_data["file"]` in `DocumentUploadSerializer.create()`, `serializers.py` line 19-23 (`Document.objects.create(...)`).

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
        # full_clean(). Build the instance unsaved, run full_clean() so
        # the model's own field validators execute, then save.
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

`Model.objects.create()` is shorthand for `Model(**kwargs); obj.save()` - it never calls `full_clean()`, and Django deliberately does not call `full_clean()` automatically from `save()` either, so a field's `validators=[...]` list is inert unless something explicitly triggers full model validation. The fix constructs the `Document` instance without persisting it, calls `full_clean()` to run `clean_fields()` (which executes `validate_file_content` against the uploaded file's magic bytes, along with every other field validator such as the `title` length check), and only calls `save()` once validation passes. `full_clean()` raises `django.core.exceptions.ValidationError`, which is a different class from DRF's `serializers.ValidationError` and would otherwise surface as an unhandled 500; the `except` block converts it so a rejected upload comes back as a normal DRF 400 response with the field-level error detail. This keeps the validation logic in the one place it is already declared (the model field's `validators`) rather than duplicating the magic-byte check in the serializer, so the source of truth for "what is an acceptable file" stays on the model.
