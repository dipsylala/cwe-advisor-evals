## Verdict

CWE-434 confirmed. The serializer bypasses the model's file validators by using `objects.create()`, which does not call field-level validation. Unrestricted file uploads bypass the `validate_file_content` check.

## Source

File: `serializers.py`, line 19

The `create()` method uses `Document.objects.create()` to save the uploaded file. Django's `objects.create()` bypasses field validators—those run only during `full_clean()` or explicit model validation. The `Document.file` field declares `validators=[validate_file_content]` in `models.py`, but that validator is never invoked here, so any file type bypasses the magic-byte check.

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
        # Run field validators explicitly since objects.create() bypasses them.
        file = validated_data["file"]
        file_field = Document._meta.get_field("file")
        
        for validator in file_field.validators:
            validator(file)
        
        return Document.objects.create(
            owner=self.context["request"].user,
            title=validated_data["title"],
            file=file,
        )
```

## Explanation

The fix extracts the file field's validators from the model and calls each one explicitly before creating the Document. This ensures `validate_file_content` runs and rejects files whose actual bytes do not match an allowed MIME type, even though `objects.create()` was used instead of the longer `full_clean()` path.

By getting validators from the model field dynamically, the code remains maintainable: if new validators are added to the model later, they automatically run here too.

The file pointer is reused after validation; `validate_file_content` calls `seek(0)` after reading, so the file is positioned correctly for Django's storage backend.
