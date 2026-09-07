## Verdict

**CONFIRMED.** The finding is valid. The `create()` method uses `Document.objects.create()`, which bypasses all field validators including `validate_file_content`. An attacker can upload malicious files of any type that will land on disk unchecked. The fix instantiates the model, calls `full_clean()` to trigger validation, and then saves it.

## Source

```python
def create(self, validated_data):
    # Document.file carries validators=[validate_file_content], a
    # magic-byte check, but that validator only runs under
    # full_clean() - Model.objects.create() never calls it, so the
    # upload lands on disk unchecked regardless of what the model
    # field declares.
    # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    return Document.objects.create(
        owner=self.context["request"].user,
        title=validated_data["title"],
        file=validated_data["file"],
    )
```

Line 19 is the call to `Document.objects.create()`.

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
        # magic-byte check. Create an instance without saving, call
        # full_clean() to run all field validators, then save to ensure
        # the file content is validated before hitting disk.
        instance = Document(
            owner=self.context["request"].user,
            title=validated_data["title"],
            file=validated_data["file"],
        )
        instance.full_clean()
        instance.save()
        return instance
```

## Explanation

Django's `Model.objects.create()` is a direct database insert that skips field-level validators entirely. The `validate_file_content` validator on the Document model's `file` field only runs during `full_clean()`, which is called by `ModelForm.is_valid()` or explicitly by application code.

The fix creates a model instance without saving it, calls `full_clean()` to run all field validators (including the content-type check via magic bytes), and then saves the validated instance. This ensures that the file's actual MIME type is verified against the allowed list before it hits disk, closing the unrestricted upload path.

The `full_clean()` call will raise `ValidationError` if the file content is not one of the allowed types (PDF, PNG, or JPEG), preventing the save and protecting against malicious uploads.
