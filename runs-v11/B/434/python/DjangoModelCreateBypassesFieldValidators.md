## Verdict

**CONFIRMED**

The vulnerability is real and exploitable. The `DocumentUploadSerializer.create()` method uses `Model.objects.create()` to persist uploaded files directly to storage, bypassing the `Document.file` field's validator (which performs content validation). This allows an attacker to upload a file with a dangerous MIME type or malicious content that would have been rejected if the model's field validators were enforced.

## Source

The attacker-controlled source is the `file` parameter in the multipart upload request, which arrives at the DRF serializer as `request.FILES['file']` and is passed through as `validated_data["file"]` to the `create()` method.

## Fix

Replace the `Model.objects.create()` call with instance creation, field validation via `full_clean()`, and then save. This ensures the model's field validators—including the `validate_file_content` check mentioned in the code comment—are executed before the file is persisted.

**Original code (lines 12–23):**
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

**Fixed code (lines 12–21):**
```python
def create(self, validated_data):
    document = Document(
        owner=self.context["request"].user,
        title=validated_data["title"],
        file=validated_data["file"],
    )
    document.full_clean()  # Enforces field validators, including validate_file_content
    document.save()
    return document
```

## Explanation

The vulnerability arises because `Model.objects.create()` bypasses Django's `full_clean()` method, which is where field validators (including `validators=[...]` lists on model fields) are executed. Although the `Document.file` field is decorated with a content validator, that validator only runs when `full_clean()` is called—never when an instance is created via `Model.objects.create()` or saved via `instance.save()` without a preceding `full_clean()`.

The fix constructs a `Document` instance without immediately saving it, then explicitly calls `full_clean()` to run all field validators (including the magic-byte content check), and only saves if validation succeeds. This ensures the file's actual content is validated against the allowlist before it lands on disk, closing the CWE-434 gap.

This pattern is the recommended way to enforce field validators in DRF serializers when the model field carries validation logic that must not be bypassed.

## Behaviour changes

- **Before:** Uploaded files were persisted via `Model.objects.create()`, bypassing the model's field validators. A file with a dangerous or attacker-controlled type would be written to storage unchecked.
- **After:** The instance is validated via `full_clean()` before `save()` is called. If the file's content fails the `validate_file_content` check (e.g., wrong MIME type or magic bytes), a `ValidationError` is raised and the file is not saved. Only files that pass the model's validators are persisted.
- **Side effect:** `full_clean()` is a synchronous blocking call; for large files, this may add slight latency to the upload response. The security guarantee is worth this trade-off.
