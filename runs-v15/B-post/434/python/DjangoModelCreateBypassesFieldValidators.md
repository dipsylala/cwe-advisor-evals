## Verdict

Exploitable. The file upload is passed directly to `Document.objects.create()` without triggering the model's field validators, allowing an uploaded file with a dangerous MIME type or malicious content to bypass the `validate_file_content` check and persist to storage.

## Source

POST request file upload received by `serializers.FileField()` at line 10 of serializers.py, passed through `serializer.validated_data["file"]` at line 22.

## Fix

**Vulnerable code:**
```python
def create(self, validated_data):
    return Document.objects.create(
        owner=self.context["request"].user,
        title=validated_data["title"],
        file=validated_data["file"],
    )
```

**Fixed code:**
```python
def create(self, validated_data):
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

The original code uses `Model.objects.create()`, which bypasses Django's field validation pipeline. The model's `validate_file_content` validator is defined on the `Document.file` field but never executes because field validators in Django only run during `full_clean()` or `ModelForm.is_valid()`, not during direct `create()` or `save()` calls. The fix constructs the instance, explicitly calls `full_clean()` to trigger all field validators (including the magic-byte content check), and then persists it. This ensures the file is validated against its allowlist before storage.

## Behaviour changes

- `instance.full_clean()` is now called before save, triggering all field validators defined on the model. If validation fails, `ValidationError` is raised and the instance is not saved. This is the intended behaviour to enforce the file-type check.
- The instance is no longer created with a direct `create()` call; it is constructed, validated, and saved separately. Both approaches result in the same database state and performance profile for this use case.
- No other method signatures, return values, or caller expectations change.
