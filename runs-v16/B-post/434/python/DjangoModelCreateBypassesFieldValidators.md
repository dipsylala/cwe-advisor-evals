## Verdict

Exploitable. The `Document.objects.create()` call bypasses Django field validators because `Model.objects.create()` and `instance.save()` do not invoke `full_clean()`. The file upload is persisted to disk without triggering the `validate_file_content` validator declared on the `Document.file` field, allowing unrestricted upload of files with dangerous types.

## Source

`validated_data["file"]` - the uploaded file from the DRF serializer, passed through without validation before reaching the sink.

## Fix

**Vulnerable code (line 19):**
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
    # Document.file carries validators=[validate_file_content], a
    # magic-byte check. These validators run under full_clean(), so
    # instantiate the model, call full_clean() to trigger all field
    # validators before persisting the file to disk.
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

The fix replaces the direct `objects.create()` call with an explicit constructor, `full_clean()`, and `save()` sequence. Django field validators are only executed during `full_clean()`; `objects.create()` and `instance.save()` bypass them entirely. By calling `full_clean()` after instantiation and before `save()`, the `validate_file_content` validator (and any other field validators on the Document model) are now triggered. If validation fails, `full_clean()` raises `ValidationError`, which the DRF serializer framework will handle as a serializer validation error. If validation passes, `save()` persists the validated file to disk.

## Behaviour changes

- **Added full_clean() call**: Triggers all field validators before save. If validators fail, a Django `ValidationError` is raised and propagated to the DRF framework as a serializer validation error. This is the intended behavior and prevents invalid files from reaching disk.
- **Changed model instantiation**: Uses the constructor (`Document(...)`) followed by `full_clean()` and `save()` instead of the shorthand `objects.create()`. The return value is still a Document instance and the context assignment (`owner`, `title`, `file`) is identical.
- **Validation is now enforced**: The previously declared but non-functional validator `validate_file_content` now executes and can reject dangerous file types before persistence.

