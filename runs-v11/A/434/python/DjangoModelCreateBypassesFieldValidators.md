## Verdict
CONFIRMED: CWE-434 - Unrestricted Upload of File with Dangerous Type

## Source
The `create()` method of `DocumentUploadSerializer` receives file data from `validated_data["file"]`, which originates from user-supplied upload in the HTTP request.

## Fix
Replace `Document.objects.create()` with an instance-based pattern that calls `full_clean()` to trigger field validators before persisting:

```python
def create(self, validated_data):
    document = Document(
        owner=self.context["request"].user,
        title=validated_data["title"],
        file=validated_data["file"],
    )
    document.full_clean()  # Runs field validators including validate_file_content
    document.save()
    return document
```

## Explanation
The vulnerability arises because `Model.objects.create()` bypasses model field validators—validators only run during `full_clean()`. The code comment explicitly notes this gap: the Document model's `file` field declares `validators=[validate_file_content]` for magic-byte validation, but `objects.create()` skips it entirely, allowing arbitrary file types to be written to disk unchecked.

The fix constructs a Document instance, calls `full_clean()` to execute all declared field validators (including the magic-byte check), and then saves. This ensures the file passes validation before persisting to the database and filesystem. If validation fails, `full_clean()` raises `ValidationError` and the file is never written.
