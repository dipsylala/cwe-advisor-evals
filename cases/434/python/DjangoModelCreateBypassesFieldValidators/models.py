import magic
from django.core.exceptions import ValidationError
from django.db import models


ALLOWED_DOCUMENT_TYPES = {"application/pdf", "image/png", "image/jpeg"}


def validate_file_content(uploaded_file):
    """Reject uploads whose actual bytes are not an allowed document type.

    Detects the real content type from the file bytes rather than trusting
    the client-supplied filename extension or Content-Type header.
    """
    file_start = uploaded_file.read(2048)
    uploaded_file.seek(0)
    detected_type = magic.from_buffer(file_start, mime=True)
    if detected_type not in ALLOWED_DOCUMENT_TYPES:
        raise ValidationError(f"Unsupported file type: {detected_type}")


class Document(models.Model):
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to="documents/", validators=[validate_file_content])
    uploaded_at = models.DateTimeField(auto_now_add=True)
