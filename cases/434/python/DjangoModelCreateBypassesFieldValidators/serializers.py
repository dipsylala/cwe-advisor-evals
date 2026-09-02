from rest_framework import serializers

from .models import Document


class DocumentUploadSerializer(serializers.Serializer):
    """Handles POST /documents/ - accepts a title and a single file upload."""

    title = serializers.CharField(max_length=255)
    file = serializers.FileField()

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
